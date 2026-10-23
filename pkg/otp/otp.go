// Package otp issues and verifies one-time codes stored in Postgres.
//
// Codes are kept in Postgres rather than Redis because verifying one changes
// other rows (activating an account, changing an email). Doing it in the same
// transaction makes "code consumed" and "effect applied" all-or-nothing, and
// row locks serialise concurrent attempts.
package otp

import (
	"context"
	"crypto/hmac"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"godigi/pkg/apperr"
	"godigi/pkg/config"
	"godigi/pkg/database"
	"godigi/pkg/security"
)

type Purpose string

const (
	PurposeEmailVerification Purpose = "email_verification"
	PurposeEmailChange       Purpose = "email_change"

	// Digits is fixed because request validation checks len=6.
	Digits = 6
)

type Config struct {
	TTL            time.Duration
	MaxAttempts    int
	ResendCooldown time.Duration
	MaxPerHour     int
	Pepper         []byte
}

func ConfigFromEnv(l *config.Loader) Config {
	return Config{
		TTL:            l.Duration("OTP_TTL", 5*time.Minute),
		MaxAttempts:    l.Int("OTP_MAX_ATTEMPTS", 5),
		ResendCooldown: l.Duration("OTP_RESEND_COOLDOWN", 60*time.Second),
		MaxPerHour:     l.Int("OTP_MAX_PER_HOUR", 5),
		Pepper:         l.Base64Secret("OTP_PEPPER", 32),
	}
}

type Manager struct {
	cfg Config
}

func NewManager(cfg Config) *Manager { return &Manager{cfg: cfg} }

func (m *Manager) TTL() time.Duration { return m.cfg.TTL }

func (m *Manager) hash(userID uuid.UUID, purpose Purpose, code string) []byte {
	return security.HMACCode(m.cfg.Pepper, string(purpose), userID.String(), code)
}

type Issued struct {
	Code      string
	ExpiresAt time.Time
}

// Issue creates a new code and invalidates any previous one for the same
// purpose. It must run inside tx. The user row lock it takes serialises
// concurrent resends, so the cooldown and hourly cap cannot be raced.
func (m *Manager) Issue(ctx context.Context, tx pgx.Tx, userID uuid.UUID, purpose Purpose, targetEmail *string) (*Issued, error) {
	if err := lockUser(ctx, tx, userID); err != nil {
		return nil, err
	}
	now := time.Now()
	latest, count, oldest, err := issueStats(ctx, tx, userID, purpose, now.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	if latest != nil {
		if wait := latest.Add(m.cfg.ResendCooldown).Sub(now); wait > 0 {
			return nil, apperr.TooManyRequests("OTP_RESEND_COOLDOWN", "please wait before requesting another code", wait)
		}
	}
	if count >= m.cfg.MaxPerHour && oldest != nil {
		return nil, apperr.TooManyRequests("OTP_RESEND_LIMIT", "too many codes requested, please try again later",
			oldest.Add(time.Hour).Sub(now))
	}
	if err := InvalidateAll(ctx, tx, userID, purpose); err != nil {
		return nil, err
	}
	code, err := security.NumericCode(Digits)
	if err != nil {
		return nil, err
	}
	expires := now.Add(m.cfg.TTL)
	err = insert(ctx, tx, Record{
		UserID:      userID,
		Purpose:     string(purpose),
		CodeHash:    m.hash(userID, purpose, code),
		TargetEmail: targetEmail,
		MaxAttempts: m.cfg.MaxAttempts,
		ExpiresAt:   expires,
		CreatedAt:   now,
	})
	if err != nil {
		return nil, err
	}
	return &Issued{Code: code, ExpiresAt: expires}, nil
}

var ErrInvalid = apperr.BadRequest("INVALID_OTP", "the code is invalid or has expired")

// Verify consumes the live code for purpose if code matches. It must run
// inside a database.WithTx transaction.
//
// Failures that change state (a counted wrong guess, an expired or exhausted
// code being retired) are returned wrapped in database.CommitAndFail. Rolling
// them back would give an attacker unlimited guesses.
func (m *Manager) Verify(ctx context.Context, tx pgx.Tx, userID uuid.UUID, purpose Purpose, code string) (*Record, error) {
	// User first: Issue locks m_users -> sys_otp_codes, so Verify must too.
	if err := lockUser(ctx, tx, userID); err != nil {
		return nil, err
	}
	rec, err := lockActive(ctx, tx, userID, purpose)
	if errors.Is(err, errNoActive) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(rec.ExpiresAt) {
		if err := invalidateOne(ctx, tx, rec.ID); err != nil {
			return nil, err
		}
		return nil, database.CommitAndFail(apperr.BadRequest("OTP_EXPIRED", "the code has expired, please request a new one"))
	}
	if rec.Attempts >= rec.MaxAttempts {
		if err := invalidateOne(ctx, tx, rec.ID); err != nil {
			return nil, err
		}
		return nil, database.CommitAndFail(attemptsExceeded)
	}
	if !hmac.Equal(rec.CodeHash, m.hash(userID, purpose, code)) {
		exhausted := rec.Attempts+1 >= rec.MaxAttempts
		if err := recordFailedAttempt(ctx, tx, rec.ID, exhausted); err != nil {
			return nil, err
		}
		if exhausted {
			return nil, database.CommitAndFail(attemptsExceeded)
		}
		return nil, database.CommitAndFail(ErrInvalid)
	}
	if err := consume(ctx, tx, rec.ID); err != nil {
		return nil, err
	}
	return rec, nil
}

var attemptsExceeded = apperr.BadRequest("OTP_ATTEMPTS_EXCEEDED", "too many incorrect attempts, please request a new code")
