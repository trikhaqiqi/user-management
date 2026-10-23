// Package service implements registration, login, token and password flows.
package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"godigi/auth-service/internal/config"
	"godigi/auth-service/internal/dto"
	"godigi/auth-service/internal/model"
	"godigi/auth-service/internal/repository"
	"godigi/pkg/apperr"
	"godigi/pkg/database"
	"godigi/pkg/jwtx"
	"godigi/pkg/logger"
	"godigi/pkg/mailer"
	"godigi/pkg/otp"
	"godigi/pkg/ratelimit"
	"godigi/pkg/security"
)

type AuthService struct {
	pool    *pgxpool.Pool
	limiter *ratelimit.Limiter
	otp     *otp.Manager
	signer  *jwtx.Signer
	mail    *mailer.Async
	cfg     *config.Config
	log     *slog.Logger
	bg      sync.WaitGroup
}

func New(pool *pgxpool.Pool, limiter *ratelimit.Limiter, mail *mailer.Async, cfg *config.Config, log *slog.Logger) *AuthService {
	return &AuthService{
		pool:    pool,
		limiter: limiter,
		otp:     otp.NewManager(cfg.OTP),
		signer:  jwtx.NewSigner(cfg.JWTPrivateKey, cfg.AccessTokenTTL),
		mail:    mail,
		cfg:     cfg,
		log:     log,
	}
}

// Wait blocks until background work (password-reset requests) has finished.
func (s *AuthService) Wait() { s.bg.Wait() }

var (
	errInvalidCredentials = apperr.Unauthorized("INVALID_CREDENTIALS", "invalid email or password")
	errInvalidRefresh     = apperr.Unauthorized("INVALID_REFRESH_TOKEN", "refresh token is invalid or expired")
	errInvalidResetToken  = apperr.BadRequest("INVALID_RESET_TOKEN", "the reset token is invalid or has expired")
	errNotVerified        = apperr.Forbidden("EMAIL_NOT_VERIFIED", "please verify your email address before logging in")
	errDeactivated        = apperr.Forbidden("ACCOUNT_DEACTIVATED", "this account has been deactivated")
)

// ValidateName trims and checks a display name.
func ValidateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", apperr.Field("name", "must not be blank")
	}
	if utf8.RuneCountInString(name) > 100 {
		return "", apperr.Field("name", "must be at most 100 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", apperr.Field("name", "must not contain control characters")
		}
	}
	return name, nil
}

// ---- Registration & OTP ----------------------------------------------------

func (s *AuthService) Register(ctx context.Context, in dto.RegisterRequest) (*dto.UserResponse, error) {
	name, err := ValidateName(in.Name)
	if err != nil {
		return nil, err
	}
	email := security.NormalizeEmail(in.Email)
	if !security.IsPlainEmail(email) {
		return nil, apperr.Field("email", "must be a valid email address")
	}
	if err := security.ValidatePassword(in.Password, email); err != nil {
		return nil, apperr.Field("password", err.Error())
	}
	hash, err := security.HashPassword(in.Password)
	if err != nil {
		return nil, err
	}

	var user *model.User
	var issued *otp.Issued
	err = database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		user, err = repository.CreateUser(ctx, tx, name, email, hash)
		if errors.Is(err, repository.ErrEmailTaken) {
			return apperr.Conflict("EMAIL_ALREADY_REGISTERED", "an account with this email already exists")
		}
		if err != nil {
			return err
		}
		issued, err = s.otp.Issue(ctx, tx, user.ID, otp.PurposeEmailVerification, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.mail.Enqueue(mailer.VerificationCode(user.Email, user.Name, issued.Code, s.otp.TTL()))
	return dto.NewUserResponse(user), nil
}

// VerifyEmail consumes a registration code and activates the account.
// Unknown emails and already-verified accounts get the same error as a wrong
// code.
func (s *AuthService) VerifyEmail(ctx context.Context, email, code string) error {
	user, err := repository.GetUserByEmail(ctx, s.pool, security.NormalizeEmail(email))
	if errors.Is(err, repository.ErrNotFound) {
		return otp.ErrInvalid
	}
	if err != nil {
		return err
	}
	if user.Status != model.UserStatusPending {
		return otp.ErrInvalid
	}
	return database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := s.otp.Verify(ctx, tx, user.ID, otp.PurposeEmailVerification, code); err != nil {
			return err
		}
		ok, err := repository.MarkEmailVerified(ctx, tx, user.ID)
		if err != nil {
			return err
		}
		if !ok {
			return otp.ErrInvalid
		}
		return nil
	})
}

// ResendVerification issues a fresh code. It succeeds silently for unknown or
// already-verified emails. Cooldown and hourly-cap errors are still returned
// for pending accounts, since a client needs them to back off.
func (s *AuthService) ResendVerification(ctx context.Context, email string) error {
	user, err := repository.GetUserByEmail(ctx, s.pool, security.NormalizeEmail(email))
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if user.Status != model.UserStatusPending {
		return nil
	}
	var issued *otp.Issued
	err = database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		issued, err = s.otp.Issue(ctx, tx, user.ID, otp.PurposeEmailVerification, nil)
		return err
	})
	if err != nil {
		return err
	}
	s.mail.Enqueue(mailer.VerificationCode(user.Email, user.Name, issued.Code, s.otp.TTL()))
	return nil
}

// ---- Login, refresh, logout -------------------------------------------------

func loginFailureKey(email string) string { return "login_fail:" + ratelimit.HashKey(email) }

// Login authenticates with email and password.
//
// Failed attempts are counted per email in Redis (on top of the gateway's
// per-IP limit), so a distributed guesser hitting one account is also
// stopped. Unknown emails are counted too, so a lockout reveals nothing about
// which accounts exist. If Redis is down, login fails closed.
func (s *AuthService) Login(ctx context.Context, email, password string, client dto.ClientInfo) (*dto.TokenResponse, error) {
	email = security.NormalizeEmail(email)
	key := loginFailureKey(email)

	failures, ttl, err := s.limiter.Peek(ctx, key)
	if err != nil {
		return nil, apperr.Unavailable(err)
	}
	if failures >= int64(s.cfg.LoginMaxFailures) {
		return nil, apperr.TooManyRequests("TOO_MANY_LOGIN_ATTEMPTS", "too many failed login attempts, please try again later", ttl)
	}

	user, err := repository.GetUserByEmail(ctx, s.pool, email)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	if user == nil {
		security.BurnPasswordCheck(password)
		s.recordLoginFailure(ctx, key)
		return nil, errInvalidCredentials
	}
	ok, err := security.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.recordLoginFailure(ctx, key)
		return nil, errInvalidCredentials
	}
	// Status is only revealed to someone who already knows the password.
	switch user.Status {
	case model.UserStatusPending:
		return nil, errNotVerified
	case model.UserStatusDeactivated:
		return nil, errDeactivated
	}
	if err := s.limiter.Reset(ctx, key); err != nil {
		s.log.Warn("could not reset login failure counter", "error", err.Error())
	}
	return s.startSession(ctx, user.ID, client)
}

func (s *AuthService) recordLoginFailure(ctx context.Context, key string) {
	if _, err := s.limiter.Hit(ctx, key, s.cfg.LoginMaxFailures, s.cfg.LoginLockout); err != nil {
		s.log.Error("could not record login failure", "error", err.Error())
	}
}

func (s *AuthService) startSession(ctx context.Context, userID uuid.UUID, client dto.ClientInfo) (*dto.TokenResponse, error) {
	var pair *dto.TokenResponse
	err := database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		user, err := repository.ShareLockUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		if user.Status != model.UserStatusActive {
			return errDeactivated
		}
		now := time.Now()
		sessionID, err := repository.CreateSession(ctx, tx, userID, now.Add(s.cfg.SessionMaxAge), truncate(client.UserAgent, 512), client.IP)
		if err != nil {
			return err
		}
		pair, err = s.issueTokens(ctx, tx, userID, sessionID, now.Add(s.cfg.SessionMaxAge))
		return err
	})
	return pair, err
}

// issueTokens creates the next refresh token in the session's chain and a
// matching access token. The refresh token never outlives its session.
func (s *AuthService) issueTokens(ctx context.Context, tx pgx.Tx, userID, sessionID uuid.UUID, sessionExpiresAt time.Time) (*dto.TokenResponse, error) {
	refresh, err := security.RandomToken(32)
	if err != nil {
		return nil, err
	}
	refreshExpires := time.Now().Add(s.cfg.RefreshTokenTTL)
	if refreshExpires.After(sessionExpiresAt) {
		refreshExpires = sessionExpiresAt
	}
	if err := repository.InsertRefreshToken(ctx, tx, sessionID, security.HashToken(refresh), refreshExpires); err != nil {
		return nil, err
	}
	access, _, err := s.signer.Sign(userID, sessionID)
	if err != nil {
		return nil, err
	}
	return &dto.TokenResponse{
		AccessToken:      access,
		TokenType:        "Bearer",
		ExpiresIn:        int(s.signer.TTL().Seconds()),
		RefreshToken:     refresh,
		RefreshExpiresIn: int(time.Until(refreshExpires).Seconds()),
	}, nil
}

// Refresh rotates a refresh token.
//
// Each token is single-use. Presenting one that was already rotated means two
// parties hold it, and we can't tell which is legitimate. So the whole session
// is revoked, which logs out the attacker and forces the real user to log in
// again. The revocation is committed even though the request fails.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*dto.TokenResponse, error) {
	var pair *dto.TokenResponse
	err := database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		st, err := repository.LockRefreshToken(ctx, tx, security.HashToken(refreshToken))
		if errors.Is(err, repository.ErrNotFound) {
			return errInvalidRefresh
		}
		if err != nil {
			return err
		}
		if st.SessionRevokedAt != nil {
			return errInvalidRefresh
		}
		if st.UsedAt != nil {
			if err := repository.RevokeSession(ctx, tx, st.SessionID, model.RevokeRefreshTokenReuse); err != nil {
				return err
			}
			s.log.Warn("refresh token reuse detected, session revoked", "session_id", st.SessionID.String(), "user_id", st.UserID.String())
			return database.CommitAndFail(apperr.Unauthorized("REFRESH_TOKEN_REUSED",
				"this refresh token was already used; the session has been revoked, please log in again"))
		}
		now := time.Now()
		if !now.Before(st.ExpiresAt) || !now.Before(st.SessionExpiresAt) {
			return errInvalidRefresh
		}
		user, err := repository.GetUserByID(ctx, tx, st.UserID)
		if err != nil {
			return err
		}
		if user.Status != model.UserStatusActive {
			if err := repository.RevokeSession(ctx, tx, st.SessionID, model.RevokeAccountInactive); err != nil {
				return err
			}
			return database.CommitAndFail(errDeactivated)
		}
		if err := repository.MarkRefreshTokenUsed(ctx, tx, st.ID); err != nil {
			return err
		}
		if err := repository.TouchSession(ctx, tx, st.SessionID); err != nil {
			return err
		}
		pair, err = s.issueTokens(ctx, tx, st.UserID, st.SessionID, st.SessionExpiresAt)
		return err
	})
	return pair, err
}

// Logout revokes the session the refresh token belongs to. That also kills
// the session's access tokens, because services check the session on every
// request. Unknown tokens succeed, making logout idempotent.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	return database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		st, err := repository.LockRefreshToken(ctx, tx, security.HashToken(refreshToken))
		if errors.Is(err, repository.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return repository.RevokeSession(ctx, tx, st.SessionID, model.RevokeLogout)
	})
}

// ---- Password recovery & change --------------------------------------------

// RequestPasswordReset returns immediately and does the work in the
// background. The response, and its timing, are identical whether or not the
// email belongs to an account.
func (s *AuthService) RequestPasswordReset(email, ip string) {
	email = security.NormalizeEmail(email)
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.requestPasswordReset(ctx, email, ip); err != nil {
			s.log.Error("password reset request failed", "email", logger.MaskEmail(email), "error", err.Error())
		}
	}()
}

func (s *AuthService) requestPasswordReset(ctx context.Context, email, ip string) error {
	user, err := repository.GetUserByEmail(ctx, s.pool, email)
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if user.Status == model.UserStatusDeactivated {
		return nil
	}
	var token string
	err = database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := repository.LockUser(ctx, tx, user.ID); err != nil {
			return err
		}
		now := time.Now()
		latest, err := repository.LatestResetTokenAt(ctx, tx, user.ID)
		if err != nil {
			return err
		}
		if latest != nil && now.Sub(*latest) < s.cfg.PasswordResetCooldown {
			return nil // silently skip; the response is generic anyway
		}
		if err := repository.InvalidateResetTokens(ctx, tx, user.ID); err != nil {
			return err
		}
		token, err = security.RandomToken(32)
		if err != nil {
			return err
		}
		return repository.InsertResetToken(ctx, tx, user.ID, security.HashToken(token), now.Add(s.cfg.PasswordResetTTL), now, ip)
	})
	if err != nil || token == "" {
		return err
	}
	s.mail.Enqueue(mailer.PasswordReset(user.Email, user.Name, token, s.cfg.PasswordResetURL, s.cfg.PasswordResetTTL))
	return nil
}

// ResetPassword sets a new password with a reset token, then revokes every
// session and every other outstanding reset token and code. Completing a
// reset proves control of the mailbox, so it also verifies a still-pending
// account. That lets the real owner reclaim an address someone else
// registered.
func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	hash := security.HashToken(token)
	found, err := repository.FindResetToken(ctx, s.pool, hash)
	if errors.Is(err, repository.ErrNotFound) {
		return errInvalidResetToken
	}
	if err != nil {
		return err
	}
	user, err := repository.GetUserByID(ctx, s.pool, found.UserID)
	if err != nil {
		return err
	}
	if err := security.ValidatePassword(newPassword, user.Email); err != nil {
		return apperr.Field("new_password", err.Error())
	}
	newHash, err := security.HashPassword(newPassword)
	if err != nil {
		return err
	}

	err = database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		user, err = repository.LockUser(ctx, tx, found.UserID)
		if err != nil {
			return err
		}
		rt, err := repository.LockResetToken(ctx, tx, hash)
		if errors.Is(err, repository.ErrNotFound) {
			return errInvalidResetToken // used or replaced concurrently
		}
		if err != nil {
			return err
		}
		if !time.Now().Before(rt.ExpiresAt) || user.Status == model.UserStatusDeactivated {
			if err := repository.InvalidateResetTokens(ctx, tx, user.ID); err != nil {
				return err
			}
			return database.CommitAndFail(errInvalidResetToken)
		}
		if err := repository.UpdatePassword(ctx, tx, user.ID, newHash); err != nil {
			return err
		}
		if user.Status == model.UserStatusPending {
			if _, err := repository.MarkEmailVerified(ctx, tx, user.ID); err != nil {
				return err
			}
		}
		if err := repository.MarkResetTokenUsed(ctx, tx, rt.ID); err != nil {
			return err
		}
		if err := repository.InvalidateResetTokens(ctx, tx, user.ID); err != nil {
			return err
		}
		if err := otp.InvalidateAll(ctx, tx, user.ID, ""); err != nil {
			return err
		}
		_, err = repository.RevokeUserSessions(ctx, tx, user.ID, model.RevokePasswordReset, nil)
		return err
	})
	if err != nil {
		return err
	}
	s.mail.Enqueue(mailer.PasswordChanged(user.Email, user.Name))
	return nil
}

// ChangePassword requires the current password. Every other session is
// signed out; the caller's own session stays valid.
func (s *AuthService) ChangePassword(ctx context.Context, userID, sessionID uuid.UUID, current, next string) error {
	if current == next {
		return apperr.Field("new_password", "must be different from the current password")
	}
	var user *model.User
	err := database.WithTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		user, err = repository.LockUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		ok, err := security.VerifyPassword(current, user.PasswordHash)
		if err != nil {
			return err
		}
		if !ok {
			return apperr.BadRequest("INVALID_CURRENT_PASSWORD", "current password is incorrect")
		}
		if err := security.ValidatePassword(next, user.Email); err != nil {
			return apperr.Field("new_password", err.Error())
		}
		hash, err := security.HashPassword(next)
		if err != nil {
			return err
		}
		if err := repository.UpdatePassword(ctx, tx, userID, hash); err != nil {
			return err
		}
		if err := repository.InvalidateResetTokens(ctx, tx, userID); err != nil {
			return err
		}
		_, err = repository.RevokeUserSessions(ctx, tx, userID, model.RevokePasswordChange, &sessionID)
		return err
	})
	if err != nil {
		return err
	}
	s.mail.Enqueue(mailer.PasswordChanged(user.Email, user.Name))
	return nil
}

// StartJanitor periodically deletes rows that can no longer matter.
func (s *AuthService) StartJanitor(ctx context.Context, every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n, err := repository.PurgeExpired(ctx, s.pool)
				if err != nil {
					s.log.Error("purge failed", "error", err.Error())
				} else if n > 0 {
					s.log.Info("purged expired auth rows", "rows", n)
				}
			}
		}
	}()
}

func truncate(s string, maxRunes int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	return string([]rune(s)[:maxRunes])
}
