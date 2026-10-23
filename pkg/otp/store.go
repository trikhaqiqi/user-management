package otp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"godigi/pkg/database"
)

// Record is one row of sys_otp_codes. The OTP engine owns that table, and
// both services use it through Manager, so its SQL lives here rather than in
// either service's repository.
type Record struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Purpose     string
	CodeHash    []byte
	TargetEmail *string
	Attempts    int
	MaxAttempts int
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

var errNoActive = errors.New("no active otp")

// lockUser takes the m_users row lock that starts every OTP operation; see
// the lock-order note in README ("Concurrency").
func lockUser(ctx context.Context, q database.Querier, userID uuid.UUID) error {
	var id uuid.UUID
	err := q.QueryRow(ctx, `SELECT id FROM m_users WHERE id = $1 FOR UPDATE`, userID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("lock user: %w", err)
	}
	return err
}

func issueStats(ctx context.Context, q database.Querier, userID uuid.UUID, purpose Purpose, since time.Time) (latest *time.Time, count int, oldest *time.Time, err error) {
	err = q.QueryRow(ctx, `SELECT
			(SELECT max(created_at) FROM sys_otp_codes WHERE user_id = $1 AND purpose = $2),
			count(*), min(created_at)
		FROM sys_otp_codes WHERE user_id = $1 AND purpose = $2 AND created_at > $3`,
		userID, string(purpose), since).Scan(&latest, &count, &oldest)
	if err != nil {
		err = fmt.Errorf("otp issue stats: %w", err)
	}
	return
}

func insert(ctx context.Context, q database.Querier, r Record) error {
	_, err := q.Exec(ctx, `INSERT INTO sys_otp_codes
		(user_id, purpose, code_hash, target_email, max_attempts, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		r.UserID, r.Purpose, r.CodeHash, r.TargetEmail, r.MaxAttempts, r.ExpiresAt, r.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert otp: %w", err)
	}
	return nil
}

func lockActive(ctx context.Context, q database.Querier, userID uuid.UUID, purpose Purpose) (*Record, error) {
	var r Record
	err := q.QueryRow(ctx, `SELECT id, user_id, purpose::text, code_hash, target_email::text,
			attempts, max_attempts, expires_at, created_at
		FROM sys_otp_codes
		WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL AND invalidated_at IS NULL
		FOR UPDATE`, userID, string(purpose)).
		Scan(&r.ID, &r.UserID, &r.Purpose, &r.CodeHash, &r.TargetEmail, &r.Attempts, &r.MaxAttempts, &r.ExpiresAt, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoActive
	}
	if err != nil {
		return nil, fmt.Errorf("lock otp: %w", err)
	}
	return &r, nil
}

func recordFailedAttempt(ctx context.Context, q database.Querier, id uuid.UUID, exhausted bool) error {
	_, err := q.Exec(ctx, `UPDATE sys_otp_codes SET attempts = attempts + 1,
			invalidated_at = CASE WHEN $2 THEN now() ELSE invalidated_at END
		WHERE id = $1`, id, exhausted)
	if err != nil {
		return fmt.Errorf("record otp attempt: %w", err)
	}
	return nil
}

func invalidateOne(ctx context.Context, q database.Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE sys_otp_codes SET invalidated_at = now() WHERE id = $1 AND invalidated_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("invalidate otp: %w", err)
	}
	return nil
}

func consume(ctx context.Context, q database.Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE sys_otp_codes SET consumed_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("consume otp: %w", err)
	}
	return nil
}

// InvalidateAll retires the user's live codes, for one purpose or (purpose
// == "") for all of them. Used when a password reset or deactivation must
// make outstanding codes useless.
func InvalidateAll(ctx context.Context, q database.Querier, userID uuid.UUID, purpose Purpose) error {
	_, err := q.Exec(ctx, `UPDATE sys_otp_codes SET invalidated_at = now()
		WHERE user_id = $1 AND ($2::text = '' OR purpose::text = $2::text)
		  AND consumed_at IS NULL AND invalidated_at IS NULL`, userID, string(purpose))
	if err != nil {
		return fmt.Errorf("invalidate otps: %w", err)
	}
	return nil
}

// Purge deletes codes older than a day. They no longer count towards the
// hourly cap and can't be verified.
func Purge(ctx context.Context, q database.Querier) (int64, error) {
	tag, err := q.Exec(ctx, `DELETE FROM sys_otp_codes WHERE created_at < now() - interval '1 day'`)
	if err != nil {
		return 0, fmt.Errorf("purge otps: %w", err)
	}
	return tag.RowsAffected(), nil
}
