package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"godigi/auth-service/internal/model"
	"godigi/pkg/database"
)

const userColumns = `id, name, email::text, phone_number, password_hash, status::text,
	email_verified_at, password_changed_at, deactivated_at, created_at, updated_at`

func scanUser(row pgx.Row) (*model.User, error) {
	var u model.User
	err := row.Scan(&u.ID, &u.Name, &u.Email, &u.PhoneNumber, &u.PasswordHash, &u.Status,
		&u.EmailVerifiedAt, &u.PasswordChangedAt, &u.DeactivatedAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return &u, nil
}

// CreateUser inserts an unverified account. The unique constraint, not a
// prior SELECT, settles two concurrent registrations for one email.
func CreateUser(ctx context.Context, q database.Querier, name, email, passwordHash string) (*model.User, error) {
	u, err := scanUser(q.QueryRow(ctx,
		`INSERT INTO m_users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING `+userColumns,
		name, email, passwordHash))
	if database.IsUniqueViolation(err, "m_users_email_key") {
		return nil, ErrEmailTaken
	}
	return u, err
}

// GetUserByEmail matches case-insensitively (email is citext).
func GetUserByEmail(ctx context.Context, q database.Querier, email string) (*model.User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userColumns+` FROM m_users WHERE email = $1`, email))
}

func GetUserByID(ctx context.Context, q database.Querier, id uuid.UUID) (*model.User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userColumns+` FROM m_users WHERE id = $1`, id))
}

// LockUser takes the row lock every state-changing flow starts with, which
// gives one lock order: m_users -> sys_otp_codes / sys_password_reset_tokens
// -> sys_sessions.
func LockUser(ctx context.Context, q database.Querier, id uuid.UUID) (*model.User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userColumns+` FROM m_users WHERE id = $1 FOR UPDATE`, id))
}

// ShareLockUser blocks a concurrent deactivation while a session is created,
// so a login can't commit a fresh session just after deactivation revoked
// all the others.
func ShareLockUser(ctx context.Context, q database.Querier, id uuid.UUID) (*model.User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userColumns+` FROM m_users WHERE id = $1 FOR SHARE`, id))
}

// MarkEmailVerified activates a pending account, reporting false if the
// account was no longer pending.
func MarkEmailVerified(ctx context.Context, q database.Querier, id uuid.UUID) (bool, error) {
	tag, err := q.Exec(ctx, `UPDATE m_users
		SET status = 'active', email_verified_at = now(), updated_at = now()
		WHERE id = $1 AND status = 'pending_verification'`, id)
	if err != nil {
		return false, fmt.Errorf("mark email verified: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func UpdatePassword(ctx context.Context, q database.Querier, id uuid.UUID, passwordHash string) error {
	_, err := q.Exec(ctx, `UPDATE m_users
		SET password_hash = $2, password_changed_at = now(), updated_at = now()
		WHERE id = $1`, id, passwordHash)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return nil
}
