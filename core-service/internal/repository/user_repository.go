// Package repository is core-service's data access layer. All SQL is
// parameterised. Functions take a database.Querier, so the service decides
// whether they run on the pool or inside its transaction.
package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"godigi/core-service/internal/model"
	"godigi/pkg/database"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrEmailTaken = errors.New("email already registered")
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

func GetUserByID(ctx context.Context, q database.Querier, id uuid.UUID) (*model.User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userColumns+` FROM m_users WHERE id = $1`, id))
}

// LockUser takes the m_users row lock that every state-changing flow starts
// with (lock order: m_users -> sys_otp_codes / sys_password_reset_tokens ->
// sys_sessions).
func LockUser(ctx context.Context, q database.Querier, id uuid.UUID) (*model.User, error) {
	return scanUser(q.QueryRow(ctx, `SELECT `+userColumns+` FROM m_users WHERE id = $1 FOR UPDATE`, id))
}

func UpdateProfile(ctx context.Context, q database.Querier, id uuid.UUID, p model.ProfileUpdate) (*model.User, error) {
	return scanUser(q.QueryRow(ctx, `UPDATE m_users SET
			name = COALESCE($2, name),
			phone_number = CASE WHEN $3 THEN $4 ELSE phone_number END,
			updated_at = now()
		WHERE id = $1 RETURNING `+userColumns,
		id, p.Name, p.SetPhone, p.PhoneNumber))
}

func UpdateEmail(ctx context.Context, q database.Querier, id uuid.UUID, email string) (*model.User, error) {
	u, err := scanUser(q.QueryRow(ctx,
		`UPDATE m_users SET email = $2, updated_at = now() WHERE id = $1 RETURNING `+userColumns, id, email))
	if database.IsUniqueViolation(err, "m_users_email_key") {
		return nil, ErrEmailTaken
	}
	return u, err
}

func EmailTaken(ctx context.Context, q database.Querier, email string) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM m_users WHERE email = $1)`, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check email: %w", err)
	}
	return exists, nil
}

func Deactivate(ctx context.Context, q database.Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE m_users
		SET status = 'deactivated', deactivated_at = now(), updated_at = now()
		WHERE id = $1 AND status <> 'deactivated'`, id)
	if err != nil {
		return fmt.Errorf("deactivate user: %w", err)
	}
	return nil
}
