package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"godigi/auth-service/internal/model"
	"godigi/pkg/database"
)

func LatestResetTokenAt(ctx context.Context, q database.Querier, userID uuid.UUID) (*time.Time, error) {
	var t *time.Time
	err := q.QueryRow(ctx, `SELECT max(created_at) FROM sys_password_reset_tokens WHERE user_id = $1`, userID).Scan(&t)
	if err != nil {
		return nil, fmt.Errorf("latest reset token: %w", err)
	}
	return t, nil
}

func InvalidateResetTokens(ctx context.Context, q database.Querier, userID uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE sys_password_reset_tokens SET invalidated_at = now()
		WHERE user_id = $1 AND used_at IS NULL AND invalidated_at IS NULL`, userID)
	if err != nil {
		return fmt.Errorf("invalidate reset tokens: %w", err)
	}
	return nil
}

func InsertResetToken(ctx context.Context, q database.Querier, userID uuid.UUID, tokenHash []byte, expiresAt, createdAt time.Time, ip string) error {
	_, err := q.Exec(ctx, `INSERT INTO sys_password_reset_tokens (user_id, token_hash, expires_at, created_at, requested_ip)
		VALUES ($1, $2, $3, $4, NULLIF($5, '')::inet)`, userID, tokenHash, expiresAt, createdAt, ip)
	if err != nil {
		return fmt.Errorf("insert reset token: %w", err)
	}
	return nil
}

// FindResetToken looks up a live token without locking. The reset flow uses
// it only to learn the user id, so it can take the user lock first and then
// re-read the token with LockResetToken, keeping the m_users-first lock
// order.
func FindResetToken(ctx context.Context, q database.Querier, tokenHash []byte) (*model.PasswordResetToken, error) {
	return scanResetToken(q.QueryRow(ctx, `SELECT id, user_id, expires_at FROM sys_password_reset_tokens
		WHERE token_hash = $1 AND used_at IS NULL AND invalidated_at IS NULL`, tokenHash))
}

func LockResetToken(ctx context.Context, q database.Querier, tokenHash []byte) (*model.PasswordResetToken, error) {
	return scanResetToken(q.QueryRow(ctx, `SELECT id, user_id, expires_at FROM sys_password_reset_tokens
		WHERE token_hash = $1 AND used_at IS NULL AND invalidated_at IS NULL FOR UPDATE`, tokenHash))
}

func scanResetToken(row pgx.Row) (*model.PasswordResetToken, error) {
	var t model.PasswordResetToken
	err := row.Scan(&t.ID, &t.UserID, &t.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan reset token: %w", err)
	}
	return &t, nil
}

func MarkResetTokenUsed(ctx context.Context, q database.Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE sys_password_reset_tokens SET used_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("mark reset token used: %w", err)
	}
	return nil
}
