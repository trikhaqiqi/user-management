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

func CreateSession(ctx context.Context, q database.Querier, userID uuid.UUID, expiresAt time.Time, userAgent, ip string) (uuid.UUID, error) {
	var id uuid.UUID
	err := q.QueryRow(ctx, `INSERT INTO sys_sessions (user_id, expires_at, user_agent, ip_address)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, '')::inet) RETURNING id`,
		userID, expiresAt, userAgent, ip).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create session: %w", err)
	}
	return id, nil
}

func TouchSession(ctx context.Context, q database.Querier, sessionID uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE sys_sessions SET last_used_at = now() WHERE id = $1`, sessionID)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

func RevokeSession(ctx context.Context, q database.Querier, sessionID uuid.UUID, reason string) error {
	_, err := q.Exec(ctx, `UPDATE sys_sessions SET revoked_at = now(), revoked_reason = $2
		WHERE id = $1 AND revoked_at IS NULL`, sessionID, reason)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeUserSessions revokes every live session of a user, optionally keeping
// one (the session that is changing its own password).
func RevokeUserSessions(ctx context.Context, q database.Querier, userID uuid.UUID, reason string, keep *uuid.UUID) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE sys_sessions SET revoked_at = now(), revoked_reason = $2
		WHERE user_id = $1 AND revoked_at IS NULL AND ($3::uuid IS NULL OR id <> $3)`, userID, reason, keep)
	if err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

func InsertRefreshToken(ctx context.Context, q database.Querier, sessionID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	_, err := q.Exec(ctx, `INSERT INTO sys_refresh_tokens (session_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		sessionID, tokenHash, expiresAt)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

// LockRefreshToken locks the token and its session. Two concurrent refreshes
// with the same token serialise here: the second sees used_at set and is
// treated as reuse.
func LockRefreshToken(ctx context.Context, q database.Querier, tokenHash []byte) (*model.RefreshToken, error) {
	var t model.RefreshToken
	err := q.QueryRow(ctx, `SELECT rt.id, rt.session_id, s.user_id, rt.expires_at, rt.used_at, s.expires_at, s.revoked_at
		FROM sys_refresh_tokens rt JOIN sys_sessions s ON s.id = rt.session_id
		WHERE rt.token_hash = $1
		FOR UPDATE OF rt, s`, tokenHash).
		Scan(&t.ID, &t.SessionID, &t.UserID, &t.ExpiresAt, &t.UsedAt, &t.SessionExpiresAt, &t.SessionRevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock refresh token: %w", err)
	}
	return &t, nil
}

func MarkRefreshTokenUsed(ctx context.Context, q database.Querier, tokenID uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE sys_refresh_tokens SET used_at = now() WHERE id = $1`, tokenID)
	if err != nil {
		return fmt.Errorf("mark refresh token used: %w", err)
	}
	return nil
}
