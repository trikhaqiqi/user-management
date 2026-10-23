package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"godigi/pkg/database"
)

// RevokeUserSessions revokes every live session of a user. core-service
// needs it for deactivation, where it must commit in the same transaction as
// the status change.
func RevokeUserSessions(ctx context.Context, q database.Querier, userID uuid.UUID, reason string) (int64, error) {
	tag, err := q.Exec(ctx, `UPDATE sys_sessions SET revoked_at = now(), revoked_reason = $2
		WHERE user_id = $1 AND revoked_at IS NULL`, userID, reason)
	if err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// InvalidateResetTokens makes any outstanding password-reset token useless.
func InvalidateResetTokens(ctx context.Context, q database.Querier, userID uuid.UUID) error {
	_, err := q.Exec(ctx, `UPDATE sys_password_reset_tokens SET invalidated_at = now()
		WHERE user_id = $1 AND used_at IS NULL AND invalidated_at IS NULL`, userID)
	if err != nil {
		return fmt.Errorf("invalidate reset tokens: %w", err)
	}
	return nil
}
