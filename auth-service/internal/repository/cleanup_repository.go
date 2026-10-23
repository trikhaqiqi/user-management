package repository

import (
	"context"
	"fmt"

	"godigi/pkg/database"
	"godigi/pkg/otp"
)

// PurgeExpired deletes rows that can no longer affect any decision.
func PurgeExpired(ctx context.Context, q database.Querier) (int64, error) {
	total, err := otp.Purge(ctx, q)
	if err != nil {
		return total, err
	}
	for _, stmt := range []string{
		`DELETE FROM sys_password_reset_tokens WHERE created_at < now() - interval '1 day'`,
		`DELETE FROM sys_sessions WHERE expires_at < now() - interval '7 days'
		    OR revoked_at < now() - interval '7 days'`,
		`DELETE FROM sys_refresh_tokens WHERE used_at < now() - interval '7 days'
		    OR expires_at < now() - interval '7 days'`,
	} {
		tag, err := q.Exec(ctx, stmt)
		if err != nil {
			return total, fmt.Errorf("purge: %w", err)
		}
		total += tag.RowsAffected()
	}
	return total, nil
}
