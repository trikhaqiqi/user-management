package model

import (
	"time"

	"github.com/google/uuid"
)

// Session revocation reasons, mirrored by the session_revoke_reason enum.
const (
	RevokeLogout            = "logout"
	RevokeRefreshTokenReuse = "refresh_token_reuse"
	RevokePasswordReset     = "password_reset"
	RevokePasswordChange    = "password_change"
	RevokeAccountInactive   = "account_inactive"
)

// Session is a row of sys_sessions: one per login.
type Session struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	UserAgent  string
	IPAddress  string
	ExpiresAt  time.Time
	LastUsedAt time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// RefreshToken is a row of sys_refresh_tokens joined with the session it
// belongs to: everything a refresh or logout decision needs.
type RefreshToken struct {
	ID               uuid.UUID
	SessionID        uuid.UUID
	UserID           uuid.UUID
	ExpiresAt        time.Time
	UsedAt           *time.Time
	SessionExpiresAt time.Time
	SessionRevokedAt *time.Time
}
