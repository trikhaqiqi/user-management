package model

import (
	"time"

	"github.com/google/uuid"
)

// PasswordResetToken is a live row of sys_password_reset_tokens. Only the
// token's SHA-256 is stored; the token itself exists only in the email.
type PasswordResetToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
}
