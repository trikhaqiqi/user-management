// Package model holds the database entities auth-service works with. They
// mirror table rows and carry no JSON tags; API shapes live in package dto.
package model

import (
	"time"

	"github.com/google/uuid"
)

// User status values, mirrored by the user_status enum.
const (
	UserStatusPending     = "pending_verification"
	UserStatusActive      = "active"
	UserStatusDeactivated = "deactivated"
)

// User is a row of m_users.
type User struct {
	ID                uuid.UUID
	Name              string
	Email             string
	PhoneNumber       *string
	PasswordHash      string
	Status            string
	EmailVerifiedAt   *time.Time
	PasswordChangedAt time.Time
	DeactivatedAt     *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func (u *User) IsVerified() bool { return u.EmailVerifiedAt != nil }
