package dto

import (
	"time"

	"github.com/google/uuid"

	"godigi/core-service/internal/model"
)

// ProfileResponse is the caller's own profile. It never includes the
// password hash.
type ProfileResponse struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	Email           string     `json:"email"`
	PhoneNumber     *string    `json:"phone_number"`
	Status          string     `json:"status"`
	EmailVerified   bool       `json:"email_verified"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func NewProfileResponse(u *model.User) *ProfileResponse {
	return &ProfileResponse{
		ID: u.ID, Name: u.Name, Email: u.Email, PhoneNumber: u.PhoneNumber, Status: u.Status,
		EmailVerified: u.EmailVerifiedAt != nil, EmailVerifiedAt: u.EmailVerifiedAt,
		CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt,
	}
}

// EmailChangeResponse is returned when a change-email code has been sent.
type EmailChangeResponse struct {
	CodeExpiresAt string `json:"code_expires_at"`
}

func NewEmailChangeResponse(expiresAt time.Time) *EmailChangeResponse {
	return &EmailChangeResponse{CodeExpiresAt: expiresAt.UTC().Format(time.RFC3339)}
}
