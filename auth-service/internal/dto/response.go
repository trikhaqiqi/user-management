package dto

import (
	"time"

	"github.com/google/uuid"

	"godigi/auth-service/internal/model"
)

// UserResponse is the account as returned by register. It never includes
// the password hash.
type UserResponse struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	Status        string    `json:"status"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

func NewUserResponse(u *model.User) *UserResponse {
	return &UserResponse{
		ID: u.ID, Name: u.Name, Email: u.Email, Status: u.Status,
		EmailVerified: u.IsVerified(), CreatedAt: u.CreatedAt,
	}
}

// TokenResponse is returned by login and refresh.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
}
