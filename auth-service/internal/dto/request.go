// Package dto defines the JSON shapes of auth-service's API. Requests are
// bound strictly (unknown fields rejected) and validated with the tags below.
package dto

type RegisterRequest struct {
	Name     string `json:"name" validate:"required,max=100"`
	Email    string `json:"email" validate:"required,email,max=254"`
	Password string `json:"password" validate:"required"`
}

type VerifyOTPRequest struct {
	Email string `json:"email" validate:"required,email,max=254"`
	OTP   string `json:"otp" validate:"required,len=6,numeric"`
}

// EmailRequest is the body of resend-otp and forgot-password.
type EmailRequest struct {
	Email string `json:"email" validate:"required,email,max=254"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email,max=254"`
	Password string `json:"password" validate:"required,max=128"`
}

// RefreshTokenRequest is the body of refresh and logout.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required,max=256"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required,max=256"`
	NewPassword string `json:"new_password" validate:"required"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,max=128"`
	NewPassword     string `json:"new_password" validate:"required"`
}

// ClientInfo is request metadata recorded on a new session. It does not come
// from the body.
type ClientInfo struct {
	UserAgent string
	IP        string
}
