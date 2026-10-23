// Package dto defines the JSON shapes of core-service's API. Requests are
// bound strictly (unknown fields rejected) and validated with the tags below.
package dto

// UpdateProfileRequest lists the only writable profile fields. Anything else
// (email, status, email_verified, id, ...) is an unknown field and fails
// binding. A nil field is left unchanged; phone_number "" clears it.
type UpdateProfileRequest struct {
	Name        *string `json:"name" validate:"omitempty,max=100"`
	PhoneNumber *string `json:"phone_number" validate:"omitempty,max=16"`
}

type ChangeEmailRequest struct {
	NewEmail        string `json:"new_email" validate:"required,email,max=254"`
	CurrentPassword string `json:"current_password" validate:"required,max=128"`
}

type VerifyEmailChangeRequest struct {
	OTP string `json:"otp" validate:"required,len=6,numeric"`
}

type DeactivateRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,max=128"`
}
