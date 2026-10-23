// Package apperr defines errors that are safe to return to API clients.
//
// The Message and Details of an Error are serialised into the response body,
// so they must never contain secrets (passwords, OTPs, tokens). The wrapped
// Err is only ever written to logs.
package apperr

import (
	"fmt"
	"net/http"
	"time"
)

// FieldError describes one invalid input field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error is an application error with a stable machine-readable code.
type Error struct {
	Status     int
	Code       string
	Message    string
	Details    []FieldError
	RetryAfter time.Duration
	Err        error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// New builds an Error with an arbitrary status.
func New(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// Validation reports one or more invalid request fields.
func Validation(details ...FieldError) *Error {
	return &Error{
		Status:  http.StatusBadRequest,
		Code:    "VALIDATION_ERROR",
		Message: "request validation failed",
		Details: details,
	}
}

// Field is shorthand for a single-field validation error.
func Field(field, message string) *Error {
	return Validation(FieldError{Field: field, Message: message})
}

func BadRequest(code, message string) *Error {
	return New(http.StatusBadRequest, code, message)
}

func Unauthorized(code, message string) *Error {
	return New(http.StatusUnauthorized, code, message)
}

func Forbidden(code, message string) *Error {
	return New(http.StatusForbidden, code, message)
}

func NotFound(code, message string) *Error {
	return New(http.StatusNotFound, code, message)
}

func Conflict(code, message string) *Error {
	return New(http.StatusConflict, code, message)
}

// TooManyRequests sets RetryAfter so the response carries a Retry-After header.
func TooManyRequests(code, message string, retryAfter time.Duration) *Error {
	e := New(http.StatusTooManyRequests, code, message)
	e.RetryAfter = retryAfter
	return e
}

// Unavailable is used when a dependency the request cannot safely skip is down.
func Unavailable(err error) *Error {
	e := New(http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "service temporarily unavailable, please try again later")
	e.Err = err
	return e
}

// Internal hides the cause from the client and keeps it for the logs.
func Internal(err error) *Error {
	e := New(http.StatusInternalServerError, "INTERNAL_ERROR", "an unexpected error occurred")
	e.Err = err
	return e
}
