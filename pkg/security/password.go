// Package security contains password hashing, token and OTP primitives.
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters follow the OWASP Password Storage Cheat Sheet
// (m=19 MiB, t=2, p=1). They are encoded into each hash, so they can be
// raised later without invalidating existing passwords.
const (
	argonMemory      uint32 = 19 * 1024
	argonIterations  uint32 = 2
	argonParallelism uint8  = 1
	argonSaltLen            = 16
	argonKeyLen      uint32 = 32

	MinPasswordLength = 8
	// MaxPasswordLength bounds hashing cost so a huge password can't be used
	// to burn CPU.
	MaxPasswordLength = 128
)

var errInvalidHash = errors.New("invalid password hash format")

// HashPassword returns a PHC-formatted argon2id hash.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword checks password against a hash produced by HashPassword.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errInvalidHash
	}
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, errInvalidHash
	}
	if memory == 0 || memory > 1<<20 || iterations == 0 || iterations > 10 || parallelism == 0 {
		return false, errInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errInvalidHash
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// BurnPasswordCheck spends the same time as a real verification. Login calls
// it for unknown emails so response time does not reveal whether an account
// exists.
func BurnPasswordCheck(password string) {
	dummyOnce.Do(func() {
		dummyHash, _ = HashPassword("timing-equaliser-not-a-real-password")
	})
	_, _ = VerifyPassword(password, dummyHash)
}

// commonPasswords is a deliberately small deny-list of passwords that pass the
// composition rules but appear at the top of every breach corpus.
var commonPasswords = map[string]struct{}{
	"password1": {}, "password123": {}, "passw0rd": {}, "qwerty123": {},
	"12345678a": {}, "abc12345": {}, "admin123": {}, "welcome1": {},
	"iloveyou1": {}, "letmein1": {}, "1q2w3e4r": {}, "p@ssw0rd": {},
}

// ValidatePassword enforces the password policy. The returned error message is
// safe to show to the client.
func ValidatePassword(password, email string) error {
	n := utf8.RuneCountInString(password)
	if n < MinPasswordLength {
		return fmt.Errorf("must be at least %d characters", MinPasswordLength)
	}
	if n > MaxPasswordLength {
		return fmt.Errorf("must be at most %d characters", MaxPasswordLength)
	}
	var hasLetter, hasDigit bool
	for _, r := range password {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsControl(r):
			return errors.New("must not contain control characters")
		}
	}
	if !hasLetter || !hasDigit {
		return errors.New("must contain at least one letter and one digit")
	}
	if strings.TrimSpace(password) != password {
		return errors.New("must not start or end with whitespace")
	}
	lower := strings.ToLower(password)
	if _, ok := commonPasswords[lower]; ok {
		return errors.New("is too common, please choose another")
	}
	if email != "" && lower == strings.ToLower(email) {
		return errors.New("must not be the same as the email address")
	}
	return nil
}
