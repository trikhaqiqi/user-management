package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
)

// RandomToken returns n random bytes, base64url encoded. 32 bytes gives 256
// bits of entropy, which is what refresh and reset tokens use.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken is the at-rest form of a high-entropy token. A plain SHA-256 is
// enough because the input is unguessable; only the hash is stored, so a
// database leak does not yield usable tokens.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// NumericCode returns a uniformly random code of the given number of digits.
func NumericCode(digits int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("generate code: %w", err)
	}
	return fmt.Sprintf("%0*d", digits, n), nil
}

// HMACCode is the at-rest form of a low-entropy code such as a 6-digit OTP.
//
// A bare hash of a 6-digit code can be reversed by trying all million values,
// so the code is keyed with a server-side pepper that never lives in the
// database. Binding the purpose and user id means a code issued for one
// purpose or account can never verify for another. Each part is
// length-prefixed so different splits of the same bytes can't collide.
func HMACCode(pepper []byte, parts ...string) []byte {
	mac := hmac.New(sha256.New, pepper)
	var lenBuf [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(p)))
		mac.Write(lenBuf[:])
		mac.Write([]byte(p))
	}
	return mac.Sum(nil)
}

// NormalizeEmail trims and lower-cases an address. Lookups are also
// case-insensitive in the database (citext); normalising keeps stored values
// tidy too.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// IsPlainEmail rejects display-name forms such as "Bob <bob@x.io>" that a
// generic email validator accepts.
func IsPlainEmail(email string) bool {
	addr, err := mail.ParseAddress(email)
	return err == nil && addr.Address == email && addr.Name == ""
}
