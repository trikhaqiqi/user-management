// Package jwtx issues and verifies access tokens.
//
// Tokens are signed with Ed25519 (EdDSA). The auth-service holds the private
// key; the gateway gets only the public key, so a compromised gateway can
// verify tokens but cannot mint them, which a shared HS256 secret would allow.
package jwtx

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	Issuer     = "godigi-auth-service"
	Audience   = "godigi-api"
	TypeAccess = "access"
)

// Claims carries the session id so services can check, on every request,
// that the session behind the token has not been revoked.
type Claims struct {
	SessionID string `json:"sid"`
	TokenType string `json:"typ"`
	jwt.RegisteredClaims
}

// ParsePrivateKey decodes a base64-encoded PKCS#8 PEM Ed25519 private key.
func ParsePrivateKey(b64 string) (ed25519.PrivateKey, error) {
	block, err := decodePEM(b64)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	k, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not Ed25519")
	}
	return k, nil
}

// ParsePublicKey decodes a base64-encoded PKIX PEM Ed25519 public key.
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	block, err := decodePEM(b64)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	k, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not Ed25519")
	}
	return k, nil
}

func decodePEM(b64 string) (*pem.Block, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("key is not valid base64: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("key is not PEM encoded")
	}
	return block, nil
}

type Signer struct {
	key ed25519.PrivateKey
	ttl time.Duration
}

func NewSigner(key ed25519.PrivateKey, ttl time.Duration) *Signer {
	return &Signer{key: key, ttl: ttl}
}

func (s *Signer) TTL() time.Duration { return s.ttl }

// Sign issues an access token for the user's session.
func (s *Signer) Sign(userID, sessionID uuid.UUID) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(s.ttl)
	claims := Claims{
		SessionID: sessionID.String(),
		TokenType: TypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(s.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return token, exp, nil
}

type Verifier struct {
	key    ed25519.PublicKey
	parser *jwt.Parser
}

// NewVerifier pins the algorithm to EdDSA. Without the pin, a token with
// "alg":"none" or an HS256 token "signed" with the public key could be
// accepted by a careless key function.
func NewVerifier(key ed25519.PublicKey) *Verifier {
	return &Verifier{
		key: key,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
			jwt.WithIssuer(Issuer),
			jwt.WithAudience(Audience),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(5*time.Second),
		),
	}
}

var ErrWrongTokenType = errors.New("token is not an access token")

// Verify checks signature, algorithm, issuer, audience and time claims, and
// that the subject and session id are well-formed.
func (v *Verifier) Verify(token string) (*Claims, error) {
	claims := &Claims{}
	_, err := v.parser.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return v.key, nil })
	if err != nil {
		return nil, err
	}
	if claims.TokenType != TypeAccess {
		return nil, ErrWrongTokenType
	}
	if _, err := uuid.Parse(claims.Subject); err != nil {
		return nil, fmt.Errorf("invalid subject: %w", err)
	}
	if _, err := uuid.Parse(claims.SessionID); err != nil {
		return nil, fmt.Errorf("invalid session id: %w", err)
	}
	return claims, nil
}

// IsExpired distinguishes an expired token, which the client should refresh,
// from one that is simply invalid.
func IsExpired(err error) bool { return errors.Is(err, jwt.ErrTokenExpired) }
