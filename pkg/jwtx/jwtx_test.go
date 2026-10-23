package jwtx

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignAndVerify(t *testing.T) {
	pub, priv := keys(t)
	uid, sid := uuid.New(), uuid.New()
	tok, exp, err := NewSigner(priv, time.Minute).Sign(uid, sid)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(exp) > time.Minute {
		t.Fatal("expiry beyond ttl")
	}
	c, err := NewVerifier(pub).Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != uid.String() || c.SessionID != sid.String() {
		t.Fatal("claims mismatch")
	}
}

func TestRejectsOtherKey(t *testing.T) {
	_, priv := keys(t)
	otherPub, _ := keys(t)
	tok, _, _ := NewSigner(priv, time.Minute).Sign(uuid.New(), uuid.New())
	if _, err := NewVerifier(otherPub).Verify(tok); err == nil {
		t.Fatal("token signed by another key accepted")
	}
}

func TestRejectsExpired(t *testing.T) {
	pub, priv := keys(t)
	tok, _, _ := NewSigner(priv, -time.Minute).Sign(uuid.New(), uuid.New())
	_, err := NewVerifier(pub).Verify(tok)
	if !IsExpired(err) {
		t.Fatalf("expected expiry error, got %v", err)
	}
}

func claimsFor(typ, iss string) Claims {
	now := time.Now()
	return Claims{
		SessionID: uuid.NewString(),
		TokenType: typ,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: iss, Subject: uuid.NewString(), Audience: jwt.ClaimStrings{Audience},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}
}

func TestRejectsAlgNone(t *testing.T) {
	pub, _ := keys(t)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodNone, claimsFor(TypeAccess, Issuer)).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerifier(pub).Verify(tok); err == nil {
		t.Fatal("alg=none accepted")
	}
}

// An HS256 token keyed with the public key is the classic algorithm-confusion
// attack against verifiers that trust the token's alg header.
func TestRejectsAlgorithmConfusion(t *testing.T) {
	pub, _ := keys(t)
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsFor(TypeAccess, Issuer)).SignedString([]byte(pub))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerifier(pub).Verify(tok); err == nil {
		t.Fatal("HS256 token accepted")
	}
}

func TestRejectsWrongIssuerAndType(t *testing.T) {
	pub, priv := keys(t)
	for name, c := range map[string]Claims{
		"issuer": claimsFor(TypeAccess, "someone-else"),
		"type":   claimsFor("refresh", Issuer),
	} {
		tok, _ := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c).SignedString(priv)
		if _, err := NewVerifier(pub).Verify(tok); err == nil {
			t.Errorf("%s: token accepted", name)
		}
	}
}

func TestParseKeys(t *testing.T) {
	pub, priv := keys(t)
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	privB64 := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubB64 := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	gotPriv, err := ParsePrivateKey(privB64)
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("private key round-trip failed: %v", err)
	}
	gotPub, err := ParsePublicKey(pubB64)
	if err != nil || !gotPub.Equal(pub) {
		t.Fatalf("public key round-trip failed: %v", err)
	}
}
