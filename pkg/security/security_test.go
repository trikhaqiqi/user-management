package security

import (
	"bytes"
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse 1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected hash format %q", hash)
	}
	ok, err := VerifyPassword("correct horse 1", hash)
	if err != nil || !ok {
		t.Fatalf("expected match, got ok=%v err=%v", ok, err)
	}
	ok, _ = VerifyPassword("correct horse 2", hash)
	if ok {
		t.Fatal("wrong password must not verify")
	}
	other, _ := HashPassword("correct horse 1")
	if other == hash {
		t.Fatal("salts must differ between hashes")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	for _, h := range []string{"", "plain", "$argon2i$v=19$m=1,t=1,p=1$a$b", "$argon2id$v=19$m=999999999,t=1,p=1$YQ$YQ"} {
		if ok, err := VerifyPassword("x", h); ok || err == nil {
			t.Errorf("hash %q: expected error, got ok=%v err=%v", h, ok, err)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	cases := map[string]bool{
		"short1":                        false,
		"onlyletters":                   false,
		"12345678":                      false,
		"Tr0ub4dor-x":                   true,
		"Password1":                     false, // common once lower-cased
		"password1":                     false, // common
		" leading1":                     false,
		"a1" + strings.Repeat("x", 127): false,
		"jane@example.com1":             true,
	}
	for pw, valid := range cases {
		if err := ValidatePassword(pw, "jane@example.com"); (err == nil) != valid {
			t.Errorf("%q: valid=%v, err=%v", pw, valid, err)
		}
	}
	if err := ValidatePassword("Jane@Example.com1", "jane@example.com1"); err == nil {
		t.Error("password equal to email must be rejected")
	}
}

func TestNumericCode(t *testing.T) {
	for i := 0; i < 200; i++ {
		c, err := NumericCode(6)
		if err != nil || len(c) != 6 || strings.Trim(c, "0123456789") != "" {
			t.Fatalf("bad code %q err=%v", c, err)
		}
	}
}

func TestHMACCodeBindsAllParts(t *testing.T) {
	p := []byte("pepper-pepper-pepper-pepper-1234")
	a := HMACCode(p, "email_verification", "user-1", "123456")
	if !bytes.Equal(a, HMACCode(p, "email_verification", "user-1", "123456")) {
		t.Fatal("HMAC must be deterministic")
	}
	for _, other := range [][]byte{
		HMACCode(p, "email_change", "user-1", "123456"),
		HMACCode(p, "email_verification", "user-2", "123456"),
		HMACCode([]byte("another-pepper-another-pepper-12"), "email_verification", "user-1", "123456"),
		HMACCode(p, "email_verificationuser-1", "", "123456"),
	} {
		if bytes.Equal(a, other) {
			t.Fatal("HMAC must differ when any part differs")
		}
	}
}

func TestIsPlainEmail(t *testing.T) {
	if !IsPlainEmail("jane@example.com") {
		t.Error("plain address rejected")
	}
	if IsPlainEmail("Jane <jane@example.com>") {
		t.Error("display-name form accepted")
	}
}
