package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifyPasswordErrors(t *testing.T) {
	if _, err := VerifyPassword("not-a-hash", "x"); err == nil {
		t.Fatal("expected error for non-argon2d hash")
	}
	if _, err := VerifyPassword("argon2id$v=19$m=131072", "x"); err == nil {
		t.Fatal("expected error for too few parts")
	}
	withBadParams := "argon2id$v=19$m=not-a-number,t=3,p=4$" + "c2FsdA" + "$" + "aGFzaA"
	if _, err := VerifyPassword(withBadParams, "x"); err == nil {
		t.Fatal("expected error for malformed params")
	}
	withBadSalt := "argon2id$v=19$m=131072,t=3,p=4$%%%$aGFzaA"
	if _, err := VerifyPassword(withBadSalt, "x"); err == nil {
		t.Fatal("expected error for malformed salt")
	}
	withBadHash := "argon2id$v=19$m=131072,t=3,p=4$c2FsdA$%%%"
	if _, err := VerifyPassword(withBadHash, "x"); err == nil {
		t.Fatal("expected error for malformed hash")
	}
}

func TestJWTManagerFromKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt", "key.pem")

	m, err := LoadOrCreateJWTManager(path, "iss", time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if m.TTL() != time.Hour {
		t.Fatalf("ttl: %v", m.TTL())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not written: %v", err)
	}

	// Reload from existing file.
	m2, err := LoadOrCreateJWTManager(path, "iss", 30*time.Minute)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if m2.TTL() != 30*time.Minute {
		t.Fatalf("ttl after reload: %v", m2.TTL())
	}
}

func TestLoadOrCreateJWTManagerErrors(t *testing.T) {
	dir := t.TempDir()

	// Path exists but is a directory -> ReadFile succeeds? No: reads dir yields error
	// that is not IsNotExist -> covered by the "not a valid key file" branch.
	if _, err := LoadOrCreateJWTManager(dir, "iss", time.Hour); err == nil {
		t.Fatal("expected error reading directory as key")
	}

	// Existing file that is not a PEM block.
	badPEM := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(badPEM, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateJWTManager(badPEM, "iss", time.Hour); err == nil {
		t.Fatal("expected error for non-PEM file")
	}

	// PEM block with invalid key material.
	invalid := filepath.Join(dir, "invalid.pem")
	if err := os.WriteFile(invalid, []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateJWTManager(invalid, "iss", time.Hour); err == nil {
		t.Fatal("expected error for invalid key material")
	}

	// Parent path is a file, so MkdirAll fails.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateJWTManager(filepath.Join(blocker, "sub", "key.pem"), "iss", time.Hour); err == nil {
		t.Fatal("expected error when parent is a file")
	}
}

func TestJWTParseRejectsWrongMethod(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	m := NewJWTManagerFromKey(key, "iss", time.Hour)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": jwt.NewNumericDate(time.Now().Add(time.Hour)).Unix(),
		"iat": jwt.NewNumericDate(time.Now()).Unix(),
		"iss": "iss",
	}).SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Parse(token); err == nil || !strings.Contains(err.Error(), "unexpected signing method: HS256") {
		t.Fatalf("expected signing method rejection, got %v", err)
	}
}

func TestJWTParseRejectsGarbage(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	m := NewJWTManagerFromKey(key, "iss", time.Hour)
	if _, err := m.Parse("garbage-token"); err == nil {
		t.Fatal("expected parse failure")
	}
}

func TestValidateAPIKeyFormatRejects(t *testing.T) {
	if err := ValidateAPIKeyFormat("nope"); err == nil {
		t.Fatal("expected rejection of non-prefixed string")
	}
	if err := ValidateAPIKeyFormat(APIKeyPrefix + "short"); err == nil {
		t.Fatal("expected rejection of too-short key")
	}
}
