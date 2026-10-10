package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/sentinel-iam/sentinel/internal/model"
)

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("supersecret123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := VerifyPassword(hash, "supersecret123")
	if err != nil || !ok {
		t.Fatalf("expected verify success, got ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword(hash, "wrongpassword")
	if err != nil {
		t.Fatalf("verify wrong: %v", err)
	}
	if ok {
		t.Fatal("expected verify failure for wrong password")
	}
}

func TestGenerateAPIKey(t *testing.T) {
	mat, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !IsAPIKeyToken(mat.Plaintext) {
		t.Fatalf("expected api key token, got %q", mat.Plaintext)
	}
	if err := ValidateAPIKeyFormat(mat.Plaintext); err != nil {
		t.Fatalf("validate format: %v", err)
	}
	if HashAPIKey(mat.Plaintext) != mat.Hash {
		t.Fatal("hash mismatch")
	}
	if IsAPIKeyToken("not-a-key") {
		t.Fatal("unexpected api key detection")
	}
}

func TestJWTIssueAndParse(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	m := NewJWTManagerFromKey(key, "test-issuer", time.Hour)
	token, exp, err := m.Issue("user-1", "tenant-1", "owner", "owner@example.com", "password")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if exp.Before(time.Now()) {
		t.Fatal("token already expired")
	}
	claims, err := m.Parse(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.Subject != "user-1" || claims.TenantID != "tenant-1" || claims.Role != "owner" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestJWTRejectsWrongIssuer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	issuer := NewJWTManagerFromKey(key, "issuer-a", time.Hour)
	parser := NewJWTManagerFromKey(key, "issuer-b", time.Hour)
	token, _, err := issuer.Issue("u", "t", "viewer", "v@example.com", "password")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := parser.Parse(token); err == nil {
		t.Fatal("expected parse failure for wrong issuer")
	}
}

func TestRBAC(t *testing.T) {
	if !Can(model.RoleOwner, PermTenantsWrite) {
		t.Fatal("owner should write tenants")
	}
	if Can(model.RoleViewer, PermTenantsWrite) {
		t.Fatal("viewer must not write tenants")
	}
	if !Can(model.RoleAnalyst, PermAlertsWrite) {
		t.Fatal("analyst should write alerts")
	}
	if Can(model.RoleViewer, PermIdentitiesWrite) {
		t.Fatal("viewer must not write identities")
	}
	if len(Permissions(model.RoleOwner)) == 0 {
		t.Fatal("owner should have permissions")
	}
}
