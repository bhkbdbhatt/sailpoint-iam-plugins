package bootstrap

import (
	"context"
	"testing"

	"github.com/sentinel-iam/sentinel/internal/store"
)

func TestEnsureOwnerIdempotent(t *testing.T) {
	st := store.NewMemory()
	c := context.Background()

	res, err := EnsureOwner(c, st, "Acme", "acme", "owner@example.com", "Owner", "supersecret123")
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if !res.TenantCreated || !res.UserCreated {
		t.Fatalf("expected creation on first run: %+v", res)
	}
	if res.User.Role != "owner" {
		t.Fatalf("role: %v", res.User.Role)
	}

	res2, err := EnsureOwner(c, st, "Acme", "acme", "owner@example.com", "Owner", "supersecret123")
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if res2.TenantCreated || res2.UserCreated {
		t.Fatalf("expected idempotent reuse: %+v", res2)
	}
	if res2.Tenant.ID != res.Tenant.ID || res2.User.ID != res.User.ID {
		t.Fatalf("ids changed between runs: %+v vs %+v", res, res2)
	}
}

func TestEnsureOwnerRespectsExistingTenant(t *testing.T) {
	st := store.NewMemory()
	c := context.Background()
	EnsureOwner(c, st, "Acme", "acme", "owner@example.com", "Owner", "supersecret123")

	res, err := EnsureOwner(c, st, "Renamed", "acme", "admin@example.com", "Admin", "supersecret123")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if res.TenantCreated || !res.UserCreated {
		t.Fatalf("expected user-only creation: %+v", res)
	}
	if res.Tenant.Name != "Acme" {
		t.Fatalf("existing tenant renamed: %+v", res.Tenant)
	}
}

func TestEnsureOwnerValidation(t *testing.T) {
	st := store.NewMemory()
	c := context.Background()

	if _, err := EnsureOwner(c, st, "Acme", "acme", "   ", "Owner", "supersecret123"); err == nil {
		t.Fatal("expected missing-email error")
	}
	if _, err := EnsureOwner(c, st, "Acme", "acme", "owner@example.com", "Owner", "weak"); err == nil {
		t.Fatal("expected weak-password error")
	}
}
