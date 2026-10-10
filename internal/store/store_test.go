package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/sentinel-iam/sentinel/internal/model"
)

func TestMemoryIdentityCRUD(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()

	created, err := st.Identities().Upsert(ctx, model.Identity{
		TenantID:     "t1",
		Type:         model.IdentityHuman,
		Name:         "Alice",
		SourceSystem: "test",
		ExternalID:   "ext-1",
		RiskScore:    10,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected generated id")
	}

	byExt, err := st.Identities().GetByExternal(ctx, "t1", "test", "ext-1")
	if err != nil || byExt.ID != created.ID {
		t.Fatalf("get by external: %v id=%s", err, byExt.ID)
	}

	updated, err := st.Identities().Upsert(ctx, model.Identity{
		TenantID:     "t1",
		Type:         model.IdentityHuman,
		Name:         "Alice Updated",
		SourceSystem: "test",
		ExternalID:   "ext-1",
		RiskScore:    20,
	})
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if updated.ID != created.ID {
		t.Fatal("expected same id on external-id upsert")
	}

	list, total, err := st.Identities().List(ctx, "t1", IdentityFilter{Types: []model.IdentityType{model.IdentityHuman}})
	if err != nil || total != 1 || len(list) != 1 || list[0].Name != "Alice Updated" {
		t.Fatalf("list: err=%v total=%d list=%+v", err, total, list)
	}

	if _, _, err := st.Identities().List(ctx, "other", IdentityFilter{}); err != nil {
		t.Fatalf("list other tenant: %v", err)
	}

	if err := st.Identities().Delete(ctx, "t1", created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.Identities().Get(ctx, "t1", created.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}

func TestMemoryTenantAndUser(t *testing.T) {
	ctx := context.Background()
	st := NewMemory()

	tenant, err := st.Tenants().Create(ctx, model.Tenant{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := st.Tenants().Create(ctx, model.Tenant{Name: "Dup", Slug: "acme"}); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}

	user, err := st.Users().Create(ctx, model.User{
		TenantID:     tenant.ID,
		Email:        "Owner@Example.com",
		Name:         "Owner",
		PasswordHash: "hash",
		Role:         model.RoleOwner,
		Status:       model.StatusActive,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if user.Email != "owner@example.com" {
		t.Fatalf("expected normalized email, got %q", user.Email)
	}
	got, err := st.Users().GetByEmail(ctx, "OWNER@example.com")
	if err != nil || got.ID != user.ID {
		t.Fatalf("get by email: %v", err)
	}
}

func TestFilePersistenceRoundTrip(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.json")

	st, err := NewFile(path)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	tenant, err := st.Tenants().Create(ctx, model.Tenant{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	user, err := st.Users().Create(ctx, model.User{
		TenantID:     tenant.ID,
		Email:        "owner@example.com",
		Name:         "Owner",
		PasswordHash: "argon-hash",
		Role:         model.RoleOwner,
		Status:       model.StatusActive,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := st.Identities().Upsert(ctx, model.Identity{
		TenantID:     tenant.ID,
		Type:         model.IdentityServiceAccount,
		Name:         "svc",
		SourceSystem: "test",
		ExternalID:   "svc-1",
	}); err != nil {
		t.Fatalf("upsert identity: %v", err)
	}

	reopened, err := NewFile(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	gotUser, err := reopened.Users().GetByEmail(ctx, "owner@example.com")
	if err != nil {
		t.Fatalf("get user after reopen: %v", err)
	}
	if gotUser.PasswordHash != "argon-hash" {
		t.Fatalf("password hash not persisted: %q", gotUser.PasswordHash)
	}
	if gotUser.ID != user.ID {
		t.Fatal("user id mismatch after reopen")
	}
	if _, err := reopened.Identities().GetByExternal(ctx, tenant.ID, "test", "svc-1"); err != nil {
		t.Fatalf("identity external index not rebuilt: %v", err)
	}
	if _, err := reopened.Tenants().GetBySlug(ctx, "acme"); err != nil {
		t.Fatalf("tenant slug index not rebuilt: %v", err)
	}
}
