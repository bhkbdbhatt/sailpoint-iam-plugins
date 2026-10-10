package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sentinel-iam/sentinel/internal/model"
)

func ctx(t *testing.T) context.Context { return context.Background() }

func testTenant(t *testing.T, m *Memory, slug string) model.Tenant {
	t.Helper()
	tnt, err := m.Tenants().Create(ctx(t), model.Tenant{Name: "Sample " + slug, Slug: slug})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tnt
}

func TestMemoryIdentities(t *testing.T) {
	m := NewMemory()
	c := ctx(t)
	tnt := testTenant(t, m, "ids")

	in := model.Identity{TenantID: tnt.ID, Type: model.IdentityHuman, Name: "Alice", SourceSystem: "manual", ExternalID: "ext-1", RiskScore: 30}
	got, err := m.Identities().Upsert(c, in)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if got.ID == "" || got.Status != model.StatusActive || got.CreatedAt.IsZero() {
		t.Fatalf("bad defaults: %+v", got)
	}
	if _, err := m.Identities().Get(c, tnt.ID, got.ID); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := m.Identities().Get(c, "other-tenant", got.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("cross-tenant get: want ErrNotFound, got %v", err)
	}
	if _, err := m.Identities().GetByExternal(c, tnt.ID, "manual", "ext-1"); err != nil {
		t.Fatalf("get by external: %v", err)
	}
	if _, err := m.Identities().GetByExternal(c, tnt.ID, "manual", "nope"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get by external missing: %v", err)
	}

	// Upsert again with same external id must reuse ID and preserve creation.
	time.Sleep(2 * time.Millisecond)
	again := in
	again.Name = "Alice Updated"
	got2, err := m.Identities().Upsert(c, again)
	if err != nil {
		t.Fatalf("upsert existing: %v", err)
	}
	if got2.ID != got.ID || got2.CreatedAt != got.CreatedAt || got2.Name != "Alice Updated" {
		t.Fatalf("upsert existing mismatch: %+v vs %+v", got, got2)
	}

	// Invalid identity rejected.
	if _, err := m.Identities().Upsert(c, model.Identity{TenantID: tnt.ID, Name: "x"}); err == nil {
		t.Fatal("expected validation error")
	}

	// Enforce tenant isolation + filters.
	m2 := NewMemory()
	tnt2 := testTenant(t, m2, "ids2")
	if _, err := m2.Identities().Upsert(c, model.Identity{TenantID: tnt2.ID, Type: model.IdentityWorkload, Name: "Robo", SourceSystem: "aws", RiskScore: 60}); err != nil {
		t.Fatalf("upsert robo: %v", err)
	}
	aliceList, total, err := m2.Identities().List(c, tnt2.ID, IdentityFilter{Query: "alice"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 0 || len(aliceList) != 0 {
		t.Fatalf("cross-tenant leak: %d %d", total, len(aliceList))
	}

	items, total, err := m2.Identities().List(c, tnt2.ID, IdentityFilter{Types: []model.IdentityType{model.IdentityHuman}, MinRisk: 0, MaxRisk: 100, Limit: 10, Offset: 0})
	if err != nil {
		t.Fatalf("list filter: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("type filter: want empty, got %d/%d", total, len(items))
	}

	items, total, err = m2.Identities().List(c, tnt2.ID, IdentityFilter{Types: []model.IdentityType{model.IdentityWorkload}, MinRisk: 25, MaxRisk: 100, SourceSystem: "aws"})
	if err != nil {
		t.Fatalf("list robo: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Name != "Robo" {
		t.Fatalf("robo list: %d/%d", total, len(items))
	}

	// Offset beyond total.
	items, total, err = m2.Identities().List(c, tnt2.ID, IdentityFilter{Offset: 50})
	if err != nil {
		t.Fatalf("list offset: %v", err)
	}
	if len(items) != 0 || total != 1 {
		t.Fatalf("offset list: %d/%d", total, len(items))
	}

	// Delete.
	if err := m2.Identities().Delete(c, tnt2.ID, items2ID(t, m2, tnt2.ID)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := m2.Identities().Delete(c, tnt2.ID, "missing"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

func items2ID(t *testing.T, m *Memory, tenantID string) string {
	t.Helper()
	all, total, err := m.Identities().List(context.Background(), tenantID, IdentityFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total == 0 || len(all) == 0 {
		t.Fatalf("no identities to delete")
	}
	return all[len(all)-1].ID
}

func TestMemoryCredentials(t *testing.T) {
	m := NewMemory()
	c := ctx(t)
	tnt := testTenant(t, m, "creds")
	tid := "ident-1"

	exp := time.Now().UTC().Add(10 * 24 * time.Hour)
	in := model.Credential{TenantID: tnt.ID, IdentityID: tid, Type: model.CredentialAccessKey, Name: "prod-key", SourceSystem: "aws", ExternalID: "AKIA1", ExpiresAt: &exp}
	got, err := m.Credentials().Upsert(c, in)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	items, total, err := m.Credentials().List(c, tnt.ID, CredentialFilter{IdentityID: tid, ExpiringWithinDays: 30})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("list: %d/%d", total, len(items))
	}
	// filter out of window
	_, total, _ = m.Credentials().List(c, tnt.ID, CredentialFilter{ExpiringWithinDays: 5})
	if total != 0 {
		t.Fatalf("expiry filter: %d", total)
	}
	// type filter
	if _, total, _ = m.Credentials().List(c, tnt.ID, CredentialFilter{Types: []model.CredentialType{model.CredentialPassword}}); total != 0 {
		t.Fatal("cred type filter failed")
	}
	if _, total, _ = m.Credentials().List(c, tnt.ID, CredentialFilter{Types: []model.CredentialType{model.CredentialAccessKey}}); total != 1 {
		t.Fatal("cred type filter failed")
	}

	// dedupe by external ID
	got2, err := m.Credentials().Upsert(c, in)
	if err != nil {
		t.Fatalf("upsert dup: %v", err)
	}
	if got2.ID != got.ID {
		t.Fatal("credential dedupe failed")
	}

	if _, err := m.Credentials().Get(c, tnt.ID, got.ID); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := m.Credentials().Get(c, "other", got.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("cross-tenant: %v", err)
	}
	if err := m.Credentials().Delete(c, tnt.ID, got.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := m.Credentials().Delete(c, tnt.ID, got.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if _, err := m.Credentials().Upsert(c, model.Credential{TenantID: tnt.ID, Type: model.CredentialPassword}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestMemoryGrantsAndResources(t *testing.T) {
	m := NewMemory()
	c := ctx(t)
	tnt := testTenant(t, m, "grants")

	r1, err := m.Resources().Upsert(c, model.Resource{TenantID: tnt.ID, Name: "s3-bucket", Type: model.ResourceBucket, SourceSystem: "aws", ExternalID: "bucket-1"})
	if err != nil {
		t.Fatalf("resource upsert: %v", err)
	}
	r2, _ := m.Resources().Upsert(c, model.Resource{TenantID: tnt.ID, Name: "db-prod", Type: model.ResourceDatabase, SourceSystem: "aws", ExternalID: "db-1"})
	got, err := m.Resources().GetByExternal(c, tnt.ID, "aws", "bucket-1")
	if err != nil || got.ID != r1.ID {
		t.Fatalf("get by external: %v %s", err, got.ID)
	}
	if _, err := m.Resources().GetByExternal(c, tnt.ID, "aws", "nope"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get by ext missing: %v", err)
	}
	items, total, _ := m.Resources().List(c, tnt.ID, ResourceFilter{Type: model.ResourceBucket})
	if total != 1 || items[0].ID != r1.ID {
		t.Fatalf("resource list: %d", total)
	}
	if _, total, _ := m.Resources().List(c, tnt.ID, ResourceFilter{Query: "db"}); total != 1 {
		t.Fatalf("resource query: %d", total)
	}
	// dedupe
	r1again, err := m.Resources().Upsert(c, model.Resource{TenantID: tnt.ID, Name: "s3-bucket", Type: model.ResourceBucket, SourceSystem: "aws", ExternalID: "bucket-1"})
	if err != nil {
		t.Fatalf("resource dedupe: %v", err)
	}
	if r1again.ID != r1.ID {
		t.Fatalf("resource dedupe changed id")
	}
	if err := m.Resources().Delete(c, tnt.ID, r2.ID); err != nil {
		t.Fatalf("delete resource: %v", err)
	}
	if _, err := m.Resources().Get(c, tnt.ID, r2.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get deleted resource: %v", err)
	}

	g1, err := m.AccessGrants().Upsert(c, model.AccessGrant{TenantID: tnt.ID, IdentityID: "i-1", ResourceID: r1.ID, Entitlement: "Read", SourceSystem: "aws", ExternalID: "g-1"})
	if err != nil {
		t.Fatalf("grant upsert: %v", err)
	}
	g2, _ := m.AccessGrants().Upsert(c, model.AccessGrant{TenantID: tnt.ID, IdentityID: "i-2", ResourceID: r1.ID, Entitlement: "Write", SourceSystem: "aws", ExternalID: "g-2"})
	if _, total, _ := m.AccessGrants().List(c, tnt.ID, AccessGrantFilter{IdentityID: "i-1"}); total != 1 {
		t.Fatalf("grant list by identity: %d", total)
	}
	if _, total, _ := m.AccessGrants().List(c, tnt.ID, AccessGrantFilter{ResourceID: r1.ID}); total != 2 {
		t.Fatalf("grant list by resource: %d", total)
	}
	if _, total, _ := m.AccessGrants().List(c, tnt.ID, AccessGrantFilter{SourceSystem: "azure"}); total != 0 {
		t.Fatalf("grant list by source: %d", total)
	}
	if _, err := m.AccessGrants().Get(c, tnt.ID, g2.ID); err != nil {
		t.Fatalf("get grant: %v", err)
	}
	if err := m.AccessGrants().Delete(c, tnt.ID, g1.ID); err != nil {
		t.Fatalf("delete grant: %v", err)
	}
	if _, err := m.AccessGrants().Get(c, tnt.ID, g1.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get deleted grant: %v", err)
	}
}

func TestMemoryUsers(t *testing.T) {
	m := NewMemory()
	c := ctx(t)
	tnt := testTenant(t, m, "users")

	u, err := m.Users().Create(c, model.User{TenantID: tnt.ID, Email: "a@Example.com", Name: "Ada", Role: model.RoleAnalyst, PasswordHash: "h"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Email != "a@example.com" {
		t.Fatalf("email not lowercased: %s", u.Email)
	}
	if _, err := m.Users().Create(c, model.User{TenantID: tnt.ID, Email: "A@example.com", Name: "Ada2", Role: model.RoleViewer}); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("duplicate email: %v", err)
	}
	byEmail, err := m.Users().GetByEmail(c, "A@EXAMPLE.COM")
	if err != nil || byEmail.ID != u.ID {
		t.Fatalf("get by email: %v", err)
	}
	if _, err := m.Users().GetByEmail(c, "missing@example.com"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get by email missing: %v", err)
	}
	if _, err := m.Users().Get(c, tnt.ID, u.ID); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, total, _ := m.Users().List(c, tnt.ID, UserFilter{Role: model.RoleAnalyst}); total != 1 {
		t.Fatalf("list by role: %d", total)
	}
	if _, total, _ := m.Users().List(c, tnt.ID, UserFilter{Query: "ada"}); total != 1 {
		t.Fatalf("list by query: %d", total)
	}

	// Update preserves hash, updates email index.
	u2, err := m.Users().Update(c, model.User{ID: u.ID, TenantID: tnt.ID, Email: "ada2@example.com", Name: "Ada L", Role: model.RoleOwner})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if u2.PasswordHash != "h" || u2.Email != "ada2@example.com" {
		t.Fatalf("update mismatch: %+v", u2)
	}
	if _, err := m.Users().GetByEmail(c, "a@example.com"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("old email still indexed: %v", err)
	}
	if _, err := m.Users().Update(c, model.User{ID: "missing-id", TenantID: tnt.ID, Email: "taken@example.com", Name: "x", Role: model.RoleViewer}); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if err := m.Users().Delete(c, tnt.ID, u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := m.Users().Get(c, tnt.ID, u.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get deleted: %v", err)
	}
	if err := m.Users().Delete(c, tnt.ID, u.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestMemoryAPIKeys(t *testing.T) {
	m := NewMemory()
	c := ctx(t)
	tnt := testTenant(t, m, "keys")

	rev := false
	k, err := m.APIKeys().Create(c, model.APIKey{TenantID: tnt.ID, UserID: "u-1", Name: "ci", Prefix: "sk", Hash: "hash-1", Role: model.RoleAdmin})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := m.APIKeys().Create(c, model.APIKey{TenantID: tnt.ID, UserID: "u-1", Name: "ci2", Prefix: "sk", Hash: "hash-1", Role: model.RoleAdmin}); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("duplicate hash: %v", err)
	}
	if _, err := m.APIKeys().Create(c, model.APIKey{TenantID: tnt.ID, UserID: "u-1", Name: "ci", Prefix: "sk", Role: model.RoleAdmin}); !errors.Is(err, model.ErrInvalid) {
		t.Fatalf("empty hash: %v", err)
	}
	if byHash, err := m.APIKeys().GetByHash(c, "hash-1"); err != nil || byHash.ID != k.ID {
		t.Fatalf("get by hash: %v", err)
	}
	if _, err := m.APIKeys().GetByHash(c, "nope"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get by hash missing: %v", err)
	}
	if _, total, _ := m.APIKeys().List(c, tnt.ID, APIKeyFilter{UserID: "u-1", Revoked: &rev}); total != 1 {
		t.Fatalf("list: %d", total)
	}
	// revoked filter excludes active
	revT := true
	if _, total, _ := m.APIKeys().List(c, tnt.ID, APIKeyFilter{Revoked: &revT}); total != 0 {
		t.Fatalf("revoked filter: %d", total)
	}
	upd, err := m.APIKeys().Update(c, model.APIKey{ID: k.ID, TenantID: tnt.ID, UserID: "u-1", Name: "ci-upd", Role: model.RoleViewer, Revoked: true})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.Hash != "hash-1" || upd.Prefix != "sk" || !upd.Revoked {
		t.Fatalf("update mismatch: %+v", upd)
	}
	if err := m.APIKeys().Delete(c, tnt.ID, k.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := m.APIKeys().Get(c, tnt.ID, k.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get deleted: %v", err)
	}
}

func TestMemoryConnectors(t *testing.T) {
	m := NewMemory()
	c := ctx(t)
	tnt := testTenant(t, m, "conns")

	cfg, err := m.Connectors().CreateConfig(c, model.ConnectorConfig{TenantID: tnt.ID, Key: model.ConnectorSimulated, Name: "sim", Enabled: true, IntervalMinutes: 5, Secrets: map[string]string{"k": "v"}})
	if err != nil {
		t.Fatalf("create config: %v", err)
	}
	if cfg.LastStatus != model.ConnectorStatusIdle {
		t.Fatalf("default status: %s", cfg.LastStatus)
	}
	enabled := true
	if _, total, _ := m.Connectors().ListConfigs(c, tnt.ID, ConnectorFilter{Key: model.ConnectorSimulated, Enabled: &enabled}); total != 1 {
		t.Fatalf("list configs: %d", total)
	}
	if _, total, _ := m.Connectors().ListConfigs(c, tnt.ID, ConnectorFilter{Key: model.ConnectorAWSIAM}); total != 0 {
		t.Fatalf("list configs key: %d", total)
	}
	if _, err := m.Connectors().GetConfig(c, tnt.ID, cfg.ID); err != nil {
		t.Fatalf("get config: %v", err)
	}
	// update without secrets preserves existing
	upd, err := m.Connectors().UpdateConfig(c, model.ConnectorConfig{ID: cfg.ID, TenantID: tnt.ID, Key: model.ConnectorSimulated, Name: "sim2", Enabled: false, IntervalMinutes: 10})
	if err != nil {
		t.Fatalf("update config: %v", err)
	}
	if upd.Secrets["k"] != "v" || upd.Name != "sim2" {
		t.Fatalf("update mismatch: %+v", upd)
	}

	// invalid interval
	if _, err := m.Connectors().CreateConfig(c, model.ConnectorConfig{TenantID: tnt.ID, Key: model.ConnectorSimulated, Name: "x", IntervalMinutes: 999999}); err == nil {
		t.Fatal("expected validation error")
	}

	start := time.Now().UTC().Add(-time.Minute)
	run, err := m.Connectors().CreateRun(c, model.ConnectorRun{TenantID: tnt.ID, ConnectorConfigID: cfg.ID, ConnectorKey: model.ConnectorSimulated, Trigger: "manual", StartedAt: start, Status: model.ConnectorStatusRunning})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	fin := time.Now().UTC()
	run.Status = model.ConnectorStatusSucceeded
	run.FinishedAt = &fin
	run.IdentitiesFound = 3
	if _, err := m.Connectors().UpdateRun(c, run); err != nil {
		t.Fatalf("update run: %v", err)
	}
	gotRun, err := m.Connectors().GetRun(c, tnt.ID, run.ID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if gotRun.Status != model.ConnectorStatusSucceeded {
		t.Fatalf("run status: %s", gotRun.Status)
	}
	if _, total, _ := m.Connectors().ListRuns(c, tnt.ID, ConnectorRunFilter{ConfigID: cfg.ID, Status: model.ConnectorStatusSucceeded}); total != 1 {
		t.Fatalf("list runs: %d", total)
	}
	if _, total, _ := m.Connectors().ListRuns(c, tnt.ID, ConnectorRunFilter{Status: model.ConnectorStatusFailed}); total != 0 {
		t.Fatalf("list runs status: %d", total)
	}
	if _, err := m.Connectors().CreateRun(c, model.ConnectorRun{TenantID: "other", ConnectorConfigID: cfg.ID, Trigger: "x", Status: model.ConnectorStatusIdle}); err != nil {
		t.Fatalf("create run other: %v", err)
	}
	// cross-tenant run list remains correct
	if _, total, _ := m.Connectors().ListRuns(c, tnt.ID, ConnectorRunFilter{}); total != 1 {
		t.Fatalf("run isolation: %d", total)
	}

	if err := m.Connectors().DeleteConfig(c, tnt.ID, cfg.ID); err != nil {
		t.Fatalf("delete config: %v", err)
	}
	if _, err := m.Connectors().GetConfig(c, tnt.ID, cfg.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get deleted config: %v", err)
	}
}

func TestMemoryTenants(t *testing.T) {
	m := NewMemory()
	c := ctx(t)
	testTenant(t, m, "ten-alpha")
	beta := testTenant(t, m, "ten-beta")

	if _, err := m.Tenants().Create(c, model.Tenant{Name: "dup", Slug: "ten-beta"}); !errors.Is(err, model.ErrConflict) {
		t.Fatalf("duplicate slug: %v", err)
	}
	if _, err := m.Tenants().Create(c, model.Tenant{Name: "bad", Slug: "UPPER"}); err == nil {
		t.Fatal("expected slug validation")
	}
	bySlug, err := m.Tenants().GetBySlug(c, "ten-beta")
	if err != nil || bySlug.ID != beta.ID {
		t.Fatalf("get by slug: %v", err)
	}
	if _, err := m.Tenants().GetBySlug(c, "nope"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get by slug missing: %v", err)
	}
	list, err := m.Tenants().List(c)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v %d", err, len(list))
	}
	if count, _ := m.Tenants().Count(c); count != 2 {
		t.Fatalf("count: %d", count)
	}
	if _, err := m.Tenants().Get(c, "missing"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
}

func TestMemoryPolicies(t *testing.T) {
	m := NewMemory()
	c := ctx(t)
	tnt := testTenant(t, m, "pols")

	p, err := m.Policies().Create(c, model.Policy{TenantID: tnt.ID, Name: "90d rotation", Rules: `{ "engine": "credential-age", "max_days": 90 }`, Engine: "rego", IntentLevel: model.IntentRole})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.Status != model.PolicyDraft {
		t.Fatalf("default status: %s", p.Status)
	}
	upd, err := m.Policies().Update(c, model.Policy{ID: p.ID, TenantID: tnt.ID, Name: "90d rotation v2", Rules: p.Rules, Engine: "rego", IntentLevel: model.IntentOrg, Status: model.PolicyActive})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.Status != model.PolicyActive {
		t.Fatalf("update status: %s", upd.Status)
	}
	if _, total, _ := m.Policies().List(c, tnt.ID, PolicyFilter{IntentLevel: model.IntentOrg, Status: model.PolicyActive, Engine: "rego"}); total != 1 {
		t.Fatalf("list: %d", total)
	}
	if _, total, _ := m.Policies().List(c, tnt.ID, PolicyFilter{Query: "rotation"}); total != 1 {
		t.Fatalf("list query: %d", total)
	}
	if _, err := m.Policies().Get(c, tnt.ID, p.ID); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := m.Policies().Update(c, model.Policy{ID: "x", TenantID: tnt.ID, Name: "n", Rules: "r", Engine: "rego", IntentLevel: model.IntentOrg}); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if _, err := m.Policies().Create(c, model.Policy{TenantID: tnt.ID, Name: "bad", Rules: "r"}); err == nil {
		t.Fatal("expected validation error")
	}
	if err := m.Policies().Delete(c, tnt.ID, p.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := m.Policies().Delete(c, tnt.ID, p.ID); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestMemoryAlerts(t *testing.T) {
	m := NewMemory()
	c := ctx(t)
	tnt := testTenant(t, m, "alert-t")

	a, err := m.Alerts().Create(c, model.Alert{TenantID: tnt.ID, IdentityID: "i-9", Type: "stale", Severity: model.SeverityHigh, Description: "stale key"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.Status != model.AlertOpen || a.DetectedAt.IsZero() {
		t.Fatalf("defaults: %+v", a)
	}
	upd, err := m.Alerts().Update(c, model.Alert{ID: a.ID, TenantID: tnt.ID, IdentityID: "i-9", Type: "stale", Severity: model.SeverityMedium, Description: "stale key", Status: model.AlertResolved})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.Status != model.AlertResolved {
		t.Fatalf("update status: %s", upd.Status)
	}
	if _, total, _ := m.Alerts().List(c, tnt.ID, AlertFilter{IdentityID: "i-9", Type: "stale", Severity: model.SeverityMedium, Status: model.AlertResolved}); total != 1 {
		t.Fatalf("list: %d", total)
	}
	if _, total, _ := m.Alerts().List(c, tnt.ID, AlertFilter{Status: model.AlertOpen}); total != 0 {
		t.Fatalf("list status: %d", total)
	}
	if _, err := m.Alerts().Get(c, tnt.ID, a.ID); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := m.Alerts().Create(c, model.Alert{TenantID: tnt.ID, Type: "x", Severity: model.SeverityInfo}); err == nil {
		t.Fatal("expected validation error")
	}
	if err := m.Alerts().Delete(c, tnt.ID, a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestMemoryStatsOverview(t *testing.T) {
	m := NewMemory()
	c := ctx(t)
	tnt := testTenant(t, m, "stats")

	if _, err := m.Identities().Upsert(c, model.Identity{TenantID: tnt.ID, Type: model.IdentityHuman, Name: "A", SourceSystem: "manual", RiskScore: 30}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Identities().Upsert(c, model.Identity{TenantID: tnt.ID, Type: model.IdentityWorkload, Name: "B", SourceSystem: "aws", RiskScore: 80, OwnerID: "someone"}); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().UTC().Add(15 * 24 * time.Hour)
	if _, err := m.Credentials().Upsert(c, model.Credential{TenantID: tnt.ID, IdentityID: "i-1", Type: model.CredentialAccessKey, Name: "k", SourceSystem: "aws", ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	res, err := m.Resources().Upsert(c, model.Resource{TenantID: tnt.ID, Name: "r", Type: model.ResourceIAMPolicy, SourceSystem: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AccessGrants().Upsert(c, model.AccessGrant{TenantID: tnt.ID, IdentityID: "i-1", ResourceID: res.ID, Entitlement: "attach", SourceSystem: "aws"}); err != nil {
		t.Fatal(err)
	}

	start := time.Now().UTC().Add(-time.Hour)
	fin := time.Now().UTC()
	if _, err := m.Connectors().CreateRun(c, model.ConnectorRun{TenantID: tnt.ID, ConnectorKey: model.ConnectorSimulated, Trigger: "sched", StartedAt: start, FinishedAt: &fin, Status: model.ConnectorStatusSucceeded}); err != nil {
		t.Fatal(err)
	}

	ov, err := m.Stats().Overview(c, tnt.ID)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if ov.TotalIdentities != 2 || ov.TotalCredentials != 1 || ov.TotalGrants != 1 || ov.TotalResources != 1 {
		t.Fatalf("overview counts: %+v", ov)
	}
	if ov.CredentialsExpiring30 != 1 {
		t.Fatalf("expiring: %d", ov.CredentialsExpiring30)
	}
	if ov.UnownedIdentities != 1 || ov.OwnerCoveragePct != 50 {
		t.Fatalf("ownership: %+v", ov)
	}
	if ov.LastConnectorRunAt == nil {
		t.Fatal("last run nil")
	}
	if ov.RiskBuckets[string(model.RiskMedium)] != 1 || ov.RiskBuckets[string(model.RiskCritical)] != 1 {
		t.Fatalf("risk buckets: %+v", ov.RiskBuckets)
	}
}

func TestMemoryPingClose(t *testing.T) {
	m := NewMemory()
	if err := m.Ping(ctx(t)); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
