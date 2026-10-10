package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sentinel-iam/sentinel/internal/model"
)

func TestFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")

	m, err := NewFile(path)
	if err != nil {
		t.Fatalf("new file: %v", err)
	}
	c := context.Background()
	tnt, err := m.Tenants().Create(c, model.Tenant{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	uid, err := m.Users().Create(c, model.User{TenantID: tnt.ID, Email: "a@b.com", Name: "A", Role: model.RoleOwner, PasswordHash: "hash-xyz"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	kid, err := m.APIKeys().Create(c, model.APIKey{TenantID: tnt.ID, UserID: uid.ID, Name: "k", Prefix: "pk", Hash: "secret-hash", Role: model.RoleAdmin})
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	iid, err := m.Identities().Upsert(c, model.Identity{TenantID: tnt.ID, Type: model.IdentityHuman, Name: "Alice", SourceSystem: "manual", ExternalID: "ext-1"})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	rid, err := m.Resources().Upsert(c, model.Resource{TenantID: tnt.ID, Name: "r", Type: model.ResourceBucket, SourceSystem: "manual", ExternalID: "res-1"})
	if err != nil {
		t.Fatalf("create resource: %v", err)
	}
	if _, err := m.Credentials().Upsert(c, model.Credential{TenantID: tnt.ID, IdentityID: iid.ID, Type: model.CredentialPassword, Name: "pw", SourceSystem: "manual", ExternalID: "cred-1"}); err != nil {
		t.Fatalf("create cred: %v", err)
	}
	if _, err := m.AccessGrants().Upsert(c, model.AccessGrant{TenantID: tnt.ID, IdentityID: iid.ID, ResourceID: rid.ID, Entitlement: "Read", SourceSystem: "manual", ExternalID: "g-1"}); err != nil {
		t.Fatalf("create grant: %v", err)
	}
	cfg, err := m.Connectors().CreateConfig(c, model.ConnectorConfig{TenantID: tnt.ID, Key: model.ConnectorSimulated, Name: "sim", Secrets: map[string]string{"tok": "s3cr3t"}})
	if err != nil {
		t.Fatalf("create config: %v", err)
	}
	run, err := m.Connectors().CreateRun(c, model.ConnectorRun{TenantID: tnt.ID, ConnectorConfigID: cfg.ID, ConnectorKey: model.ConnectorSimulated, Trigger: "manual", Status: model.ConnectorStatusSucceeded})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if _, err := m.Policies().Create(c, model.Policy{TenantID: tnt.ID, Name: "p", Rules: "r", Engine: "rego", IntentLevel: model.IntentRole}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if _, err := m.Alerts().Create(c, model.Alert{TenantID: tnt.ID, Type: "x", Severity: model.SeverityLow, Description: "d"}); err != nil {
		t.Fatalf("create alert: %v", err)
	}

	// Reload from disk and verify everything round-tripped incl. password hash,
	// key hash, connector secrets, and ext indexes.
	m2, err := NewFile(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	u, err := m2.Users().GetByEmail(c, "a@b.com")
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if u.PasswordHash != "hash-xyz" {
		t.Fatalf("password hash lost: %q", u.PasswordHash)
	}
	k, err := m2.APIKeys().GetByHash(c, "secret-hash")
	if err != nil {
		t.Fatalf("reload key: %v", err)
	}
	if k.ID != kid.ID || k.Hash != "secret-hash" {
		t.Fatalf("key round trip failed: %+v", k)
	}
	if cc, err := m2.Connectors().GetConfig(c, tnt.ID, cfg.ID); err != nil || cc.Secrets["tok"] != "s3cr3t" {
		t.Fatalf("config secrets lost: %v %+v", err, cc)
	}
	if _, err := m2.Identities().GetByExternal(c, tnt.ID, "manual", "ext-1"); err != nil {
		t.Fatalf("identity ext index lost: %v", err)
	}
	if _, err := m2.Resources().GetByExternal(c, tnt.ID, "manual", "res-1"); err != nil {
		t.Fatalf("resource ext index lost: %v", err)
	}
	if _, err := m2.Connectors().GetRun(c, tnt.ID, run.ID); err != nil {
		t.Fatalf("run lost: %v", err)
	}
	if list, err := m2.Tenants().List(c); err != nil || len(list) != 1 {
		t.Fatalf("tenants lost: %v", err)
	}
	if got, _ := m2.Stats().Overview(c, tnt.ID); got.TotalIdentities != 1 {
		t.Fatalf("stats lost: %+v", got)
	}
}

func TestFileReadErrors(t *testing.T) {
	if _, err := NewFile(filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Fatalf("missing file should be fine: %v", err)
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFile(bad); err == nil {
		t.Fatal("expected parse error")
	}
	// empty file is fine
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFile(empty); err != nil {
		t.Fatalf("empty file: %v", err)
	}
}

func TestFileConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	m, err := NewFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c := context.Background()
	tnt, err := m.Tenants().Create(c, model.Tenant{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatal(err)
	}

	const workers = 8
	const perWorker = 5
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			for i := 0; i < perWorker; i++ {
				if _, err := m.Identities().Upsert(c, model.Identity{
					TenantID: tnt.ID, Type: model.IdentityHuman, Name: "u",
					SourceSystem: "manual", ExternalID: "conc-" + string(rune('a'+w)) + "-" + string(rune('0'+i)),
				}); err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}(w)
	}
	for w := 0; w < workers; w++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}

	// All writes must survive a reload, file must be valid JSON.
	m2, err := NewFile(path)
	if err != nil {
		t.Fatalf("reload after concurrency: %v", err)
	}
	_, total, _ := m2.Identities().List(c, tnt.ID, IdentityFilter{Limit: 100})
	if total != workers*perWorker {
		t.Fatalf("expected %d identities, got %d", workers*perWorker, total)
	}
}
