package connector

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/secrets"
	"github.com/sentinel-iam/sentinel/internal/store"
)

func testBox(t *testing.T) *secrets.Box {
	t.Helper()
	box, err := secrets.NewFromKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("box: %v", err)
	}
	return box
}

func testRunner(t *testing.T) (*store.Memory, *Runner) {
	t.Helper()
	st := store.NewMemory()
	return st, NewRunner(st, Default(), testBox(t), time.Minute, slog.New(slog.DiscardHandler))
}

func TestRunnerRunSuccess(t *testing.T) {
	st, r := testRunner(t)
	c := context.Background()
	tnt, err := st.Tenants().Create(c, model.Tenant{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := st.Connectors().CreateConfig(c, model.ConnectorConfig{TenantID: tnt.ID, Key: model.ConnectorSimulated, Name: "sim", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	run, err := r.Run(c, tnt.ID, cfg.ID, "manual")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if run.Status != model.ConnectorStatusSucceeded {
		t.Fatalf("run status %s (error %s)", run.Status, run.Error)
	}
	if run.Trigger != "manual" || run.ConnectorConfigID != cfg.ID || run.ConnectorKey != model.ConnectorSimulated {
		t.Fatalf("run meta: %+v", run)
	}
	if run.IdentitiesFound == 0 || run.ResourcesFound == 0 || run.GrantsFound == 0 {
		t.Fatalf("no data: %+v", run)
	}
	// config marked succeeded
	got, _ := st.Connectors().GetConfig(c, tnt.ID, cfg.ID)
	if got.LastStatus != model.ConnectorStatusSucceeded || got.LastRunAt == nil {
		t.Fatalf("config not marked: %+v", got)
	}
	// run persisted
	if _, err := st.Connectors().GetRun(c, tnt.ID, run.ID); err != nil {
		t.Fatalf("run not persisted: %v", err)
	}
}

func TestRunnerRunUnknownConnector(t *testing.T) {
	st, r := testRunner(t)
	c := context.Background()
	tnt, err := st.Tenants().Create(c, model.Tenant{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := st.Connectors().CreateConfig(c, model.ConnectorConfig{TenantID: tnt.ID, Key: model.ConnectorAzureEntra, Name: "entra", Enabled: true})

	run, err := r.Run(c, tnt.ID, cfg.ID, "manual")
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if run.Status != model.ConnectorStatusFailed {
		t.Fatalf("expected failed, got %s", run.Status)
	}
	if run.Error == "" {
		t.Fatal("expected error message on run")
	}
	got, _ := st.Connectors().GetConfig(c, tnt.ID, cfg.ID)
	if got.LastStatus != model.ConnectorStatusFailed || got.LastError == "" {
		t.Fatalf("config not marked failed: %+v", got)
	}
}

func TestRunnerRunMissingConfig(t *testing.T) {
	_, r := testRunner(t)
	if _, err := r.Run(context.Background(), "t", "nope", "manual"); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestRunnerRunSecretDecryptFailure(t *testing.T) {
	st, r := testRunner(t)
	c := context.Background()
	tnt, _ := st.Tenants().Create(c, model.Tenant{Name: "Acme", Slug: "acme"})
	cfg, _ := st.Connectors().CreateConfig(c, model.ConnectorConfig{
		TenantID: tnt.ID, Key: model.ConnectorSimulated, Name: "sim",
		Secrets: map[string]string{"access_key_id": "not-valid-ciphertext"},
	})
	run, err := r.Run(c, tnt.ID, cfg.ID, "manual")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if run.Status != model.ConnectorStatusFailed {
		t.Fatalf("expected failed on decrypt error, got %s", run.Status)
	}
}

func TestRunnerRunEncryptedSecret(t *testing.T) {
	st := store.NewMemory()
	box := testBox(t)
	r := NewRunner(st, Default(), box, time.Minute, slog.New(slog.DiscardHandler))
	c := context.Background()
	tnt, _ := st.Tenants().Create(c, model.Tenant{Name: "Acme", Slug: "acme"})

	enc, err := box.Encrypt("AKIA-SECRET")
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := st.Connectors().CreateConfig(c, model.ConnectorConfig{
		TenantID: tnt.ID, Key: model.ConnectorSimulated, Name: "sim",
		Secrets: map[string]string{"access_key_id": enc},
	})
	run, err := r.Run(c, tnt.ID, cfg.ID, "manual")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if run.Status != model.ConnectorStatusSucceeded {
		t.Fatalf("encrypted secret should decrypt and succeed, got %s: %s", run.Status, run.Error)
	}
}

// staticConnector returns a fixed result for owner-resolution and uration tests.
type staticConnector struct {
	key    model.ConnectorKey
	result *Result
}

func (s staticConnector) Key() model.ConnectorKey { return s.key }
func (s staticConnector) Discover(context.Context, string, model.ConnectorConfig) (*Result, error) {
	return s.result, nil
}

func TestRunnerOwnerResolution(t *testing.T) {
	st := store.NewMemory()
	registry := NewRegistry()
	registry.Register(staticConnector{key: model.ConnectorAWSIAM, result: &Result{
		Identities: []model.Identity{
			{TenantID: "x", Type: model.IdentityHuman, Name: "alice", SourceSystem: "aws_iam", ExternalID: "arn:alice"},
			{TenantID: "x", Type: model.IdentityWorkload, Name: "bob", SourceSystem: "aws_iam", ExternalID: "arn:bob", OwnerID: "arn:alice"},
		},
		Credentials: []model.Credential{
			{TenantID: "x", IdentityID: "arn:bob", Type: model.CredentialAccessKey, Name: "k", SourceSystem: "aws_iam", ExternalID: "AKIA1"},
		},
	}})
	r := NewRunner(st, registry, testBox(t), time.Minute, slog.New(slog.DiscardHandler))
	c := context.Background()
	tnt, _ := st.Tenants().Create(c, model.Tenant{Name: "Acme", Slug: "acme"})

	cfg, _ := st.Connectors().CreateConfig(c, model.ConnectorConfig{TenantID: tnt.ID, Key: model.ConnectorAWSIAM, Name: "aws"})
	run, err := r.Run(c, tnt.ID, cfg.ID, "manual")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if run.Status != model.ConnectorStatusSucceeded {
		t.Fatalf("run failed: %s %s", run.Status, run.Error)
	}

	items, total, _ := st.Identities().List(c, tnt.ID, store.IdentityFilter{})
	if total != 2 {
		t.Fatalf("identities: %d", total)
	}
	byExt := map[string]string{}
	for _, id := range items {
		byExt[id.ExternalID] = id.ID
	}
	var bob model.Identity
	for _, id := range items {
		if id.Name == "bob" {
			bob = id
		}
	}
	if bob.OwnerID != byExt["arn:alice"] {
		t.Fatalf("owner not resolved: %q vs %q", bob.OwnerID, byExt["arn:alice"])
	}
	// credential identity ref resolved
	creds, total, _ := st.Credentials().List(c, tnt.ID, store.CredentialFilter{})
	if total != 1 {
		t.Fatalf("creds: %d", total)
	}
	if creds[0].IdentityID != byExt["arn:bob"] {
		t.Fatalf("credential identity not resolved: %q", creds[0].IdentityID)
	}
}

func TestRegistryKeys(t *testing.T) {
	reg := NewRegistry()
	reg.Register(Simulated{})
	reg.Register(NewAWSIAM())
	if len(reg.Keys()) != 2 {
		t.Fatalf("keys: %v", reg.Keys())
	}
	if _, ok := reg.Get(model.ConnectorSimulated); !ok {
		t.Fatal("simulated missing")
	}
	if _, ok := reg.Get("unknown"); ok {
		t.Fatal("unknown key present")
	}
	if Default() == nil {
		t.Fatal("default registry nil")
	}
}
