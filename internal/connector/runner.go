package connector

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/sentinel-iam/sentinel/internal/metrics"
	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/secrets"
	"github.com/sentinel-iam/sentinel/internal/store"
)

// Runner executes a connector configuration and persists the discovered data.
type Runner struct {
	store    store.Store
	registry *Registry
	box      *secrets.Box
	timeout  time.Duration
	log      *slog.Logger
}

func NewRunner(st store.Store, registry *Registry, box *secrets.Box, timeout time.Duration, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	if registry == nil {
		registry = Default()
	}
	return &Runner{store: st, registry: registry, box: box, timeout: timeout, log: log}
}

// Run loads configID, executes its connector and records the outcome. Connector
// execution failures are recorded on the run (status=failed) and returned with a
// nil error so callers can inspect the run record.
func (r *Runner) Run(ctx context.Context, tenantID, configID, trigger string) (model.ConnectorRun, error) {
	cfg, err := r.store.Connectors().GetConfig(ctx, tenantID, configID)
	if err != nil {
		return model.ConnectorRun{}, err
	}
	start := time.Now().UTC()
	run, err := r.store.Connectors().CreateRun(ctx, model.ConnectorRun{
		TenantID:          tenantID,
		ConnectorConfigID: cfg.ID,
		ConnectorKey:      cfg.Key,
		Trigger:           trigger,
		StartedAt:         start,
		Status:            model.ConnectorStatusRunning,
	})
	if err != nil {
		return model.ConnectorRun{}, err
	}

	conn, ok := r.registry.Get(cfg.Key)
	if !ok {
		return r.fail(ctx, run, cfg, notImplemented(cfg.Key))
	}

	plain, err := r.decrypt(cfg)
	if err != nil {
		return r.fail(ctx, run, cfg, err)
	}

	runCtx := ctx
	if r.timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	result, err := conn.Discover(runCtx, tenantID, plain)
	if err != nil {
		return r.fail(ctx, run, cfg, err)
	}
	if result == nil {
		result = &Result{}
	}

	run.IdentitiesFound = len(result.Identities)
	run.CredentialsFound = len(result.Credentials)
	run.GrantsFound = len(result.Grants)
	run.ResourcesFound = len(result.Resources)

	idByExt, err := r.persistIdentities(ctx, tenantID, result.Identities)
	if err != nil {
		return r.fail(ctx, run, cfg, err)
	}
	resByExt, err := r.persistResources(ctx, tenantID, result.Resources)
	if err != nil {
		return r.fail(ctx, run, cfg, err)
	}
	if err := r.persistCredentials(ctx, tenantID, result.Credentials, idByExt); err != nil {
		return r.fail(ctx, run, cfg, err)
	}
	if err := r.persistGrants(ctx, tenantID, result.Grants, idByExt, resByExt); err != nil {
		return r.fail(ctx, run, cfg, err)
	}

	now := time.Now().UTC()
	run.FinishedAt = &now
	run.Status = model.ConnectorStatusSucceeded
	updated, err := r.store.Connectors().UpdateRun(ctx, run)
	if err != nil {
		return run, err
	}
	r.markConfig(ctx, cfg, model.ConnectorStatusSucceeded, "")
	metrics.ConnectorRuns.Inc(string(cfg.Key), string(run.Status))
	metrics.ConnectorSeconds.Observe(time.Since(start), string(cfg.Key))
	return updated, nil
}

func (r *Runner) fail(ctx context.Context, run model.ConnectorRun, cfg model.ConnectorConfig, cause error) (model.ConnectorRun, error) {
	now := time.Now().UTC()
	run.FinishedAt = &now
	run.Status = model.ConnectorStatusFailed
	run.Error = cause.Error()
	updated, err := r.store.Connectors().UpdateRun(ctx, run)
	if err != nil {
		return run, err
	}
	r.markConfig(ctx, cfg, model.ConnectorStatusFailed, cause.Error())
	metrics.ConnectorRuns.Inc(string(cfg.Key), string(run.Status))
	metrics.ConnectorSeconds.Observe(time.Since(run.StartedAt), string(cfg.Key))
	return updated, nil
}

func (r *Runner) markConfig(ctx context.Context, cfg model.ConnectorConfig, status model.ConnectorStatus, errMsg string) {
	now := time.Now().UTC()
	cfg.LastRunAt = &now
	cfg.LastStatus = status
	cfg.LastError = errMsg
	if _, err := r.store.Connectors().UpdateConfig(ctx, cfg); err != nil {
		r.log.Warn("failed to update connector config", "connector_id", cfg.ID, "error", err)
	}
}

func (r *Runner) decrypt(cfg model.ConnectorConfig) (model.ConnectorConfig, error) {
	if len(cfg.Secrets) == 0 {
		return cfg, nil
	}
	out := cfg
	out.Secrets = make(map[string]string, len(cfg.Secrets))
	for k, v := range cfg.Secrets {
		dec, err := r.box.Decrypt(v)
		if err != nil {
			return cfg, fmt.Errorf("decrypt secret %q: %w", k, err)
		}
		out.Secrets[k] = dec
	}
	return out, nil
}

func extMapKey(source, external string) string { return source + "\x00" + external }

func (r *Runner) persistIdentities(ctx context.Context, tenantID string, items []model.Identity) (map[string]string, error) {
	idByExt := make(map[string]string, len(items))
	stored := make([]model.Identity, 0, len(items))
	for _, in := range items {
		in.ID = ""
		in.TenantID = tenantID
		out, err := r.store.Identities().Upsert(ctx, in)
		if err != nil {
			return nil, err
		}
		stored = append(stored, out)
		if out.ExternalID != "" {
			idByExt[extMapKey(out.SourceSystem, out.ExternalID)] = out.ID
		}
	}
	for _, in := range stored {
		if in.OwnerID == "" {
			continue
		}
		if id, ok := idByExt[extMapKey(in.SourceSystem, in.OwnerID)]; ok {
			in.OwnerID = id
			if _, err := r.store.Identities().Upsert(ctx, in); err != nil {
				return nil, err
			}
		}
	}
	return idByExt, nil
}

func (r *Runner) persistResources(ctx context.Context, tenantID string, items []model.Resource) (map[string]string, error) {
	resByExt := make(map[string]string, len(items))
	for _, in := range items {
		in.ID = ""
		in.TenantID = tenantID
		out, err := r.store.Resources().Upsert(ctx, in)
		if err != nil {
			return nil, err
		}
		if out.ExternalID != "" {
			resByExt[extMapKey(out.SourceSystem, out.ExternalID)] = out.ID
		}
	}
	return resByExt, nil
}

func (r *Runner) persistCredentials(ctx context.Context, tenantID string, items []model.Credential, idByExt map[string]string) error {
	for _, in := range items {
		in.ID = ""
		in.TenantID = tenantID
		if in.IdentityID != "" {
			if id, ok := idByExt[extMapKey(in.SourceSystem, in.IdentityID)]; ok {
				in.IdentityID = id
			}
		}
		if _, err := r.store.Credentials().Upsert(ctx, in); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) persistGrants(ctx context.Context, tenantID string, items []model.AccessGrant, idByExt, resByExt map[string]string) error {
	for _, in := range items {
		in.ID = ""
		in.TenantID = tenantID
		if in.IdentityID != "" {
			if id, ok := idByExt[extMapKey(in.SourceSystem, in.IdentityID)]; ok {
				in.IdentityID = id
			}
		}
		if in.ResourceID != "" {
			if id, ok := resByExt[extMapKey(in.SourceSystem, in.ResourceID)]; ok {
				in.ResourceID = id
			}
		}
		if _, err := r.store.AccessGrants().Upsert(ctx, in); err != nil {
			return err
		}
	}
	return nil
}
