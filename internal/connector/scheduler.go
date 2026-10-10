package connector

import (
	"context"
	"log/slog"
	"time"

	"github.com/sentinel-iam/sentinel/internal/metrics"
	"github.com/sentinel-iam/sentinel/internal/store"
)

// Scheduler periodically runs enabled connectors for every tenant.
type Scheduler struct {
	store    store.Store
	runner   *Runner
	interval time.Duration
	log      *slog.Logger
}

func NewScheduler(st store.Store, runner *Runner, interval time.Duration, log *slog.Logger) *Scheduler {
	if log == nil {
		log = slog.Default()
	}
	return &Scheduler{store: st, runner: runner, interval: interval, log: log}
}

// Start launches the scheduler loop. It returns immediately; the loop stops when
// ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	if s.interval <= 0 {
		s.log.Warn("scheduler disabled: interval must be positive")
		return
	}
	go func() {
		s.log.Info("scheduler started", "interval", s.interval)
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				s.log.Info("scheduler stopped")
				return
			case <-ticker.C:
				metrics.SchedulerTicks.Inc(s.interval.String())
				s.RunOnce(ctx)
			}
		}
	}()
}

// RunOnce executes all enabled connectors across all tenants.
func (s *Scheduler) RunOnce(ctx context.Context) {
	tenants, err := s.store.Tenants().List(ctx)
	if err != nil {
		s.log.Error("scheduler: list tenants", "error", err)
		return
	}
	enabled := true
	for _, tenant := range tenants {
		configs, _, err := s.store.Connectors().ListConfigs(ctx, tenant.ID, store.ConnectorFilter{Enabled: &enabled})
		if err != nil {
			s.log.Error("scheduler: list connectors", "tenant_id", tenant.ID, "error", err)
			continue
		}
		for _, cfg := range configs {
			if ctx.Err() != nil {
				return
			}
			run, err := s.runner.Run(ctx, tenant.ID, cfg.ID, "scheduled")
			if err != nil {
				s.log.Error("scheduler: run connector", "tenant_id", tenant.ID, "connector_id", cfg.ID, "error", err)
				continue
			}
			s.log.Info("scheduler: connector finished",
				"tenant_id", tenant.ID,
				"connector_id", cfg.ID,
				"status", run.Status,
			)
		}
	}
}
