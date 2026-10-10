package connector

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/store"
)

func TestSchedulerRunOnce(t *testing.T) {
	st := store.NewMemory()
	runner := NewRunner(st, Default(), testBox(t), time.Minute, slog.New(slog.DiscardHandler))
	s := NewScheduler(st, runner, time.Minute, slog.New(slog.DiscardHandler))
	c := context.Background()

	tnt1, _ := st.Tenants().Create(c, model.Tenant{Name: "A", Slug: "t-a"})
	tnt2, _ := st.Tenants().Create(c, model.Tenant{Name: "B", Slug: "t-b"})
	if _, err := st.Connectors().CreateConfig(c, model.ConnectorConfig{TenantID: tnt1.ID, Key: model.ConnectorSimulated, Name: "sim-a", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Connectors().CreateConfig(c, model.ConnectorConfig{TenantID: tnt2.ID, Key: model.ConnectorSimulated, Name: "sim-b", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Connectors().CreateConfig(c, model.ConnectorConfig{TenantID: tnt2.ID, Key: model.ConnectorSimulated, Name: "sim-b-disabled", Enabled: false}); err != nil {
		t.Fatal(err)
	}

	s.RunOnce(c)

	// two successful runs (disabled one skipped)
	_, total, _ := st.Connectors().ListRuns(c, tnt1.ID, store.ConnectorRunFilter{})
	if total != 1 {
		t.Fatalf("tenant1 runs: %d", total)
	}
	_, total, _ = st.Connectors().ListRuns(c, tnt2.ID, store.ConnectorRunFilter{})
	if total != 1 {
		t.Fatalf("tenant2 runs: %d", total)
	}
	all, total, _ := st.Connectors().ListRuns(c, tnt1.ID, store.ConnectorRunFilter{Status: model.ConnectorStatusSucceeded})
	_ = all
	if total != 1 {
		t.Fatalf("succeeded runs: %d", total)
	}
}

func TestSchedulerStartStopsOnCancel(t *testing.T) {
	st := store.NewMemory()
	runner := NewRunner(st, Default(), testBox(t), time.Minute, slog.New(slog.DiscardHandler))
	s := NewScheduler(st, runner, 10*time.Millisecond, slog.New(slog.DiscardHandler))

	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)
}

func TestSchedulerDisabledInterval(t *testing.T) {
	st := store.NewMemory()
	runner := NewRunner(st, Default(), testBox(t), time.Minute, slog.New(slog.DiscardHandler))
	s := NewScheduler(st, runner, 0, slog.New(slog.DiscardHandler))
	s.Start(context.Background()) // must return immediately, not run
	time.Sleep(10 * time.Millisecond)
}
