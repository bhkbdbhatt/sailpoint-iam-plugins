package cli

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/sentinel-iam/sentinel/internal/config"
	"github.com/sentinel-iam/sentinel/internal/store"
)

func openStore(cfg *config.Config) (store.Store, error) {
	switch cfg.StoreKind {
	case "memory":
		return store.NewMemory(), nil
	case "file":
		return store.NewFile(cfg.StorePath())
	case "neo4j":
		return nil, errors.New("neo4j store is not implemented in this build; set SENTINEL_STORE=file or memory")
	default:
		return nil, fmt.Errorf("unknown store kind %q", cfg.StoreKind)
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler)
}
