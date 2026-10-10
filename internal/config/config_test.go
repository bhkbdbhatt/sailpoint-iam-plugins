package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SENTINEL_HTTP_ADDR", "SENTINEL_DATA_DIR", "SENTINEL_STORE", "SENTINEL_LOG_LEVEL",
		"SENTINEL_CORS_ORIGINS", "SENTINEL_METRICS_ENABLED", "SENTINEL_NEO4J_URI", "SENTINEL_NEO4J_USER",
		"SENTINEL_NEO4J_PASSWORD", "SENTINEL_JWT_KEY_PATH", "SENTINEL_JWT_TTL", "SENTINEL_JWT_ISSUER",
		"SENTINEL_MASTER_KEY_PATH", "SENTINEL_SCHEDULER_ENABLED", "SENTINEL_SCHEDULER_INTERVAL",
		"SENTINEL_DISCOVERY_TIMEOUT", "SENTINEL_BOOTSTRAP_TENANT", "SENTINEL_BOOTSTRAP_SLUG",
		"SENTINEL_BOOTSTRAP_EMAIL", "SENTINEL_BOOTSTRAP_NAME", "SENTINEL_BOOTSTRAP_PASSWORD",
	} {
		os.Unsetenv(k)
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	dir := filepath.Join(t.TempDir(), "data")
	t.Setenv("SENTINEL_DATA_DIR", dir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.HTTPAddr != ":8080" || cfg.StoreKind != "file" || cfg.LogLevel != "info" {
		t.Fatalf("defaults: %+v", cfg)
	}
	if !cfg.Metrics || !cfg.SchedulerEnabled {
		t.Fatal("metrics/scheduler should default true")
	}
	if cfg.JWTTTL != 12*time.Hour || cfg.SchedulerInterval != 5*time.Minute {
		t.Fatalf("durations: %+v", cfg)
	}
	if cfg.StorePath() != filepath.Join(dir, "sentinel.json") {
		t.Fatalf("store path: %s", cfg.StorePath())
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("data dir not created: %v", err)
	}
}

func TestLoadOverrides(t *testing.T) {
	clearEnv(t)
	dir := filepath.Join(t.TempDir(), "data")
	t.Setenv("SENTINEL_DATA_DIR", dir)
	t.Setenv("SENTINEL_HTTP_ADDR", "127.0.0.1:9999")
	t.Setenv("SENTINEL_STORE", "memory")
	t.Setenv("SENTINEL_LOG_LEVEL", "debug")
	t.Setenv("SENTINEL_CORS_ORIGINS", "https://a.example.com, https://b.example.com, ")
	t.Setenv("SENTINEL_METRICS_ENABLED", "false")
	t.Setenv("SENTINEL_SCHEDULER_ENABLED", "false")
	t.Setenv("SENTINEL_JWT_TTL", "1h")
	t.Setenv("SENTINEL_SCHEDULER_INTERVAL", "2m")
	t.Setenv("SENTINEL_DISCOVERY_TIMEOUT", "30s")
	t.Setenv("SENTINEL_BOOTSTRAP_EMAIL", "admin@example.com")
	t.Setenv("SENTINEL_BOOTSTRAP_PASSWORD", "bootstrap-pass")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.HTTPAddr != "127.0.0.1:9999" || cfg.StoreKind != "memory" || cfg.LogLevel != "debug" {
		t.Fatalf("overrides: %+v", cfg)
	}
	if cfg.Metrics || cfg.SchedulerEnabled {
		t.Fatal("flags should be false")
	}
	if len(cfg.CORSOrigins) != 2 || cfg.CORSOrigins[0] != "https://a.example.com" {
		t.Fatalf("cors: %v", cfg.CORSOrigins)
	}
	if cfg.JWTTTL != time.Hour || cfg.SchedulerInterval != 2*time.Minute || cfg.DiscoveryTimeout != 30*time.Second {
		t.Fatalf("durations: %+v", cfg)
	}
	if cfg.BootstrapEmail != "admin@example.com" || cfg.BootstrapPassword != "bootstrap-pass" {
		t.Fatalf("bootstrap: %+v", cfg)
	}
}

func TestLoadErrors(t *testing.T) {
	clearEnv(t)
	t.Setenv("SENTINEL_DATA_DIR", t.TempDir())

	t.Setenv("SENTINEL_STORE", "mongo")
	if _, err := Load(); err == nil {
		t.Fatal("bad store accepted")
	}

	t.Setenv("SENTINEL_STORE", "neo4j")
	if _, err := Load(); err == nil {
		t.Fatal("neo4j without password accepted")
	}
	t.Setenv("SENTINEL_NEO4J_PASSWORD", "pw")
	if _, err := Load(); err != nil {
		t.Fatalf("neo4j with password rejected: %v", err)
	}

	t.Setenv("SENTINEL_STORE", "file")
	t.Setenv("SENTINEL_LOG_LEVEL", "loud")
	if _, err := Load(); err == nil {
		t.Fatal("bad log level accepted")
	}
	t.Setenv("SENTINEL_LOG_LEVEL", "warning")
	if _, err := Load(); err != nil {
		t.Fatalf("warning level rejected: %v", err)
	}
	t.Setenv("SENTINEL_LOG_LEVEL", "info")

	t.Setenv("SENTINEL_JWT_TTL", "0s")
	if _, err := Load(); err == nil {
		t.Fatal("zero jwt ttl accepted")
	}
	t.Setenv("SENTINEL_JWT_TTL", "12h")

	t.Setenv("SENTINEL_SCHEDULER_INTERVAL", "-1s")
	if _, err := Load(); err == nil {
		t.Fatal("negative scheduler interval accepted")
	}
	t.Setenv("SENTINEL_SCHEDULER_INTERVAL", "5m")

	// Bad duration falls back to default rather than error.
	t.Setenv("SENTINEL_JWT_TTL", "not-a-duration")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("bad duration should fall back: %v", err)
	}
	if cfg.JWTTTL != 12*time.Hour {
		t.Fatalf("ttl fallback: %v", cfg.JWTTTL)
	}
	t.Setenv("SENTINEL_JWT_TTL", "12h")

	// "warning" scales are handled; verify lowercased log level path.
	t.Setenv("SENTINEL_LOG_LEVEL", "WARN")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("uppercase log level rejected: %v", err)
	}
	if cfg.LogLevel != "WARN" {
		t.Fatalf("log level preserved: %q", cfg.LogLevel)
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("HELPER_TEST_A", "x")
	if got := envOr("HELPER_TEST_A", "def"); got != "x" {
		t.Fatalf("envOr: %q", got)
	}
	if got := envOr("HELPER_MISSING", "def"); got != "def" {
		t.Fatalf("envOr default: %q", got)
	}
	t.Setenv("HELPER_TEST_D", "3s")
	if got := envDuration("HELPER_TEST_D", time.Minute); got != 3*time.Second {
		t.Fatalf("envDuration: %v", got)
	}
	t.Setenv("HELPER_TEST_D", "junk")
	if got := envDuration("HELPER_TEST_D", time.Minute); got != time.Minute {
		t.Fatalf("envDuration fallback: %v", got)
	}
	t.Setenv("HELPER_TEST_B", "true")
	if !envBool("HELPER_TEST_B", false) {
		t.Fatal("envBool true")
	}
	t.Setenv("HELPER_TEST_B", "false")
	if envBool("HELPER_TEST_B", true) {
		t.Fatal("envBool fallback")
	}
	if envBool("HELPER_TEST_B", false) {
		t.Fatal("envBool false")
	}
	t.Setenv("HELPER_TEST_L", "a,b, c ,,d")
	if got := envList("HELPER_TEST_L"); len(got) != 4 || got[2] != "c" {
		t.Fatalf("envList: %v", got)
	}
	if got := envList("HELPER_MISSING"); got != nil {
		t.Fatalf("envList empty: %v", got)
	}
}
