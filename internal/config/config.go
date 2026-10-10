package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr  string
	DataDir   string
	StoreKind string
	LogLevel  string

	CORSOrigins []string
	Metrics     bool

	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string

	JWTKeyPath string
	JWTTTL     time.Duration
	Issuer     string

	MasterKeyPath string

	SchedulerEnabled  bool
	SchedulerInterval time.Duration
	DiscoveryTimeout  time.Duration

	BootstrapTenant   string
	BootstrapSlug     string
	BootstrapEmail    string
	BootstrapName     string
	BootstrapPassword string
}

func Load() (*Config, error) {
	dataDir := envOr("SENTINEL_DATA_DIR", "./data")
	cfg := &Config{
		HTTPAddr:          envOr("SENTINEL_HTTP_ADDR", ":8080"),
		DataDir:           dataDir,
		StoreKind:         envOr("SENTINEL_STORE", "file"),
		LogLevel:          envOr("SENTINEL_LOG_LEVEL", "info"),
		CORSOrigins:       envList("SENTINEL_CORS_ORIGINS"),
		Metrics:           envBool("SENTINEL_METRICS_ENABLED", true),
		Neo4jURI:          envOr("SENTINEL_NEO4J_URI", "bolt://localhost:7687"),
		Neo4jUser:         envOr("SENTINEL_NEO4J_USER", "neo4j"),
		Neo4jPassword:     os.Getenv("SENTINEL_NEO4J_PASSWORD"),
		JWTKeyPath:        envOr("SENTINEL_JWT_KEY_PATH", filepath.Join(dataDir, "jwt.key")),
		JWTTTL:            envDuration("SENTINEL_JWT_TTL", 12*time.Hour),
		Issuer:            envOr("SENTINEL_JWT_ISSUER", "sentinel"),
		MasterKeyPath:     envOr("SENTINEL_MASTER_KEY_PATH", filepath.Join(dataDir, "master.key")),
		SchedulerEnabled:  envBool("SENTINEL_SCHEDULER_ENABLED", true),
		SchedulerInterval: envDuration("SENTINEL_SCHEDULER_INTERVAL", 5*time.Minute),
		DiscoveryTimeout:  envDuration("SENTINEL_DISCOVERY_TIMEOUT", 5*time.Minute),
		BootstrapTenant:   envOr("SENTINEL_BOOTSTRAP_TENANT", "Default"),
		BootstrapSlug:     envOr("SENTINEL_BOOTSTRAP_SLUG", "default"),
		BootstrapEmail:    os.Getenv("SENTINEL_BOOTSTRAP_EMAIL"),
		BootstrapName:     envOr("SENTINEL_BOOTSTRAP_NAME", "Owner"),
		BootstrapPassword: os.Getenv("SENTINEL_BOOTSTRAP_PASSWORD"),
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	switch cfg.StoreKind {
	case "memory", "file", "neo4j":
	default:
		return nil, fmt.Errorf("SENTINEL_STORE must be memory, file or neo4j, got %q", cfg.StoreKind)
	}
	if cfg.StoreKind == "neo4j" && cfg.Neo4jPassword == "" {
		return nil, fmt.Errorf("SENTINEL_NEO4J_PASSWORD is required when SENTINEL_STORE=neo4j")
	}
	switch strings.ToLower(cfg.LogLevel) {
	case "debug", "info", "warn", "warning", "error":
	default:
		return nil, fmt.Errorf("SENTINEL_LOG_LEVEL must be debug, info, warn or error, got %q", cfg.LogLevel)
	}
	if cfg.JWTTTL <= 0 {
		return nil, fmt.Errorf("SENTINEL_JWT_TTL must be positive")
	}
	if cfg.SchedulerInterval <= 0 {
		return nil, fmt.Errorf("SENTINEL_SCHEDULER_INTERVAL must be positive")
	}
	if cfg.DiscoveryTimeout <= 0 {
		cfg.DiscoveryTimeout = 5 * time.Minute
	}
	return cfg, nil
}

// StorePath returns the on-disk path used by the file-backed store.
func (c *Config) StorePath() string {
	return filepath.Join(c.DataDir, "sentinel.json")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envList(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}
