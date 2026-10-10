package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentinel-iam/sentinel/internal/api"
	"github.com/sentinel-iam/sentinel/internal/auth"
	"github.com/sentinel-iam/sentinel/internal/bootstrap"
	"github.com/sentinel-iam/sentinel/internal/config"
	"github.com/sentinel-iam/sentinel/internal/connector"
	"github.com/sentinel-iam/sentinel/internal/secrets"
)

func newServeCmd() *cobra.Command {
	var bootstrapNow bool
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP API server and connector scheduler",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			log := newLogger(cfg.LogLevel)

			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			box, err := secrets.LoadOrCreate(cfg.MasterKeyPath)
			if err != nil {
				return err
			}
			jwtm, err := auth.LoadOrCreateJWTManager(cfg.JWTKeyPath, cfg.Issuer, cfg.JWTTTL)
			if err != nil {
				return err
			}

			if bootstrapNow || (cfg.BootstrapEmail != "" && cfg.BootstrapPassword != "") {
				res, err := bootstrap.EnsureOwner(cmd.Context(), st, cfg.BootstrapTenant, cfg.BootstrapSlug, cfg.BootstrapEmail, cfg.BootstrapName, cfg.BootstrapPassword)
				if err != nil {
					return fmt.Errorf("bootstrap: %w", err)
				}
				log.Info("bootstrap complete",
					"tenant", res.Tenant.Slug,
					"tenant_created", res.TenantCreated,
					"user", res.User.Email,
					"user_created", res.UserCreated,
				)
			}

			registry := connector.Default()
			runner := connector.NewRunner(st, registry, box, cfg.DiscoveryTimeout, log)
			server := api.New(st, jwtm, box, runner, log, api.WithCORS(cfg.CORSOrigins), api.WithMetrics(cfg.Metrics))

			httpServer := &http.Server{
				Addr:              cfg.HTTPAddr,
				Handler:           server.Handler(),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      60 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if cfg.SchedulerEnabled {
				connector.NewScheduler(st, runner, cfg.SchedulerInterval, log).Start(ctx)
			}

			errCh := make(chan error, 1)
			go func() {
				log.Info("http server listening", "addr", cfg.HTTPAddr, "store", cfg.StoreKind)
				if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
			}()

			select {
			case err := <-errCh:
				return err
			case <-ctx.Done():
				log.Info("shutdown signal received")
			}

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return httpServer.Shutdown(shutdownCtx)
		},
	}
	cmd.Flags().BoolVar(&bootstrapNow, "bootstrap", false, "create the bootstrap tenant/owner if it does not exist")
	return cmd
}
