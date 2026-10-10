package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sentinel-iam/sentinel/internal/config"
	"github.com/sentinel-iam/sentinel/internal/connector"
	"github.com/sentinel-iam/sentinel/internal/secrets"
	"github.com/sentinel-iam/sentinel/internal/store"
)

func newConnectorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connector",
		Short: "Inspect and run discovery connectors",
	}
	cmd.AddCommand(newConnectorListCmd(), newConnectorRunCmd())
	return cmd
}

func newConnectorListCmd() *cobra.Command {
	var tenant string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List connector configurations for a tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			configs, total, err := st.Connectors().ListConfigs(cmd.Context(), tenant, store.ConnectorFilter{})
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "%d connector(s)\n", total)
			for _, c := range configs {
				_, _ = fmt.Fprintf(out, "  %s  %-12s  %-24s  enabled=%t  status=%s\n", c.ID, c.Key, c.Name, c.Enabled, c.LastStatus)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tenant, "tenant", "", "tenant id")
	_ = cmd.MarkFlagRequired("tenant")
	return cmd
}

func newConnectorRunCmd() *cobra.Command {
	var tenant, id string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a connector configuration once",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			box, err := secrets.LoadOrCreate(cfg.MasterKeyPath)
			if err != nil {
				return err
			}
			log := newLogger(cfg.LogLevel)
			runner := connector.NewRunner(st, connector.Default(), box, cfg.DiscoveryTimeout, log)
			run, err := runner.Run(cmd.Context(), tenant, id, "cli")
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "run %s: %s\n", run.ID, run.Status)
			_, _ = fmt.Fprintf(out, "  identities=%d credentials=%d grants=%d resources=%d\n",
				run.IdentitiesFound, run.CredentialsFound, run.GrantsFound, run.ResourcesFound)
			if run.Error != "" {
				_, _ = fmt.Fprintf(out, "  error: %s\n", run.Error)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tenant, "tenant", "", "tenant id")
	cmd.Flags().StringVar(&id, "id", "", "connector config id")
	_ = cmd.MarkFlagRequired("tenant")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}
