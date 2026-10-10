package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sentinel-iam/sentinel/internal/bootstrap"
	"github.com/sentinel-iam/sentinel/internal/config"
)

func newBootstrapCmd() *cobra.Command {
	var (
		tenant   string
		slug     string
		email    string
		name     string
		password string
	)
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Create the initial tenant and owner user",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if email == "" {
				email = cfg.BootstrapEmail
			}
			if password == "" {
				password = cfg.BootstrapPassword
			}
			if tenant == "" {
				tenant = cfg.BootstrapTenant
			}
			if slug == "" {
				slug = cfg.BootstrapSlug
			}
			if name == "" {
				name = cfg.BootstrapName
			}

			st, err := openStore(cfg)
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()

			res, err := bootstrap.EnsureOwner(cmd.Context(), st, tenant, slug, email, name, password)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "tenant: %s (slug %s, created %t)\n", res.Tenant.ID, res.Tenant.Slug, res.TenantCreated)
			_, _ = fmt.Fprintf(out, "owner:  %s (created %t)\n", res.User.Email, res.UserCreated)
			if cfg.StoreKind == "memory" {
				_, _ = fmt.Fprintln(out, "warning: memory store is per-process; use SENTINEL_STORE=file for persistence")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tenant, "tenant", "", "tenant name")
	cmd.Flags().StringVar(&slug, "slug", "", "tenant slug")
	cmd.Flags().StringVar(&email, "email", "", "owner email")
	cmd.Flags().StringVar(&name, "name", "", "owner display name")
	cmd.Flags().StringVar(&password, "password", "", "owner password")
	return cmd
}
