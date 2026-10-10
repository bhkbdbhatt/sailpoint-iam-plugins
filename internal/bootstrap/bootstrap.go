package bootstrap

import (
	"context"
	"errors"
	"strings"

	"github.com/sentinel-iam/sentinel/internal/auth"
	"github.com/sentinel-iam/sentinel/internal/model"
	"github.com/sentinel-iam/sentinel/internal/store"
)

// Result describes what EnsureOwner created or reused.
type Result struct {
	Tenant        model.Tenant
	User          model.User
	TenantCreated bool
	UserCreated   bool
}

// EnsureOwner creates the tenant (by slug) and the owner user (by email) if they
// do not already exist. It is idempotent.
func EnsureOwner(ctx context.Context, st store.Store, tenantName, slug, email, name, password string) (Result, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return Result{}, errors.New("bootstrap email is required")
	}
	if name == "" {
		name = "Owner"
	}

	var res Result
	tenant, err := st.Tenants().GetBySlug(ctx, slug)
	if err != nil {
		if !errors.Is(err, model.ErrNotFound) {
			return Result{}, err
		}
		if err := model.ValidatePassword(password); err != nil {
			return Result{}, err
		}
		tenant, err = st.Tenants().Create(ctx, model.Tenant{
			Name:   tenantName,
			Slug:   slug,
			Status: model.StatusActive,
		})
		if err != nil {
			return Result{}, err
		}
		res.TenantCreated = true
	}
	res.Tenant = tenant

	if _, err := st.Users().GetByEmail(ctx, email); err == nil {
		res.User, _ = st.Users().GetByEmail(ctx, email)
		return res, nil
	} else if !errors.Is(err, model.ErrNotFound) {
		return Result{}, err
	}

	if err := model.ValidatePassword(password); err != nil {
		return Result{}, err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return Result{}, err
	}
	user, err := st.Users().Create(ctx, model.User{
		TenantID:     tenant.ID,
		Email:        email,
		Name:         name,
		PasswordHash: hash,
		Role:         model.RoleOwner,
		Status:       model.StatusActive,
	})
	if err != nil {
		return Result{}, err
	}
	res.User = user
	res.UserCreated = true
	return res, nil
}
