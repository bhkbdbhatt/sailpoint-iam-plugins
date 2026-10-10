package api

import (
	"context"

	"github.com/sentinel-iam/sentinel/internal/model"
)

type principal struct {
	UserID   string
	TenantID string
	Role     model.Role
	Email    string
	Method   string
}

type ctxKey int

const principalCtxKey ctxKey = iota

func withPrincipal(ctx context.Context, p principal) context.Context {
	return context.WithValue(ctx, principalCtxKey, p)
}

func principalFrom(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalCtxKey).(principal)
	return p, ok
}
