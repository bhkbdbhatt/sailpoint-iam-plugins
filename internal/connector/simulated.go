package connector

import (
	"context"
	"time"

	"github.com/sentinel-iam/sentinel/internal/model"
)

// Simulated is a deterministic connector that produces representative IAM data
// without contacting any external system. It is used for demos and testing.
type Simulated struct{}

func (Simulated) Key() model.ConnectorKey { return model.ConnectorSimulated }

func (Simulated) Discover(ctx context.Context, tenantID string, cfg model.ConnectorConfig) (*Result, error) {
	now := time.Now().UTC()
	src := string(model.ConnectorSimulated)

	admin := model.Identity{
		TenantID:     tenantID,
		Type:         model.IdentityHuman,
		Name:         "Sim Admin",
		DisplayName:  "Simulated Administrator",
		Environment:  "prod",
		SourceSystem: src,
		ExternalID:   "sim:user:admin",
		RiskScore:    35,
		Status:       model.StatusActive,
		Attributes:   map[string]string{"email": "sim-admin@example.com"},
	}
	svc := model.Identity{
		TenantID:      tenantID,
		Type:          model.IdentityServiceAccount,
		Name:          "sim-svc-billing",
		Environment:   "prod",
		CloudProvider: "aws",
		SourceSystem:  src,
		ExternalID:    "sim:sa:billing",
		RiskScore:     58,
		Status:        model.StatusActive,
	}
	agent := model.Identity{
		TenantID:     tenantID,
		Type:         model.IdentityAIAgent,
		Name:         "sim-agent-ops",
		Environment:  "prod",
		SourceSystem: src,
		ExternalID:   "sim:agent:ops",
		RiskScore:    72,
		Status:       model.StatusActive,
		OwnerID:      "sim:user:admin",
	}
	orphan := model.Identity{
		TenantID:     tenantID,
		Type:         model.IdentityAPIKey,
		Name:         "sim-legacy-key",
		Environment:  "staging",
		SourceSystem: src,
		ExternalID:   "sim:key:legacy",
		RiskScore:    88,
		Status:       model.StatusOrphaned,
	}

	role := model.Resource{
		TenantID:     tenantID,
		Name:         "billing-writer",
		Type:         model.ResourceCloudRole,
		Environment:  "prod",
		SourceSystem: src,
		ExternalID:   "sim:role:billing-writer",
	}
	bucket := model.Resource{
		TenantID:     tenantID,
		Name:         "invoices-prod",
		Type:         model.ResourceBucket,
		Environment:  "prod",
		SourceSystem: src,
		ExternalID:   "sim:bucket:invoices",
	}
	db := model.Resource{
		TenantID:     tenantID,
		Name:         "customers",
		Type:         model.ResourceDatabase,
		Environment:  "prod",
		SourceSystem: src,
		ExternalID:   "sim:db:customers",
	}

	issued := now.Add(-120 * 24 * time.Hour)
	expires := now.Add(21 * 24 * time.Hour)

	cred := model.Credential{
		TenantID:         tenantID,
		IdentityID:       "sim:sa:billing",
		Type:             model.CredentialAccessKey,
		Name:             "billing access key",
		Scope:            "billing:write",
		IssuedAt:         &issued,
		ExpiresAt:        &expires,
		RotationSchedule: "90d",
		SourceSystem:     src,
		ExternalID:       "sim:cred:sa-billing",
		Status:           model.StatusActive,
	}
	agentCred := model.Credential{
		TenantID:     tenantID,
		IdentityID:   "sim:agent:ops",
		Type:         model.CredentialOAuthToken,
		Name:         "agent oauth token",
		Scope:        "ops:read ops:write",
		SourceSystem: src,
		ExternalID:   "sim:cred:agent-ops",
		IsEphemeral:  true,
		Status:       model.StatusActive,
	}

	granted := now.Add(-200 * 24 * time.Hour)
	grant1 := model.AccessGrant{
		TenantID:      tenantID,
		IdentityID:    "sim:user:admin",
		ResourceID:    "sim:role:billing-writer",
		Entitlement:   "assume",
		GrantedAt:     &granted,
		UsageCount30D: 12,
		SourceSystem:  src,
		ExternalID:    "sim:grant:admin-role",
	}
	grant2 := model.AccessGrant{
		TenantID:      tenantID,
		IdentityID:    "sim:sa:billing",
		ResourceID:    "sim:bucket:invoices",
		Entitlement:   "read",
		GrantedAt:     &granted,
		UsageCount30D: 430,
		SourceSystem:  src,
		ExternalID:    "sim:grant:svc-bucket",
	}
	grant3 := model.AccessGrant{
		TenantID:      tenantID,
		IdentityID:    "sim:agent:ops",
		ResourceID:    "sim:db:customers",
		Entitlement:   "query",
		GrantedAt:     &granted,
		UsageCount30D: 0,
		SourceSystem:  src,
		ExternalID:    "sim:grant:agent-db",
	}

	return &Result{
		Identities:  []model.Identity{admin, svc, agent, orphan},
		Credentials: []model.Credential{cred, agentCred},
		Grants:      []model.AccessGrant{grant1, grant2, grant3},
		Resources:   []model.Resource{role, bucket, db},
	}, nil
}
