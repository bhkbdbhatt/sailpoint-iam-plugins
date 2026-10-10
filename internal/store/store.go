package store

import (
	"context"

	"github.com/sentinel-iam/sentinel/internal/model"
)

type Store interface {
	Identities() IdentityStore
	Credentials() CredentialStore
	AccessGrants() AccessGrantStore
	Resources() ResourceStore
	Tenants() TenantStore
	Users() UserStore
	APIKeys() APIKeyStore
	Connectors() ConnectorStore
	Policies() PolicyStore
	Alerts() AlertStore
	Stats() StatsStore
	Ping(ctx context.Context) error
	Close() error
}

type IdentityFilter struct {
	Types        []model.IdentityType
	Query        string
	OwnerID      string
	Status       model.Status
	SourceSystem string
	MinRisk      int
	MaxRisk      int
	Limit        int
	Offset       int
}

type IdentityStore interface {
	Upsert(ctx context.Context, in model.Identity) (model.Identity, error)
	Get(ctx context.Context, tenantID, id string) (model.Identity, error)
	GetByExternal(ctx context.Context, tenantID, sourceSystem, externalID string) (model.Identity, error)
	List(ctx context.Context, tenantID string, f IdentityFilter) ([]model.Identity, int, error)
	Delete(ctx context.Context, tenantID, id string) error
}

type CredentialFilter struct {
	IdentityID         string
	Types              []model.CredentialType
	SourceSystem       string
	ExpiringWithinDays int
	Limit              int
	Offset             int
}

type CredentialStore interface {
	Upsert(ctx context.Context, in model.Credential) (model.Credential, error)
	Get(ctx context.Context, tenantID, id string) (model.Credential, error)
	List(ctx context.Context, tenantID string, f CredentialFilter) ([]model.Credential, int, error)
	Delete(ctx context.Context, tenantID, id string) error
}

type AccessGrantFilter struct {
	IdentityID   string
	ResourceID   string
	SourceSystem string
	Limit        int
	Offset       int
}

type AccessGrantStore interface {
	Upsert(ctx context.Context, in model.AccessGrant) (model.AccessGrant, error)
	Get(ctx context.Context, tenantID, id string) (model.AccessGrant, error)
	List(ctx context.Context, tenantID string, f AccessGrantFilter) ([]model.AccessGrant, int, error)
	Delete(ctx context.Context, tenantID, id string) error
}

type ResourceFilter struct {
	Query        string
	Type         model.ResourceType
	SourceSystem string
	Limit        int
	Offset       int
}

type ResourceStore interface {
	Upsert(ctx context.Context, in model.Resource) (model.Resource, error)
	Get(ctx context.Context, tenantID, id string) (model.Resource, error)
	GetByExternal(ctx context.Context, tenantID, sourceSystem, externalID string) (model.Resource, error)
	List(ctx context.Context, tenantID string, f ResourceFilter) ([]model.Resource, int, error)
	Delete(ctx context.Context, tenantID, id string) error
}

type TenantStore interface {
	Create(ctx context.Context, in model.Tenant) (model.Tenant, error)
	Get(ctx context.Context, id string) (model.Tenant, error)
	GetBySlug(ctx context.Context, slug string) (model.Tenant, error)
	List(ctx context.Context) ([]model.Tenant, error)
	Count(ctx context.Context) (int, error)
}

type UserFilter struct {
	Role   model.Role
	Status model.Status
	Query  string
	Limit  int
	Offset int
}

type UserStore interface {
	Create(ctx context.Context, in model.User) (model.User, error)
	Get(ctx context.Context, tenantID, id string) (model.User, error)
	GetByEmail(ctx context.Context, email string) (model.User, error)
	List(ctx context.Context, tenantID string, f UserFilter) ([]model.User, int, error)
	Update(ctx context.Context, in model.User) (model.User, error)
	Delete(ctx context.Context, tenantID, id string) error
}

type APIKeyFilter struct {
	UserID  string
	Revoked *bool
	Limit   int
	Offset  int
}

type APIKeyStore interface {
	Create(ctx context.Context, in model.APIKey) (model.APIKey, error)
	Get(ctx context.Context, tenantID, id string) (model.APIKey, error)
	GetByHash(ctx context.Context, hash string) (model.APIKey, error)
	List(ctx context.Context, tenantID string, f APIKeyFilter) ([]model.APIKey, int, error)
	Update(ctx context.Context, in model.APIKey) (model.APIKey, error)
	Delete(ctx context.Context, tenantID, id string) error
}

type ConnectorFilter struct {
	Key     model.ConnectorKey
	Enabled *bool
	Limit   int
	Offset  int
}

type ConnectorRunFilter struct {
	ConfigID string
	Status   model.ConnectorStatus
	Limit    int
	Offset   int
}

type ConnectorStore interface {
	CreateConfig(ctx context.Context, in model.ConnectorConfig) (model.ConnectorConfig, error)
	GetConfig(ctx context.Context, tenantID, id string) (model.ConnectorConfig, error)
	ListConfigs(ctx context.Context, tenantID string, f ConnectorFilter) ([]model.ConnectorConfig, int, error)
	UpdateConfig(ctx context.Context, in model.ConnectorConfig) (model.ConnectorConfig, error)
	DeleteConfig(ctx context.Context, tenantID, id string) error

	CreateRun(ctx context.Context, in model.ConnectorRun) (model.ConnectorRun, error)
	UpdateRun(ctx context.Context, in model.ConnectorRun) (model.ConnectorRun, error)
	GetRun(ctx context.Context, tenantID, id string) (model.ConnectorRun, error)
	ListRuns(ctx context.Context, tenantID string, f ConnectorRunFilter) ([]model.ConnectorRun, int, error)
}

type StatsStore interface {
	Overview(ctx context.Context, tenantID string) (model.Overview, error)
}

type PolicyFilter struct {
	IntentLevel model.IntentLevel
	Status      model.PolicyStatus
	Engine      string
	Query       string
	Limit       int
	Offset      int
}

type PolicyStore interface {
	Create(ctx context.Context, in model.Policy) (model.Policy, error)
	Get(ctx context.Context, tenantID, id string) (model.Policy, error)
	List(ctx context.Context, tenantID string, f PolicyFilter) ([]model.Policy, int, error)
	Update(ctx context.Context, in model.Policy) (model.Policy, error)
	Delete(ctx context.Context, tenantID, id string) error
}

type AlertFilter struct {
	IdentityID string
	Type       string
	Severity   model.AlertSeverity
	Status     model.AlertStatus
	Limit      int
	Offset     int
}

type AlertStore interface {
	Create(ctx context.Context, in model.Alert) (model.Alert, error)
	Get(ctx context.Context, tenantID, id string) (model.Alert, error)
	List(ctx context.Context, tenantID string, f AlertFilter) ([]model.Alert, int, error)
	Update(ctx context.Context, in model.Alert) (model.Alert, error)
	Delete(ctx context.Context, tenantID, id string) error
}
