package model

import "time"

type IdentityType string

const (
	IdentityHuman          IdentityType = "human"
	IdentityWorkload       IdentityType = "workload"
	IdentityServiceAccount IdentityType = "service_account"
	IdentityAPIKey         IdentityType = "api_key"
	IdentityOAuthToken     IdentityType = "oauth_token"
	IdentityAIAgent        IdentityType = "ai_agent"
	IdentityMCPServer      IdentityType = "mcp_server"
	IdentityDevice         IdentityType = "device"
	IdentityCertificate    IdentityType = "certificate"
	IdentityTeam           IdentityType = "team"
)

var AllIdentityTypes = []IdentityType{
	IdentityHuman, IdentityWorkload, IdentityServiceAccount, IdentityAPIKey,
	IdentityOAuthToken, IdentityAIAgent, IdentityMCPServer, IdentityDevice,
	IdentityCertificate, IdentityTeam,
}

func ParseIdentityType(s string) (IdentityType, bool) {
	for _, t := range AllIdentityTypes {
		if string(t) == s {
			return t, true
		}
	}
	return "", false
}

func (t IdentityType) Valid() bool {
	_, ok := ParseIdentityType(string(t))
	return ok
}

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
	StatusOrphaned Status = "orphaned"
	StatusRevoked  Status = "revoked"
	StatusExpired  Status = "expired"
	StatusInvited  Status = "invited"
)

type SystemRef struct {
	SourceSystem string `json:"source_system"`
	ExternalID   string `json:"external_id"`
}

type Identity struct {
	ID            string            `json:"id"`
	TenantID      string            `json:"tenant_id"`
	Type          IdentityType      `json:"type"`
	Name          string            `json:"name"`
	DisplayName   string            `json:"display_name,omitempty"`
	OwnerID       string            `json:"owner_id,omitempty"`
	Environment   string            `json:"environment,omitempty"`
	CloudProvider string            `json:"cloud_provider,omitempty"`
	SourceSystem  string            `json:"source_system"`
	ExternalID    string            `json:"external_id"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	LastUsedAt    *time.Time        `json:"last_used_at,omitempty"`
	RiskScore     int               `json:"risk_score"`
	Status        Status            `json:"status"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

func (i Identity) Ref() SystemRef {
	return SystemRef{SourceSystem: i.SourceSystem, ExternalID: i.ExternalID}
}

type CredentialType string

const (
	CredentialPassword          CredentialType = "password"
	CredentialAPIKey            CredentialType = "api_key"
	CredentialAccessKey         CredentialType = "access_key"
	CredentialOAuthToken        CredentialType = "oauth_token"
	CredentialCertificate       CredentialType = "certificate"
	CredentialServiceAccountKey CredentialType = "service_account_key"
	CredentialSSHKey            CredentialType = "ssh_key"
	CredentialFederated         CredentialType = "federated"
)

var AllCredentialTypes = []CredentialType{
	CredentialPassword, CredentialAPIKey, CredentialAccessKey, CredentialOAuthToken,
	CredentialCertificate, CredentialServiceAccountKey, CredentialSSHKey, CredentialFederated,
}

func (t CredentialType) Valid() bool {
	for _, c := range AllCredentialTypes {
		if c == t {
			return true
		}
	}
	return false
}

type Credential struct {
	ID               string         `json:"id"`
	TenantID         string         `json:"tenant_id"`
	IdentityID       string         `json:"identity_id"`
	Type             CredentialType `json:"type"`
	Name             string         `json:"name,omitempty"`
	Scope            string         `json:"scope,omitempty"`
	IssuedAt         *time.Time     `json:"issued_at,omitempty"`
	ExpiresAt        *time.Time     `json:"expires_at,omitempty"`
	RotationSchedule string         `json:"rotation_schedule,omitempty"`
	SourceSystem     string         `json:"source_system"`
	ExternalID       string         `json:"external_id"`
	IsEphemeral      bool           `json:"is_ephemeral"`
	Status           Status         `json:"status"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

type ResourceType string

const (
	ResourceCloudRole       ResourceType = "cloud_role"
	ResourceIAMPolicy       ResourceType = "iam_policy"
	ResourceApplication     ResourceType = "application"
	ResourceDatabase        ResourceType = "database"
	ResourceAPI             ResourceType = "api"
	ResourceBucket          ResourceType = "bucket"
	ResourceSecret          ResourceType = "secret"
	ResourceUnknownResource ResourceType = "resource"
)

type Resource struct {
	ID           string       `json:"id"`
	TenantID     string       `json:"tenant_id"`
	Name         string       `json:"name"`
	Type         ResourceType `json:"type"`
	Environment  string       `json:"environment,omitempty"`
	SourceSystem string       `json:"source_system"`
	ExternalID   string       `json:"external_id"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

type AccessGrant struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	IdentityID    string     `json:"identity_id"`
	ResourceID    string     `json:"resource_id"`
	Entitlement   string     `json:"entitlement"`
	GrantedAt     *time.Time `json:"granted_at,omitempty"`
	GrantedBy     string     `json:"granted_by,omitempty"`
	PolicyID      string     `json:"policy_id,omitempty"`
	UsageCount30D int        `json:"usage_count_30d"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	SourceSystem  string     `json:"source_system"`
	ExternalID    string     `json:"external_id"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type AutonomyLevel int

const (
	AutonomyCopilot        AutonomyLevel = 1
	AutonomySupervised     AutonomyLevel = 2
	AutonomySemiAutonomous AutonomyLevel = 3
	AutonomyAutonomous     AutonomyLevel = 4
	AutonomyDelegated      AutonomyLevel = 5
)

func (a AutonomyLevel) Valid() bool { return a >= AutonomyCopilot && a <= AutonomyDelegated }

type AgentIdentity struct {
	ID                 string            `json:"id"`
	TenantID           string            `json:"tenant_id"`
	IdentityID         string            `json:"identity_id"`
	AutonomyLevel      AutonomyLevel     `json:"autonomy_level"`
	Framework          string            `json:"framework,omitempty"`
	OwnerID            string            `json:"owner_id"`
	Purpose            string            `json:"purpose,omitempty"`
	AllowedTools       []string          `json:"allowed_tools,omitempty"`
	MaxDelegationDepth int               `json:"max_delegation_depth"`
	KillSwitchStatus   string            `json:"kill_switch_status"`
	ToolCallLogRef     string            `json:"tool_call_log_ref,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
	Attributes         map[string]string `json:"attributes,omitempty"`
}

type IntentLevel string

const (
	IntentOrg       IntentLevel = "org"
	IntentRole      IntentLevel = "role"
	IntentDeveloper IntentLevel = "developer"
	IntentRuntime   IntentLevel = "runtime"
)

func (i IntentLevel) Valid() bool {
	switch i {
	case IntentOrg, IntentRole, IntentDeveloper, IntentRuntime:
		return true
	}
	return false
}

type PolicyStatus string

const (
	PolicyDraft      PolicyStatus = "draft"
	PolicyActive     PolicyStatus = "active"
	PolicyDisabled   PolicyStatus = "disabled"
	PolicySimulation PolicyStatus = "simulation"
)

type Policy struct {
	ID            string       `json:"id"`
	TenantID      string       `json:"tenant_id"`
	Name          string       `json:"name"`
	Scope         string       `json:"scope,omitempty"`
	Rules         string       `json:"rules"`
	Engine        string       `json:"engine"`
	IntentLevel   IntentLevel  `json:"intent_level"`
	EffectiveDate *time.Time   `json:"effective_date,omitempty"`
	Status        PolicyStatus `json:"status"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

type AlertSeverity string

const (
	SeverityInfo     AlertSeverity = "info"
	SeverityLow      AlertSeverity = "low"
	SeverityMedium   AlertSeverity = "medium"
	SeverityHigh     AlertSeverity = "high"
	SeverityCritical AlertSeverity = "critical"
)

type AlertStatus string

const (
	AlertOpen         AlertStatus = "open"
	AlertAcknowledged AlertStatus = "acknowledged"
	AlertResolved     AlertStatus = "resolved"
)

type Alert struct {
	ID                string        `json:"id"`
	TenantID          string        `json:"tenant_id"`
	IdentityID        string        `json:"identity_id"`
	Type              string        `json:"type"`
	Severity          AlertSeverity `json:"severity"`
	DetectedAt        time.Time     `json:"detected_at"`
	Description       string        `json:"description"`
	RecommendedAction string        `json:"recommended_action,omitempty"`
	Status            AlertStatus   `json:"status"`
	CreatedAt         time.Time     `json:"created_at"`
	UpdatedAt         time.Time     `json:"updated_at"`
}

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Role string

const (
	RoleOwner   Role = "owner"
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

type User struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	PasswordHash string     `json:"-"`
	Role         Role       `json:"role"`
	Status       Status     `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

type APIKey struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Hash       string     `json:"-"`
	Role       Role       `json:"role"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Revoked    bool       `json:"revoked"`
}

type ConnectorKey string

const (
	ConnectorAWSIAM     ConnectorKey = "aws_iam"
	ConnectorAzureEntra ConnectorKey = "azure_entra"
	ConnectorSimulated  ConnectorKey = "simulated"
)

type ConnectorStatus string

const (
	ConnectorStatusIdle      ConnectorStatus = "idle"
	ConnectorStatusRunning   ConnectorStatus = "running"
	ConnectorStatusSucceeded ConnectorStatus = "succeeded"
	ConnectorStatusFailed    ConnectorStatus = "failed"
)

type ConnectorConfig struct {
	ID              string            `json:"id"`
	TenantID        string            `json:"tenant_id"`
	Key             ConnectorKey      `json:"key"`
	Name            string            `json:"name"`
	Enabled         bool              `json:"enabled"`
	IntervalMinutes int               `json:"interval_minutes"`
	Secrets         map[string]string `json:"-"`
	Options         map[string]string `json:"options,omitempty"`
	LastRunAt       *time.Time        `json:"last_run_at,omitempty"`
	LastStatus      ConnectorStatus   `json:"last_status,omitempty"`
	LastError       string            `json:"last_error,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type ConnectorRun struct {
	ID                string          `json:"id"`
	TenantID          string          `json:"tenant_id"`
	ConnectorConfigID string          `json:"connector_config_id"`
	ConnectorKey      ConnectorKey    `json:"connector_key"`
	Trigger           string          `json:"trigger"`
	StartedAt         time.Time       `json:"started_at"`
	FinishedAt        *time.Time      `json:"finished_at,omitempty"`
	Status            ConnectorStatus `json:"status"`
	IdentitiesFound   int             `json:"identities_found"`
	CredentialsFound  int             `json:"credentials_found"`
	GrantsFound       int             `json:"grants_found"`
	ResourcesFound    int             `json:"resources_found"`
	Error             string          `json:"error,omitempty"`
}

type RiskBucket string

const (
	RiskLow      RiskBucket = "low"
	RiskMedium   RiskBucket = "medium"
	RiskHigh     RiskBucket = "high"
	RiskCritical RiskBucket = "critical"
)

func BucketForRisk(score int) RiskBucket {
	switch {
	case score >= 75:
		return RiskCritical
	case score >= 50:
		return RiskHigh
	case score >= 25:
		return RiskMedium
	default:
		return RiskLow
	}
}

type Overview struct {
	TotalIdentities       int            `json:"total_identities"`
	IdentitiesByType      map[string]int `json:"identities_by_type"`
	IdentitiesByStatus    map[string]int `json:"identities_by_status"`
	RiskBuckets           map[string]int `json:"risk_buckets"`
	TotalCredentials      int            `json:"total_credentials"`
	CredentialsExpiring30 int            `json:"credentials_expiring_30d"`
	TotalGrants           int            `json:"total_grants"`
	TotalResources        int            `json:"total_resources"`
	UnownedIdentities     int            `json:"unowned_identities"`
	OwnerCoveragePct      float64        `json:"owner_coverage_pct"`
	LastConnectorRunAt    *time.Time     `json:"last_connector_run_at,omitempty"`
}
