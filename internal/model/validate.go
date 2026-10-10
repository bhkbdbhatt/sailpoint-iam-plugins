package model

import (
	"net/mail"
	"regexp"
	"strings"
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

func (i Identity) Validate() error {
	var errs ValidationErrors
	if !i.Type.Valid() {
		errs = append(errs, field("type", "unknown identity type"))
	}
	if strings.TrimSpace(i.Name) == "" {
		errs = append(errs, field("name", "required"))
	}
	if i.TenantID == "" {
		errs = append(errs, field("tenant_id", "required"))
	}
	if i.RiskScore < 0 || i.RiskScore > 100 {
		errs = append(errs, field("risk_score", "must be between 0 and 100"))
	}
	if i.SourceSystem == "" {
		errs = append(errs, field("source_system", "required"))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (c Credential) Validate() error {
	var errs ValidationErrors
	if !c.Type.Valid() {
		errs = append(errs, field("type", "unknown credential type"))
	}
	if c.TenantID == "" {
		errs = append(errs, field("tenant_id", "required"))
	}
	if c.IdentityID == "" {
		errs = append(errs, field("identity_id", "required"))
	}
	if c.SourceSystem == "" {
		errs = append(errs, field("source_system", "required"))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (r Resource) Validate() error {
	var errs ValidationErrors
	if strings.TrimSpace(r.Name) == "" {
		errs = append(errs, field("name", "required"))
	}
	if r.TenantID == "" {
		errs = append(errs, field("tenant_id", "required"))
	}
	if r.SourceSystem == "" {
		errs = append(errs, field("source_system", "required"))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (g AccessGrant) Validate() error {
	var errs ValidationErrors
	if g.TenantID == "" {
		errs = append(errs, field("tenant_id", "required"))
	}
	if g.IdentityID == "" {
		errs = append(errs, field("identity_id", "required"))
	}
	if g.ResourceID == "" {
		errs = append(errs, field("resource_id", "required"))
	}
	if strings.TrimSpace(g.Entitlement) == "" {
		errs = append(errs, field("entitlement", "required"))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (t Tenant) Validate() error {
	var errs ValidationErrors
	if strings.TrimSpace(t.Name) == "" {
		errs = append(errs, field("name", "required"))
	}
	if !slugRe.MatchString(t.Slug) {
		errs = append(errs, field("slug", "must be 3-64 lowercase alphanumeric or hyphens"))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (u User) Validate() error {
	var errs ValidationErrors
	if _, err := mail.ParseAddress(u.Email); err != nil {
		errs = append(errs, field("email", "invalid email address"))
	}
	if strings.TrimSpace(u.Name) == "" {
		errs = append(errs, field("name", "required"))
	}
	if !u.Role.Valid() {
		errs = append(errs, field("role", "must be owner, admin, analyst or viewer"))
	}
	if u.TenantID == "" {
		errs = append(errs, field("tenant_id", "required"))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (r Role) Valid() bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleAnalyst, RoleViewer:
		return true
	}
	return false
}

var weakPasswords = map[string]bool{
	"password":     true,
	"password123":  true,
	"password1234": true,
	"changeme":     true,
	"changeme123":  true,
	"default":      true,
	"default123":   true,
	"sentinel":     true,
	"sentinel123":  true,
	"admin":        true,
	"admin123":     true,
	"12345678":     true,
	"123456789":    true,
	"qwerty123":    true,
	"letmein":      true,
	"welcome123":   true,
	"iloveyou":     true,
	"abc123456":    true,
	"monkey123":    true,
	"superman":     true,
	"dragon":       true,
	"football":     true,
	"secret":       true,
	"secret123":    true,
	"trustno1":     true,
}

func ValidatePassword(pw string) error {
	if len(pw) < 12 {
		return field("password", "must be at least 12 characters")
	}
	if weakPasswords[strings.ToLower(pw)] {
		return field("password", "password is too common; choose a stronger one")
	}
	return nil
}

func (c ConnectorConfig) Validate() error {
	var errs ValidationErrors
	if c.Key == "" {
		errs = append(errs, field("key", "required"))
	}
	if strings.TrimSpace(c.Name) == "" {
		errs = append(errs, field("name", "required"))
	}
	if c.TenantID == "" {
		errs = append(errs, field("tenant_id", "required"))
	}
	if c.IntervalMinutes < 0 || c.IntervalMinutes > 10080 {
		errs = append(errs, field("interval_minutes", "must be between 0 and 10080"))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (p Policy) Validate() error {
	var errs ValidationErrors
	if strings.TrimSpace(p.Name) == "" {
		errs = append(errs, field("name", "required"))
	}
	if p.TenantID == "" {
		errs = append(errs, field("tenant_id", "required"))
	}
	if !p.IntentLevel.Valid() {
		errs = append(errs, field("intent_level", "must be org, role, developer or runtime"))
	}
	if p.Engine == "" {
		errs = append(errs, field("engine", "required"))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (a Alert) Validate() error {
	var errs ValidationErrors
	if a.TenantID == "" {
		errs = append(errs, field("tenant_id", "required"))
	}
	if strings.TrimSpace(a.Type) == "" {
		errs = append(errs, field("type", "required"))
	}
	if !a.Severity.Valid() {
		errs = append(errs, field("severity", "must be info, low, medium, high or critical"))
	}
	if strings.TrimSpace(a.Description) == "" {
		errs = append(errs, field("description", "required"))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (s AlertSeverity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

func (s AlertStatus) Valid() bool {
	switch s {
	case AlertOpen, AlertAcknowledged, AlertResolved:
		return true
	}
	return false
}

func (s PolicyStatus) Valid() bool {
	switch s {
	case PolicyDraft, PolicyActive, PolicyDisabled, PolicySimulation:
		return true
	}
	return false
}

func (a AgentIdentity) Validate() error {
	var errs ValidationErrors
	if a.TenantID == "" {
		errs = append(errs, field("tenant_id", "required"))
	}
	if a.IdentityID == "" {
		errs = append(errs, field("identity_id", "required"))
	}
	if !a.AutonomyLevel.Valid() {
		errs = append(errs, field("autonomy_level", "must be 1-5"))
	}
	if a.OwnerID == "" {
		errs = append(errs, field("owner_id", "required"))
	}
	if a.MaxDelegationDepth < 0 {
		errs = append(errs, field("max_delegation_depth", "must be >= 0"))
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}
