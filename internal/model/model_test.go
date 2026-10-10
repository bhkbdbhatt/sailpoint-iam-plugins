package model

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("supersecret123"); err != nil {
		t.Fatalf("strong password rejected: %v", err)
	}
	if err := ValidatePassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err := ValidatePassword("password123"); err == nil {
		t.Fatal("weak password accepted")
	}
	if err := ValidatePassword("PASSWORD123"); err == nil {
		t.Fatal("weak password (case-insensitive) accepted")
	}
}

func TestIdentityValidate(t *testing.T) {
	ok := Identity{TenantID: "t", Type: IdentityHuman, Name: "A", SourceSystem: "s"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
	bad := Identity{TenantID: "t", Type: "bogus", Name: "A", SourceSystem: "s"}
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid type accepted")
	}
	if err := (Identity{TenantID: "t", Type: IdentityHuman, Name: "", SourceSystem: "s"}).Validate(); err == nil {
		t.Fatal("empty name accepted")
	}
	if err := (Identity{TenantID: "t", Type: IdentityHuman, Name: "A", SourceSystem: ""}).Validate(); err == nil {
		t.Fatal("empty source accepted")
	}
	if err := (Identity{TenantID: "", Type: IdentityHuman, Name: "A", SourceSystem: "s"}).Validate(); err == nil {
		t.Fatal("empty tenant accepted")
	}
	if err := (Identity{TenantID: "t", Type: IdentityHuman, Name: "A", SourceSystem: "s", RiskScore: 150}).Validate(); err == nil {
		t.Fatal("risk out of range accepted")
	}
	var ve ValidationErrors
	if !errors.As(bad.Validate(), &ve) {
		t.Fatalf("expected ValidationErrors, got %v", bad.Validate())
	}
	if len(ve) != 1 || ve[0].Field != "type" {
		t.Fatalf("unexpected error shape: %v", ve)
	}
	if !strings.Contains(bad.Validate().Error(), "type") {
		t.Fatalf("error string: %s", bad.Validate().Error())
	}
}

func TestCredentialResourceGrantValidate(t *testing.T) {
	cred := Credential{TenantID: "t", IdentityID: "i", Type: CredentialOAuthToken, SourceSystem: "s"}
	if err := cred.Validate(); err != nil {
		t.Fatalf("cred rejected: %v", err)
	}
	if err := (Credential{TenantID: "t", IdentityID: "", Type: CredentialOAuthToken, SourceSystem: "s"}).Validate(); err == nil {
		t.Fatal("cred without identity accepted")
	}
	if err := (Credential{TenantID: "t", IdentityID: "i", Type: "nope", SourceSystem: "s"}).Validate(); err == nil {
		t.Fatal("bad cred type accepted")
	}

	res := Resource{TenantID: "t", Name: "r", SourceSystem: "s"}
	if err := res.Validate(); err != nil {
		t.Fatalf("resource rejected: %v", err)
	}
	if err := (Resource{TenantID: "t", Name: "", SourceSystem: "s"}).Validate(); err == nil {
		t.Fatal("empty resource name accepted")
	}

	g := AccessGrant{TenantID: "t", IdentityID: "i", ResourceID: "r", Entitlement: "Read"}
	if err := g.Validate(); err != nil {
		t.Fatalf("grant rejected: %v", err)
	}
	if err := (AccessGrant{TenantID: "t", IdentityID: "i", ResourceID: "r"}).Validate(); err == nil {
		t.Fatal("grant without entitlement accepted")
	}
}

func TestTenantAndUserValidate(t *testing.T) {
	if err := (Tenant{Name: "Acme", Slug: "acme"}).Validate(); err != nil {
		t.Fatalf("tenant rejected: %v", err)
	}
	if err := (Tenant{Name: "", Slug: "acme"}).Validate(); err == nil {
		t.Fatal("empty tenant name accepted")
	}
	for _, slug := range []string{"A", "a", "-abc", "abc-", "a", "ab", strings.Repeat("a", 65)} {
		if err := (Tenant{Name: "x", Slug: slug}).Validate(); err == nil {
			t.Fatalf("bad slug %q accepted", slug)
		}
	}

	u := User{TenantID: "t", Email: "a@b.com", Name: "A", Role: RoleOwner}
	if err := u.Validate(); err != nil {
		t.Fatalf("user rejected: %v", err)
	}
	if err := (User{TenantID: "t", Email: "not-an-email", Name: "A", Role: RoleOwner}).Validate(); err == nil {
		t.Fatal("bad email accepted")
	}
	if err := (User{TenantID: "t", Email: "a@b.com", Name: "A", Role: "boss"}).Validate(); err == nil {
		t.Fatal("bad role accepted")
	}
	if !RoleAdmin.Valid() || !RoleViewer.Valid() || !RoleAnalyst.Valid() || !RoleOwner.Valid() {
		t.Fatal("valid roles rejected")
	}
	if Role("root").Valid() {
		t.Fatal("invalid role accepted")
	}
}

func TestPolicyAlertValidate(t *testing.T) {
	p := Policy{TenantID: "t", Name: "p", Rules: "r", Engine: "rego", IntentLevel: IntentOrg}
	if err := p.Validate(); err != nil {
		t.Fatalf("policy rejected: %v", err)
	}
	if err := (Policy{TenantID: "t", Name: "p", Rules: "r", Engine: "rego", IntentLevel: "boss"}).Validate(); err == nil {
		t.Fatal("bad intent level accepted")
	}
	if err := (Policy{TenantID: "t", Name: "p", Rules: "r", Engine: ""}).Validate(); err == nil {
		t.Fatal("empty engine accepted")
	}
	if !PolicySimulation.Valid() || !PolicyActive.Valid() || !PolicyDraft.Valid() || !PolicyDisabled.Valid() {
		t.Fatal("policy statuses invalid")
	}

	a := Alert{TenantID: "t", Type: "x", Severity: SeverityCritical, Description: "d"}
	if err := a.Validate(); err != nil {
		t.Fatalf("alert rejected: %v", err)
	}
	if err := (Alert{TenantID: "t", Type: "", Severity: SeverityLow, Description: "d"}).Validate(); err == nil {
		t.Fatal("empty alert type accepted")
	}
	if err := (Alert{TenantID: "t", Type: "x", Severity: "loud", Description: "d"}).Validate(); err == nil {
		t.Fatal("bad severity accepted")
	}
	if err := (Alert{TenantID: "t", Type: "x", Severity: SeverityInfo, Description: ""}).Validate(); err == nil {
		t.Fatal("empty description accepted")
	}
	for _, s := range []AlertSeverity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if !s.Valid() {
			t.Fatalf("severity %s invalid", s)
		}
	}
	for _, s := range []AlertStatus{AlertOpen, AlertAcknowledged, AlertResolved} {
		if !s.Valid() {
			t.Fatalf("status %s invalid", s)
		}
	}
}

func TestConnectorConfigValidate(t *testing.T) {
	good := ConnectorConfig{TenantID: "t", Key: ConnectorAWSIAM, Name: "aws"}
	if err := good.Validate(); err != nil {
		t.Fatalf("config rejected: %v", err)
	}
	if err := (ConnectorConfig{TenantID: "t", Key: "", Name: "aws"}).Validate(); err == nil {
		t.Fatal("empty key accepted")
	}
	if err := (ConnectorConfig{TenantID: "t", Key: ConnectorAWSIAM, Name: ""}).Validate(); err == nil {
		t.Fatal("empty name accepted")
	}
	if err := (ConnectorConfig{TenantID: "t", Key: ConnectorAWSIAM, Name: "n", IntervalMinutes: 20000}).Validate(); err == nil {
		t.Fatal("interval out of range accepted")
	}
	if err := (ConnectorConfig{TenantID: "", Key: ConnectorAWSIAM, Name: "n"}).Validate(); err == nil {
		t.Fatal("empty tenant accepted")
	}
}

func TestModelHelpers(t *testing.T) {
	if !IdentityWorkload.Valid() || !IdentityTeam.Valid() || IdentityType("robot").Valid() {
		t.Fatal("identity type validity wrong")
	}
	if len(AllIdentityTypes) != 10 {
		t.Fatal("identity types list changed")
	}
	if ty, ok := ParseIdentityType("ai_agent"); !ok || ty != IdentityAIAgent {
		t.Fatal("parse identity type failed")
	}
	if _, ok := ParseIdentityType("nope"); ok {
		t.Fatal("parse bogus type succeeded")
	}
	for _, c := range []CredentialType{CredentialPassword, CredentialAPIKey, CredentialAccessKey, CredentialOAuthToken, CredentialCertificate, CredentialServiceAccountKey, CredentialSSHKey, CredentialFederated} {
		if !c.Valid() {
			t.Fatalf("credential type %s invalid", c)
		}
	}
	for _, lvl := range []AutonomyLevel{AutonomyCopilot, AutonomySupervised, AutonomySemiAutonomous, AutonomyAutonomous, AutonomyDelegated} {
		if !lvl.Valid() {
			t.Fatalf("autonomy %d invalid", lvl)
		}
	}
	if (AutonomyLevel(0)).Valid() || (AutonomyLevel(9)).Valid() {
		t.Fatal("autonomy bounds")
	}
	for _, i := range []IntentLevel{IntentOrg, IntentRole, IntentDeveloper, IntentRuntime} {
		if !i.Valid() {
			t.Fatalf("intent %s invalid", i)
		}
	}
	if BucketForRisk(0) != RiskLow || BucketForRisk(24) != RiskLow || BucketForRisk(25) != RiskMedium || BucketForRisk(49) != RiskMedium || BucketForRisk(50) != RiskHigh || BucketForRisk(74) != RiskHigh || BucketForRisk(75) != RiskCritical || BucketForRisk(100) != RiskCritical {
		t.Fatal("risk bucketing wrong")
	}
	now := time.Now()
	if (Identity{SourceSystem: "a", ExternalID: "b"}).Ref() != (SystemRef{SourceSystem: "a", ExternalID: "b"}) {
		t.Fatal("ref mismatch")
	}
	_ = now
}

func TestAgentIdentityValidate(t *testing.T) {
	a := AgentIdentity{TenantID: "t", IdentityID: "i", AutonomyLevel: AutonomySupervised, OwnerID: "o"}
	if err := a.Validate(); err != nil {
		t.Fatalf("agent rejected: %v", err)
	}
	if err := (AgentIdentity{TenantID: "t", IdentityID: "i", AutonomyLevel: 7, OwnerID: "o"}).Validate(); err == nil {
		t.Fatal("bad autonomy accepted")
	}
	if err := (AgentIdentity{TenantID: "t", IdentityID: "i", AutonomyLevel: AutonomyCopilot, OwnerID: ""}).Validate(); err == nil {
		t.Fatal("empty owner accepted")
	}
	if err := (AgentIdentity{TenantID: "t", IdentityID: "i", AutonomyLevel: AutonomyCopilot, OwnerID: "o", MaxDelegationDepth: -1}).Validate(); err == nil {
		t.Fatal("negative depth accepted")
	}
}
