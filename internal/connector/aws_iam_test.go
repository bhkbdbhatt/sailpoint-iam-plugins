package connector

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/sentinel-iam/sentinel/internal/model"
)

// fakeIAM implements iamAPI with fixed data and supports a single page.
type fakeIAM struct {
	users         []iamtypes.User
	roles         []iamtypes.Role
	groups        []iamtypes.Group
	accessKeys    map[string][]iamtypes.AccessKeyMetadata
	mfa           map[string]int
	attachedUser  map[string][]iamtypes.AttachedPolicy
	attachedRole  map[string][]iamtypes.AttachedPolicy
	attachedGroup map[string][]iamtypes.AttachedPolicy
	inlineUser    map[string][]string
	inlineRole    map[string][]string
	inlineGroup   map[string][]string
	pageUsers     bool
	userCalls     int
}

func (f *fakeIAM) ListUsers(_ context.Context, in *iam.ListUsersInput, _ ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	f.userCalls++
	if f.pageUsers {
		if in.Marker == nil {
			return &iam.ListUsersOutput{Users: f.users[:1], IsTruncated: true, Marker: aws.String("m1")}, nil
		}
		return &iam.ListUsersOutput{Users: f.users[1:]}, nil
	}
	return &iam.ListUsersOutput{Users: f.users}, nil
}

func (f *fakeIAM) ListRoles(_ context.Context, _ *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: f.roles}, nil
}

func (f *fakeIAM) ListGroups(_ context.Context, _ *iam.ListGroupsInput, _ ...func(*iam.Options)) (*iam.ListGroupsOutput, error) {
	return &iam.ListGroupsOutput{Groups: f.groups}, nil
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: f.accessKeys[str(in.UserName)]}, nil
}

func (f *fakeIAM) ListMFADevices(_ context.Context, in *iam.ListMFADevicesInput, _ ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	devices := make([]iamtypes.MFADevice, f.mfa[str(in.UserName)])
	return &iam.ListMFADevicesOutput{MFADevices: devices}, nil
}

func (f *fakeIAM) ListAttachedUserPolicies(_ context.Context, in *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	return &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: f.attachedUser[str(in.UserName)]}, nil
}

func (f *fakeIAM) ListAttachedRolePolicies(_ context.Context, in *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: f.attachedRole[str(in.RoleName)]}, nil
}

func (f *fakeIAM) ListAttachedGroupPolicies(_ context.Context, in *iam.ListAttachedGroupPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error) {
	return &iam.ListAttachedGroupPoliciesOutput{AttachedPolicies: f.attachedGroup[str(in.GroupName)]}, nil
}

func (f *fakeIAM) ListUserPolicies(_ context.Context, in *iam.ListUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	return &iam.ListUserPoliciesOutput{PolicyNames: f.inlineUser[str(in.UserName)]}, nil
}

func (f *fakeIAM) ListRolePolicies(_ context.Context, in *iam.ListRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return &iam.ListRolePoliciesOutput{PolicyNames: f.inlineRole[str(in.RoleName)]}, nil
}

func (f *fakeIAM) ListGroupPolicies(_ context.Context, in *iam.ListGroupPoliciesInput, _ ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error) {
	return &iam.ListGroupPoliciesOutput{PolicyNames: f.inlineGroup[str(in.GroupName)]}, nil
}

func newFakeIAM() *fakeIAM {
	return &fakeIAM{
		users: []iamtypes.User{
			{UserName: aws.String("alice"), Arn: aws.String("arn:aws:iam::123456789012:user/alice"), UserId: aws.String("AIDA1"), Path: aws.String("/"), PasswordLastUsed: nil},
			{UserName: aws.String("bob"), Arn: aws.String("arn:aws:iam::123456789012:user/bob"), UserId: aws.String("AIDA2")},
		},
		roles: []iamtypes.Role{
			{RoleName: aws.String("billing-writer"), Arn: aws.String("arn:aws:iam::123456789012:role/billing-writer"), RoleId: aws.String("AROA1")},
		},
		groups: []iamtypes.Group{
			{GroupName: aws.String("admins"), Arn: aws.String("arn:aws:iam::123456789012:group/admins"), GroupId: aws.String("AGPA1")},
		},
		accessKeys: map[string][]iamtypes.AccessKeyMetadata{
			"alice": {{AccessKeyId: aws.String("AKIA1"), Status: iamtypes.StatusTypeActive}},
			"bob":   {{AccessKeyId: aws.String("AKIA2"), Status: iamtypes.StatusTypeInactive}},
		},
		mfa: map[string]int{"alice": 1, "bob": 0},
		attachedUser: map[string][]iamtypes.AttachedPolicy{
			"alice": {{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")}},
		},
		attachedRole: map[string][]iamtypes.AttachedPolicy{
			"billing-writer": {{PolicyName: aws.String("Billing"), PolicyArn: aws.String("arn:aws:iam::aws:policy/Billing")}},
		},
		attachedGroup: map[string][]iamtypes.AttachedPolicy{
			"admins": {{PolicyName: aws.String("PowerUser"), PolicyArn: aws.String("arn:aws:iam::aws:policy/PowerUserAccess")}},
		},
		inlineUser:  map[string][]string{"bob": {"bob-inline"}},
		inlineRole:  map[string][]string{"billing-writer": {"role-inline"}},
		inlineGroup: map[string][]string{"admins": {"group-inline"}},
	}
}

func TestAWSIAMDiscover(t *testing.T) {
	a := newAWSIAMWithClient(newFakeIAM())
	res, err := a.Discover(context.Background(), "t1", model.ConnectorConfig{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	if len(res.Identities) != 4 {
		t.Fatalf("identities: want 4, got %d (%v)", len(res.Identities), names(res.Identities))
	}
	types := map[model.IdentityType]int{}
	for _, id := range res.Identities {
		types[id.Type]++
		if id.TenantID != "t1" {
			t.Fatalf("identity %s missing tenant", id.Name)
		}
	}
	if types[model.IdentityHuman] != 2 || types[model.IdentityWorkload] != 1 || types[model.IdentityTeam] != 1 {
		t.Fatalf("unexpected identity types: %v", types)
	}

	if len(res.Credentials) != 2 {
		t.Fatalf("credentials: want 2, got %d", len(res.Credentials))
	}
	for _, c := range res.Credentials {
		if c.Type != model.CredentialAccessKey {
			t.Fatalf("unexpected credential type %s", c.Type)
		}
		if c.IdentityID == "" || c.ExternalID == "" {
			t.Fatalf("credential missing refs: %+v", c)
		}
	}

	// alice: 1 attached; bob: 1 inline; role: 1 attached + 1 inline; group: 1 attached + 1 inline.
	if len(res.Grants) != 6 {
		t.Fatalf("grants: want 6, got %d", len(res.Grants))
	}
	if len(res.Resources) != 6 {
		t.Fatalf("resources: want 6, got %d", len(res.Resources))
	}
	for _, rsc := range res.Resources {
		if rsc.TenantID != "t1" {
			t.Fatalf("resource %s missing tenant", rsc.Name)
		}
	}

	var alice model.Identity
	for _, id := range res.Identities {
		if id.Name == "alice" {
			alice = id
		}
	}
	if alice.Attributes["account_id"] != "123456789012" {
		t.Fatalf("account id not derived: %q", alice.Attributes["account_id"])
	}
	if alice.Attributes["mfa_enabled"] != "true" {
		t.Fatalf("expected mfa enabled for alice")
	}
}

func TestAWSIAMPagination(t *testing.T) {
	f := newFakeIAM()
	f.pageUsers = true
	a := newAWSIAMWithClient(f)
	res, err := a.Discover(context.Background(), "t1", model.ConnectorConfig{})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(res.Identities) != 4 {
		t.Fatalf("identities across pages: want 4, got %d", len(res.Identities))
	}
	if f.userCalls < 2 {
		t.Fatalf("expected multiple ListUsers calls, got %d", f.userCalls)
	}
}

func TestAWSIAMKey(t *testing.T) {
	if NewAWSIAM().Key() != model.ConnectorAWSIAM {
		t.Fatal("unexpected connector key")
	}
}

func names(ids []model.Identity) []string {
	out := make([]string, 0, len(ids))
	for _, i := range ids {
		out = append(out, i.Name)
	}
	return out
}
