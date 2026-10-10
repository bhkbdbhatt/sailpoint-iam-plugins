package connector

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/sentinel-iam/sentinel/internal/model"
)

// awsIAMSource is the source-system name recorded on discovered records.
const awsIAMSource = string(model.ConnectorAWSIAM)

// iamAPI is the subset of the IAM client used by the connector. It exists so
// tests can inject a fake and so the SDK client can be substituted.
type iamAPI interface {
	ListUsers(ctx context.Context, in *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListRoles(ctx context.Context, in *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListGroups(ctx context.Context, in *iam.ListGroupsInput, optFns ...func(*iam.Options)) (*iam.ListGroupsOutput, error)
	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	ListMFADevices(ctx context.Context, in *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	ListAttachedUserPolicies(ctx context.Context, in *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, in *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListAttachedGroupPolicies(ctx context.Context, in *iam.ListAttachedGroupPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	ListUserPolicies(ctx context.Context, in *iam.ListUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	ListRolePolicies(ctx context.Context, in *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	ListGroupPolicies(ctx context.Context, in *iam.ListGroupPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error)
}

// clientFactory builds an IAM client from a connector configuration.
type clientFactory func(ctx context.Context, cfg model.ConnectorConfig) (iamAPI, error)

// AWSIAM discovers IAM users, roles, groups, access keys and policy
// attachments from an AWS account.
type AWSIAM struct {
	factory clientFactory
}

// NewAWSIAM returns an AWS IAM connector backed by the AWS SDK.
func NewAWSIAM() AWSIAM { return AWSIAM{} }

// newAWSIAMWithClient returns a connector with an injected client (tests).
func newAWSIAMWithClient(c iamAPI) AWSIAM {
	return AWSIAM{factory: func(context.Context, model.ConnectorConfig) (iamAPI, error) { return c, nil }}
}

func (AWSIAM) Key() model.ConnectorKey { return model.ConnectorAWSIAM }

func (a AWSIAM) Discover(ctx context.Context, tenantID string, cfg model.ConnectorConfig) (*Result, error) {
	client, err := a.client(ctx, cfg)
	if err != nil {
		return nil, err
	}

	res := &Result{}
	env := cfg.Options["environment"]
	if env == "" {
		env = "prod"
	}

	accountID := ""

	// Users, their access keys, MFA state and policy attachments.
	users, err := a.listUsers(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("list iam users: %w", err)
	}
	for _, u := range users {
		arn := str(u.Arn)
		if accountID == "" {
			accountID = accountFromARN(arn)
		}
		ext := arn
		if ext == "" {
			ext = awsIAMSource + ":user/" + str(u.UserName)
		}
		mfaCount, err := a.countMFA(ctx, client, str(u.UserName))
		if err != nil {
			return nil, fmt.Errorf("list mfa devices for %s: %w", str(u.UserName), err)
		}
		keys, err := a.listAccessKeys(ctx, client, str(u.UserName))
		if err != nil {
			return nil, fmt.Errorf("list access keys for %s: %w", str(u.UserName), err)
		}

		attrs := map[string]string{
			"user_id":     str(u.UserId),
			"account_id":  accountID,
			"mfa_enabled": boolStr(mfaCount > 0),
			"mfa_count":   fmt.Sprintf("%d", mfaCount),
		}
		if p := str(u.Path); p != "" {
			attrs["path"] = p
		}
		if u.PasswordLastUsed != nil {
			attrs["password_last_used"] = u.PasswordLastUsed.UTC().Format(time.RFC3339)
		}
		for _, t := range u.Tags {
			attrs["tag:"+str(t.Key)] = str(t.Value)
		}

		risk := 20
		if mfaCount == 0 {
			risk += 25
		}
		if len(keys) > 0 {
			risk += 15
		}
		if u.PasswordLastUsed == nil {
			risk += 10
		}

		identity := model.Identity{
			TenantID:      tenantID,
			Type:          model.IdentityHuman,
			Name:          str(u.UserName),
			DisplayName:   str(u.UserName),
			Environment:   env,
			CloudProvider: "aws",
			SourceSystem:  awsIAMSource,
			ExternalID:    ext,
			RiskScore:     clampRisk(risk),
			Status:        model.StatusActive,
			CreatedAt:     timeOrZero(u.CreateDate),
			Attributes:    attrs,
		}
		res.Identities = append(res.Identities, identity)

		for _, k := range keys {
			keyID := str(k.AccessKeyId)
			status := model.StatusActive
			if k.Status == iamtypes.StatusTypeInactive {
				status = model.StatusDisabled
			}
			cred := model.Credential{
				TenantID:     tenantID,
				IdentityID:   ext,
				Type:         model.CredentialAccessKey,
				Name:         str(u.UserName) + " access key",
				Scope:        "access_key",
				IssuedAt:     k.CreateDate,
				SourceSystem: awsIAMSource,
				ExternalID:   keyID,
				Status:       status,
			}
			res.Credentials = append(res.Credentials, cred)
		}

		grants, resources, err := a.userPolicyAttachment(ctx, client, str(u.UserName), tenantID, ext, env)
		if err != nil {
			return nil, err
		}
		res.Grants = append(res.Grants, grants...)
		res.Resources = append(res.Resources, resources...)
	}

	// Roles and their policy attachments.
	roles, err := a.listRoles(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("list iam roles: %w", err)
	}
	for _, r := range roles {
		arn := str(r.Arn)
		if accountID == "" {
			accountID = accountFromARN(arn)
		}
		ext := arn
		if ext == "" {
			ext = awsIAMSource + ":role/" + str(r.RoleName)
		}
		attrs := map[string]string{"role_id": str(r.RoleId), "account_id": accountID}
		if p := str(r.Path); p != "" {
			attrs["path"] = p
		}
		if d := str(r.Description); d != "" {
			attrs["description"] = d
		}
		if r.RoleLastUsed != nil && r.RoleLastUsed.LastUsedDate != nil {
			attrs["last_used"] = r.RoleLastUsed.LastUsedDate.UTC().Format(time.RFC3339)
		}
		for _, t := range r.Tags {
			attrs["tag:"+str(t.Key)] = str(t.Value)
		}
		res.Identities = append(res.Identities, model.Identity{
			TenantID:      tenantID,
			Type:          model.IdentityWorkload,
			Name:          str(r.RoleName),
			DisplayName:   str(r.RoleName),
			Environment:   env,
			CloudProvider: "aws",
			SourceSystem:  awsIAMSource,
			ExternalID:    ext,
			RiskScore:     clampRisk(35),
			Status:        model.StatusActive,
			CreatedAt:     timeOrZero(r.CreateDate),
			Attributes:    attrs,
		})

		grants, resources, err := a.rolePolicyAttachment(ctx, client, str(r.RoleName), tenantID, ext, env)
		if err != nil {
			return nil, err
		}
		res.Grants = append(res.Grants, grants...)
		res.Resources = append(res.Resources, resources...)
	}

	// Groups and their policy attachments.
	groups, err := a.listGroups(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("list iam groups: %w", err)
	}
	for _, g := range groups {
		arn := str(g.Arn)
		if accountID == "" {
			accountID = accountFromARN(arn)
		}
		ext := arn
		if ext == "" {
			ext = awsIAMSource + ":group/" + str(g.GroupName)
		}
		res.Identities = append(res.Identities, model.Identity{
			TenantID:      tenantID,
			Type:          model.IdentityTeam,
			Name:          str(g.GroupName),
			DisplayName:   str(g.GroupName),
			Environment:   env,
			CloudProvider: "aws",
			SourceSystem:  awsIAMSource,
			ExternalID:    ext,
			RiskScore:     clampRisk(15),
			Status:        model.StatusActive,
			CreatedAt:     timeOrZero(g.CreateDate),
			Attributes:    map[string]string{"group_id": str(g.GroupId), "account_id": accountID},
		})

		grants, resources, err := a.groupPolicyAttachment(ctx, client, str(g.GroupName), tenantID, ext, env)
		if err != nil {
			return nil, err
		}
		res.Grants = append(res.Grants, grants...)
		res.Resources = append(res.Resources, resources...)
	}

	return res, nil
}

func (a AWSIAM) client(ctx context.Context, cfg model.ConnectorConfig) (iamAPI, error) {
	if a.factory != nil {
		return a.factory(ctx, cfg)
	}

	region := cfg.Options["region"]
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}

	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if ak := cfg.Secrets["access_key_id"]; ak != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(ak, cfg.Secrets["secret_access_key"], cfg.Secrets["session_token"]),
		))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	if roleArn := cfg.Options["role_arn"]; roleArn != "" {
		provider := stscreds.NewAssumeRoleProvider(
			sts.NewFromConfig(awsCfg), roleArn,
			func(o *stscreds.AssumeRoleOptions) {
				if eid := cfg.Options["external_id"]; eid != "" {
					o.ExternalID = aws.String(eid)
				}
			},
		)
		awsCfg.Credentials = aws.NewCredentialsCache(provider)
	}

	return iam.NewFromConfig(awsCfg), nil
}

func (a AWSIAM) listUsers(ctx context.Context, c iamAPI) ([]iamtypes.User, error) {
	var out []iamtypes.User
	var marker *string
	for {
		page, err := c.ListUsers(ctx, &iam.ListUsersInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Users...)
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

func (a AWSIAM) listRoles(ctx context.Context, c iamAPI) ([]iamtypes.Role, error) {
	var out []iamtypes.Role
	var marker *string
	for {
		page, err := c.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Roles...)
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

func (a AWSIAM) listGroups(ctx context.Context, c iamAPI) ([]iamtypes.Group, error) {
	var out []iamtypes.Group
	var marker *string
	for {
		page, err := c.ListGroups(ctx, &iam.ListGroupsInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Groups...)
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

func (a AWSIAM) listAccessKeys(ctx context.Context, c iamAPI, user string) ([]iamtypes.AccessKeyMetadata, error) {
	var out []iamtypes.AccessKeyMetadata
	var marker *string
	for {
		page, err := c.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(user), Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.AccessKeyMetadata...)
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

func (a AWSIAM) countMFA(ctx context.Context, c iamAPI, user string) (int, error) {
	count := 0
	var marker *string
	for {
		page, err := c.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: aws.String(user), Marker: marker})
		if err != nil {
			return 0, err
		}
		count += len(page.MFADevices)
		if !page.IsTruncated {
			return count, nil
		}
		marker = page.Marker
	}
}

// policyAttachments collects attached and inline policies for an identity and
// returns the resulting grants and policy resources.
func (a AWSIAM) policyAttachments(tenantID, identityExt, env string, attached []iamtypes.AttachedPolicy, inlineNames []string) ([]model.AccessGrant, []model.Resource) {
	var grants []model.AccessGrant
	var resources []model.Resource

	for _, ap := range attached {
		arn := str(ap.PolicyArn)
		name := str(ap.PolicyName)
		resources = append(resources, model.Resource{
			TenantID:     tenantID,
			Name:         name,
			Type:         model.ResourceIAMPolicy,
			Environment:  env,
			SourceSystem: awsIAMSource,
			ExternalID:   arn,
		})
		grants = append(grants, model.AccessGrant{
			TenantID:     tenantID,
			IdentityID:   identityExt,
			ResourceID:   arn,
			Entitlement:  "attach",
			SourceSystem: awsIAMSource,
			ExternalID:   identityExt + "|attach|" + arn,
		})
	}

	for _, name := range inlineNames {
		ext := identityExt + "|inline|" + name
		resources = append(resources, model.Resource{
			TenantID:     tenantID,
			Name:         name,
			Type:         model.ResourceIAMPolicy,
			Environment:  env,
			SourceSystem: awsIAMSource,
			ExternalID:   ext,
		})
		grants = append(grants, model.AccessGrant{
			TenantID:     tenantID,
			IdentityID:   identityExt,
			ResourceID:   ext,
			Entitlement:  "inline",
			SourceSystem: awsIAMSource,
			ExternalID:   ext + "|grant",
		})
	}
	return grants, resources
}

func (a AWSIAM) userPolicyAttachment(ctx context.Context, c iamAPI, user, tenantID, ext, env string) ([]model.AccessGrant, []model.Resource, error) {
	attached, err := a.listAttachedUserPolicies(ctx, c, user)
	if err != nil {
		return nil, nil, fmt.Errorf("list attached user policies for %s: %w", user, err)
	}
	inline, err := a.listUserPolicies(ctx, c, user)
	if err != nil {
		return nil, nil, fmt.Errorf("list inline user policies for %s: %w", user, err)
	}
	g, r := a.policyAttachments(tenantID, ext, env, attached, inline)
	return g, r, nil
}

func (a AWSIAM) rolePolicyAttachment(ctx context.Context, c iamAPI, role, tenantID, ext, env string) ([]model.AccessGrant, []model.Resource, error) {
	attached, err := a.listAttachedRolePolicies(ctx, c, role)
	if err != nil {
		return nil, nil, fmt.Errorf("list attached role policies for %s: %w", role, err)
	}
	inline, err := a.listRolePolicies(ctx, c, role)
	if err != nil {
		return nil, nil, fmt.Errorf("list inline role policies for %s: %w", role, err)
	}
	g, r := a.policyAttachments(tenantID, ext, env, attached, inline)
	return g, r, nil
}

func (a AWSIAM) groupPolicyAttachment(ctx context.Context, c iamAPI, group, tenantID, ext, env string) ([]model.AccessGrant, []model.Resource, error) {
	attached, err := a.listAttachedGroupPolicies(ctx, c, group)
	if err != nil {
		return nil, nil, fmt.Errorf("list attached group policies for %s: %w", group, err)
	}
	inline, err := a.listGroupPolicies(ctx, c, group)
	if err != nil {
		return nil, nil, fmt.Errorf("list inline group policies for %s: %w", group, err)
	}
	g, r := a.policyAttachments(tenantID, ext, env, attached, inline)
	return g, r, nil
}

func (a AWSIAM) listAttachedUserPolicies(ctx context.Context, c iamAPI, user string) ([]iamtypes.AttachedPolicy, error) {
	var out []iamtypes.AttachedPolicy
	var marker *string
	for {
		page, err := c.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(user), Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.AttachedPolicies...)
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

func (a AWSIAM) listAttachedRolePolicies(ctx context.Context, c iamAPI, role string) ([]iamtypes.AttachedPolicy, error) {
	var out []iamtypes.AttachedPolicy
	var marker *string
	for {
		page, err := c.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(role), Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.AttachedPolicies...)
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

func (a AWSIAM) listAttachedGroupPolicies(ctx context.Context, c iamAPI, group string) ([]iamtypes.AttachedPolicy, error) {
	var out []iamtypes.AttachedPolicy
	var marker *string
	for {
		page, err := c.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: aws.String(group), Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.AttachedPolicies...)
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

func (a AWSIAM) listUserPolicies(ctx context.Context, c iamAPI, user string) ([]string, error) {
	var out []string
	var marker *string
	for {
		page, err := c.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(user), Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.PolicyNames...)
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

func (a AWSIAM) listRolePolicies(ctx context.Context, c iamAPI, role string) ([]string, error) {
	var out []string
	var marker *string
	for {
		page, err := c.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: aws.String(role), Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.PolicyNames...)
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

func (a AWSIAM) listGroupPolicies(ctx context.Context, c iamAPI, group string) ([]string, error) {
	var out []string
	var marker *string
	for {
		page, err := c.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{GroupName: aws.String(group), Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.PolicyNames...)
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func clampRisk(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// accountFromARN extracts the account id from an ARN
// (arn:partition:service:region:account:resource).
func accountFromARN(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) >= 6 {
		return parts[4]
	}
	return ""
}
