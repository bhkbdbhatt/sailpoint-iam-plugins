package auth

import "github.com/sentinel-iam/sentinel/internal/model"

const (
	PermTenantsRead     = "tenants:read"
	PermTenantsWrite    = "tenants:write"
	PermUsersRead       = "users:read"
	PermUsersWrite      = "users:write"
	PermAPIKeysWrite    = "apikeys:write"
	PermIdentitiesRead  = "identities:read"
	PermIdentitiesWrite = "identities:write"
	PermCredentialsRead = "credentials:read"
	PermGrantsRead      = "grants:read"
	PermResourcesRead   = "resources:read"
	PermConnectorsRead  = "connectors:read"
	PermConnectorsWrite = "connectors:write"
	PermConnectorsRun   = "connectors:run"
	PermStatsRead       = "stats:read"
	PermAlertsRead      = "alerts:read"
	PermAlertsWrite     = "alerts:write"
	PermPoliciesRead    = "policies:read"
	PermPoliciesWrite   = "policies:write"
)

var rolePermissions = map[model.Role]map[string]bool{
	model.RoleOwner: permissionSet(
		PermTenantsRead, PermTenantsWrite, PermUsersRead, PermUsersWrite, PermAPIKeysWrite,
		PermIdentitiesRead, PermIdentitiesWrite, PermCredentialsRead, PermGrantsRead,
		PermResourcesRead, PermConnectorsRead, PermConnectorsWrite, PermConnectorsRun,
		PermStatsRead, PermAlertsRead, PermAlertsWrite, PermPoliciesRead, PermPoliciesWrite,
	),
	model.RoleAdmin: permissionSet(
		PermTenantsRead, PermUsersRead, PermUsersWrite, PermAPIKeysWrite,
		PermIdentitiesRead, PermIdentitiesWrite, PermCredentialsRead, PermGrantsRead,
		PermResourcesRead, PermConnectorsRead, PermConnectorsWrite, PermConnectorsRun,
		PermStatsRead, PermAlertsRead, PermAlertsWrite, PermPoliciesRead, PermPoliciesWrite,
	),
	model.RoleAnalyst: permissionSet(
		PermTenantsRead, PermUsersRead,
		PermIdentitiesRead, PermCredentialsRead, PermGrantsRead,
		PermResourcesRead, PermConnectorsRead, PermConnectorsRun,
		PermStatsRead, PermAlertsRead, PermAlertsWrite, PermPoliciesRead,
	),
	model.RoleViewer: permissionSet(
		PermIdentitiesRead, PermCredentialsRead, PermGrantsRead,
		PermResourcesRead, PermConnectorsRead, PermStatsRead, PermPoliciesRead,
	),
}

func permissionSet(perms ...string) map[string]bool {
	set := make(map[string]bool, len(perms))
	for _, p := range perms {
		set[p] = true
	}
	return set
}

func Can(role model.Role, perm string) bool {
	set, ok := rolePermissions[role]
	if !ok {
		return false
	}
	return set[perm]
}

func Permissions(role model.Role) []string {
	set := rolePermissions[role]
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	return out
}
