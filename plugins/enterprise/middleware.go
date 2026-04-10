package enterprise

import (
	"strings"

	"github.com/valyala/fasthttp"
)

// Context keys for storing user info in request context.
const (
	CtxKeyUserID     = "enterprise_user_id"
	CtxKeyUserEmail  = "enterprise_user_email"
	CtxKeyUserRole   = "enterprise_user_role"
	CtxKeyUserTeamID = "enterprise_user_team_id"
)

// RoutePermission maps an API route pattern to a required resource+operation.
type RoutePermission struct {
	Method    string
	Prefix    string
	Resource  Resource
	Operation Operation
}

// APIRoutePermissions defines the RBAC requirements for each API endpoint.
var APIRoutePermissions = []RoutePermission{
	// Enterprise user management
	{Method: "GET", Prefix: "/api/enterprise/users", Resource: ResourceUsers, Operation: OpRead},
	{Method: "POST", Prefix: "/api/enterprise/users", Resource: ResourceUsers, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/enterprise/users/", Resource: ResourceUsers, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/enterprise/users/", Resource: ResourceUsers, Operation: OpDelete},
	{Method: "GET", Prefix: "/api/enterprise/audit-logs", Resource: ResourceAuditLogs, Operation: OpRead},

	// Governance endpoints
	{Method: "GET", Prefix: "/api/governance/virtual-keys", Resource: ResourceVirtualKeys, Operation: OpRead},
	{Method: "POST", Prefix: "/api/governance/virtual-keys", Resource: ResourceVirtualKeys, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/governance/virtual-keys/", Resource: ResourceVirtualKeys, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/governance/virtual-keys/", Resource: ResourceVirtualKeys, Operation: OpDelete},
	{Method: "GET", Prefix: "/api/governance/teams", Resource: ResourceTeams, Operation: OpRead},
	{Method: "POST", Prefix: "/api/governance/teams", Resource: ResourceTeams, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/governance/teams/", Resource: ResourceTeams, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/governance/teams/", Resource: ResourceTeams, Operation: OpDelete},
	{Method: "GET", Prefix: "/api/governance/customers", Resource: ResourceCustomers, Operation: OpRead},
	{Method: "POST", Prefix: "/api/governance/customers", Resource: ResourceCustomers, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/governance/customers/", Resource: ResourceCustomers, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/governance/customers/", Resource: ResourceCustomers, Operation: OpDelete},

	// Settings & config
	{Method: "GET", Prefix: "/api/config", Resource: ResourceSettings, Operation: OpRead},
	{Method: "PUT", Prefix: "/api/config", Resource: ResourceSettings, Operation: OpUpdate},
	{Method: "GET", Prefix: "/api/providers", Resource: ResourceModelProvider, Operation: OpRead},
	{Method: "POST", Prefix: "/api/providers", Resource: ResourceModelProvider, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/providers/", Resource: ResourceModelProvider, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/providers/", Resource: ResourceModelProvider, Operation: OpDelete},
	{Method: "GET", Prefix: "/api/plugins", Resource: ResourcePlugins, Operation: OpRead},
	{Method: "PUT", Prefix: "/api/plugins", Resource: ResourcePlugins, Operation: OpUpdate},
	{Method: "GET", Prefix: "/api/logs", Resource: ResourceLogs, Operation: OpRead},
}

// CheckRoutePermission checks if a role has permission for the given HTTP method + path.
func CheckRoutePermission(role Role, method, path string) bool {
	if role == RoleAdmin {
		return true
	}

	// Whitelisted routes (no RBAC check needed)
	whitelisted := []string{
		"/api/session/",
		"/api/enterprise/roles",
		"/api/enterprise/permissions",
		"/health",
	}
	for _, w := range whitelisted {
		if strings.HasPrefix(path, w) || path == w {
			return true
		}
	}

	// Check against route permissions
	for _, rp := range APIRoutePermissions {
		if rp.Method == method && strings.HasPrefix(path, rp.Prefix) {
			return IsAllowed(role, rp.Resource, rp.Operation)
		}
	}

	// Default: deny for non-admin
	return false
}

// ExtractUserFromContext retrieves user info stored in the fasthttp request context.
func ExtractUserFromContext(ctx *fasthttp.RequestCtx) (userID, email string, role Role, teamID *string) {
	if v, ok := ctx.UserValue(CtxKeyUserID).(string); ok {
		userID = v
	}
	if v, ok := ctx.UserValue(CtxKeyUserEmail).(string); ok {
		email = v
	}
	if v, ok := ctx.UserValue(CtxKeyUserRole).(string); ok {
		role = Role(v)
	}
	if v, ok := ctx.UserValue(CtxKeyUserTeamID).(*string); ok {
		teamID = v
	}
	return
}
