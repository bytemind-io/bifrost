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
	{Method: "GET", Prefix: "/api/enterprise/users", Resource: ResourceUsers, Operation: OpView},
	{Method: "POST", Prefix: "/api/enterprise/users", Resource: ResourceUsers, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/enterprise/users/", Resource: ResourceUsers, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/enterprise/users/", Resource: ResourceUsers, Operation: OpDelete},

	// Audit logs
	{Method: "GET", Prefix: "/api/enterprise/audit-logs", Resource: ResourceAuditLogs, Operation: OpView},

	// Team member management
	{Method: "GET", Prefix: "/api/enterprise/teams/", Resource: ResourceUsers, Operation: OpView},
	{Method: "POST", Prefix: "/api/enterprise/teams/", Resource: ResourceUsers, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/enterprise/teams/", Resource: ResourceUsers, Operation: OpUpdate},

	// Governance - Virtual keys
	{Method: "GET", Prefix: "/api/governance/virtual-keys", Resource: ResourceVirtualKeys, Operation: OpView},
	{Method: "POST", Prefix: "/api/governance/virtual-keys", Resource: ResourceVirtualKeys, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/governance/virtual-keys/", Resource: ResourceVirtualKeys, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/governance/virtual-keys/", Resource: ResourceVirtualKeys, Operation: OpDelete},

	// Governance - Teams
	{Method: "GET", Prefix: "/api/governance/teams", Resource: ResourceVirtualKeys, Operation: OpView},
	{Method: "POST", Prefix: "/api/governance/teams", Resource: ResourceVirtualKeys, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/governance/teams/", Resource: ResourceVirtualKeys, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/governance/teams/", Resource: ResourceVirtualKeys, Operation: OpDelete},

	// Governance - Customers (admin-level operations, use Settings resource)
	{Method: "GET", Prefix: "/api/governance/customers", Resource: ResourceVirtualKeys, Operation: OpView},
	{Method: "POST", Prefix: "/api/governance/customers", Resource: ResourceSettings, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/governance/customers/", Resource: ResourceSettings, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/governance/customers/", Resource: ResourceSettings, Operation: OpDelete},

	// Governance - Budgets & rate limits
	{Method: "GET", Prefix: "/api/governance/budgets", Resource: ResourceVirtualKeys, Operation: OpView},
	{Method: "GET", Prefix: "/api/governance/rate-limits", Resource: ResourceVirtualKeys, Operation: OpView},

	// Governance - Routing rules
	{Method: "GET", Prefix: "/api/governance/routing-rules", Resource: ResourceAdaptiveRouter, Operation: OpView},
	{Method: "POST", Prefix: "/api/governance/routing-rules", Resource: ResourceAdaptiveRouter, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/governance/routing-rules/", Resource: ResourceAdaptiveRouter, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/governance/routing-rules/", Resource: ResourceAdaptiveRouter, Operation: OpDelete},

	// Governance - Model configs & providers
	{Method: "GET", Prefix: "/api/governance/model-configs", Resource: ResourceModelProvider, Operation: OpView},
	{Method: "POST", Prefix: "/api/governance/model-configs", Resource: ResourceModelProvider, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/governance/model-configs/", Resource: ResourceModelProvider, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/governance/model-configs/", Resource: ResourceModelProvider, Operation: OpDelete},
	{Method: "GET", Prefix: "/api/governance/providers", Resource: ResourceModelProvider, Operation: OpView},
	{Method: "PUT", Prefix: "/api/governance/providers/", Resource: ResourceModelProvider, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/governance/providers/", Resource: ResourceModelProvider, Operation: OpDelete},

	// Settings & config
	{Method: "GET", Prefix: "/api/config", Resource: ResourceSettings, Operation: OpView},
	{Method: "PUT", Prefix: "/api/config", Resource: ResourceSettings, Operation: OpUpdate},
	{Method: "GET", Prefix: "/api/proxy-config", Resource: ResourceSettings, Operation: OpView},
	{Method: "PUT", Prefix: "/api/proxy-config", Resource: ResourceSettings, Operation: OpUpdate},
	{Method: "POST", Prefix: "/api/pricing/force-sync", Resource: ResourceSettings, Operation: OpUpdate},

	// Providers & models
	{Method: "GET", Prefix: "/api/providers", Resource: ResourceModelProvider, Operation: OpView},
	{Method: "POST", Prefix: "/api/providers", Resource: ResourceModelProvider, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/providers/", Resource: ResourceModelProvider, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/providers/", Resource: ResourceModelProvider, Operation: OpDelete},
	{Method: "GET", Prefix: "/api/models", Resource: ResourceModelProvider, Operation: OpView},
	{Method: "GET", Prefix: "/api/keys", Resource: ResourceModelProvider, Operation: OpView},

	// Plugins
	{Method: "GET", Prefix: "/api/plugins", Resource: ResourcePlugins, Operation: OpView},
	{Method: "POST", Prefix: "/api/plugins", Resource: ResourcePlugins, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/plugins/", Resource: ResourcePlugins, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/plugins/", Resource: ResourcePlugins, Operation: OpDelete},

	// Logs
	{Method: "GET", Prefix: "/api/logs", Resource: ResourceLogs, Operation: OpView},
	{Method: "DELETE", Prefix: "/api/logs", Resource: ResourceLogs, Operation: OpDelete},
	{Method: "POST", Prefix: "/api/logs/recalculate-cost", Resource: ResourceLogs, Operation: OpUpdate},
	{Method: "GET", Prefix: "/api/mcp-logs", Resource: ResourceLogs, Operation: OpView},
	{Method: "DELETE", Prefix: "/api/mcp-logs", Resource: ResourceLogs, Operation: OpDelete},

	// MCP Gateway
	{Method: "GET", Prefix: "/api/mcp/clients", Resource: ResourceMCPGateway, Operation: OpView},
	{Method: "GET", Prefix: "/api/mcp/client/", Resource: ResourceMCPGateway, Operation: OpView},
	{Method: "POST", Prefix: "/api/mcp/client", Resource: ResourceMCPGateway, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/mcp/client/", Resource: ResourceMCPGateway, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/mcp/client/", Resource: ResourceMCPGateway, Operation: OpDelete},

	// Prompt repo (uses Plugins resource)
	{Method: "GET", Prefix: "/api/prompt-repo/", Resource: ResourcePlugins, Operation: OpView},
	{Method: "POST", Prefix: "/api/prompt-repo/", Resource: ResourcePlugins, Operation: OpCreate},
	{Method: "PUT", Prefix: "/api/prompt-repo/", Resource: ResourcePlugins, Operation: OpUpdate},
	{Method: "DELETE", Prefix: "/api/prompt-repo/", Resource: ResourcePlugins, Operation: OpDelete},

	// OAuth
	{Method: "GET", Prefix: "/api/oauth/", Resource: ResourceSettings, Operation: OpView},
	{Method: "DELETE", Prefix: "/api/oauth/", Resource: ResourceSettings, Operation: OpDelete},

	// Cache
	{Method: "DELETE", Prefix: "/api/cache/", Resource: ResourceSettings, Operation: OpDelete},
}

// CheckRoutePermission checks if a role has permission for the given HTTP method + path.
// Uses the RoleStore for dynamic permission lookup.
func CheckRoutePermission(roleStore *RoleStore, roleName string, method, path string) bool {
	// Admin always allowed (fast path, case-insensitive for backward compat)
	if strings.EqualFold(roleName, "Admin") {
		return true
	}

	// Whitelisted routes (any authenticated user)
	whitelisted := []string{
		"/api/session/",
		"/api/enterprise/login",
		"/api/enterprise/logout",
		"/api/enterprise/roles",
		"/api/enterprise/permissions",
		"/api/enterprise/me",
		"/api/config",
		"/api/version",
		"/ws",
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
			return roleStore.IsAllowed(roleName, rp.Resource, rp.Operation)
		}
	}

	// Default: deny for non-admin
	return false
}

// ExtractUserFromContext retrieves user info stored in the fasthttp request context.
func ExtractUserFromContext(ctx *fasthttp.RequestCtx) (userID, email string, role string, teamID *string) {
	if v, ok := ctx.UserValue(CtxKeyUserID).(string); ok {
		userID = v
	}
	if v, ok := ctx.UserValue(CtxKeyUserEmail).(string); ok {
		email = v
	}
	if v, ok := ctx.UserValue(CtxKeyUserRole).(string); ok {
		role = v
	}
	if v, ok := ctx.UserValue(CtxKeyUserTeamID).(*string); ok {
		teamID = v
	}
	return
}
