// Package enterprise provides multi-tenancy with fixed roles for Bifrost.
package enterprise

// Role represents a user role in the system.
type Role string

const (
	RoleAdmin       Role = "admin"
	RoleTeamManager Role = "team_manager"
	RoleUser        Role = "user"
	RoleViewer      Role = "viewer"
)

// Resource represents a system resource.
type Resource string

const (
	ResourceAll           Resource = "*"
	ResourceVirtualKeys   Resource = "VirtualKeys"
	ResourceTeams         Resource = "Teams"
	ResourceCustomers     Resource = "Customers"
	ResourceUsers         Resource = "Users"
	ResourceLogs          Resource = "Logs"
	ResourceObservability Resource = "Observability"
	ResourceSettings      Resource = "Settings"
	ResourceModelProvider Resource = "ModelProvider"
	ResourcePlugins       Resource = "Plugins"
	ResourceMCPGateway    Resource = "MCPGateway"
	ResourceAuditLogs     Resource = "AuditLogs"
	ResourceRBAC          Resource = "RBAC"
	ResourceGovernance    Resource = "Governance"
	ResourceRoutingRules  Resource = "RoutingRules"
)

// Operation represents an action on a resource.
type Operation string

const (
	OpAll    Operation = "*"
	OpRead   Operation = "Read"
	OpView   Operation = "View"
	OpCreate Operation = "Create"
	OpUpdate Operation = "Update"
	OpDelete Operation = "Delete"
)

// RolePermissions defines what each role can do.
var RolePermissions = map[Role]map[Resource][]Operation{
	RoleAdmin: {
		ResourceAll: {OpAll},
	},
	RoleTeamManager: {
		ResourceVirtualKeys:   {OpRead, OpCreate, OpUpdate, OpDelete},
		ResourceTeams:         {OpRead, OpUpdate},
		ResourceUsers:         {OpRead},
		ResourceLogs:          {OpRead},
		ResourceObservability: {OpRead},
		ResourceGovernance:    {OpRead},
	},
	RoleUser: {
		ResourceVirtualKeys: {OpRead},
		ResourceLogs:        {OpRead},
		ResourceGovernance:  {OpRead},
	},
	RoleViewer: {
		ResourceAll: {OpRead, OpView},
	},
}

// RoleInfo describes a role for API responses.
type RoleInfo struct {
	Name        Role                     `json:"name"`
	Label       string                   `json:"label"`
	Description string                   `json:"description"`
	Permissions map[Resource][]Operation `json:"permissions"`
}

// GetAllRoles returns info about all available roles.
func GetAllRoles() []RoleInfo {
	return []RoleInfo{
		{
			Name:        RoleAdmin,
			Label:       "Admin",
			Description: "Full access to all features and settings",
			Permissions: RolePermissions[RoleAdmin],
		},
		{
			Name:        RoleTeamManager,
			Label:       "Team Manager",
			Description: "Manage team virtual keys, members, and view team usage",
			Permissions: RolePermissions[RoleTeamManager],
		},
		{
			Name:        RoleUser,
			Label:       "User",
			Description: "View own virtual keys and usage logs",
			Permissions: RolePermissions[RoleUser],
		},
		{
			Name:        RoleViewer,
			Label:       "Viewer",
			Description: "Read-only access to visible resources",
			Permissions: RolePermissions[RoleViewer],
		},
	}
}

// IsAllowed checks if a role has permission for a given resource+operation.
func IsAllowed(role Role, resource Resource, operation Operation) bool {
	perms, ok := RolePermissions[role]
	if !ok {
		return false
	}
	// Check wildcard resource
	if ops, ok := perms[ResourceAll]; ok {
		for _, op := range ops {
			if op == OpAll || op == operation {
				return true
			}
		}
	}
	// Check specific resource
	if ops, ok := perms[resource]; ok {
		for _, op := range ops {
			if op == OpAll || op == operation {
				return true
			}
		}
	}
	return false
}

// GetPermissionsMap returns a flat map of resource->operation->bool for frontend RBAC context.
func GetPermissionsMap(role Role) map[string]map[string]bool {
	result := make(map[string]map[string]bool)

	allResources := []Resource{
		ResourceVirtualKeys, ResourceTeams, ResourceCustomers, ResourceUsers,
		ResourceLogs, ResourceObservability, ResourceSettings, ResourceModelProvider,
		ResourcePlugins, ResourceMCPGateway, ResourceAuditLogs, ResourceRBAC,
		ResourceGovernance, ResourceRoutingRules,
	}
	allOps := []Operation{OpRead, OpView, OpCreate, OpUpdate, OpDelete}

	for _, res := range allResources {
		resMap := make(map[string]bool)
		for _, op := range allOps {
			resMap[string(op)] = IsAllowed(role, res, op)
		}
		result[string(res)] = resMap
	}
	return result
}
