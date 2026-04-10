package enterprise

import (
	"testing"
)

func TestIsAllowed_Admin(t *testing.T) {
	// Admin should be allowed to do everything
	tests := []struct {
		resource  Resource
		operation Operation
	}{
		{ResourceVirtualKeys, OpRead},
		{ResourceVirtualKeys, OpCreate},
		{ResourceVirtualKeys, OpDelete},
		{ResourceUsers, OpCreate},
		{ResourceAuditLogs, OpRead},
		{ResourceSettings, OpUpdate},
		{ResourceCustomers, OpDelete},
	}
	for _, tt := range tests {
		if !IsAllowed(RoleAdmin, tt.resource, tt.operation) {
			t.Errorf("Admin should be allowed %s:%s", tt.resource, tt.operation)
		}
	}
}

func TestIsAllowed_TeamManager(t *testing.T) {
	// TeamManager can manage VKs, read teams/users/logs
	allowed := []struct {
		resource  Resource
		operation Operation
	}{
		{ResourceVirtualKeys, OpRead},
		{ResourceVirtualKeys, OpCreate},
		{ResourceVirtualKeys, OpUpdate},
		{ResourceVirtualKeys, OpDelete},
		{ResourceTeams, OpRead},
		{ResourceTeams, OpUpdate},
		{ResourceUsers, OpRead},
		{ResourceLogs, OpRead},
	}
	for _, tt := range allowed {
		if !IsAllowed(RoleTeamManager, tt.resource, tt.operation) {
			t.Errorf("TeamManager should be allowed %s:%s", tt.resource, tt.operation)
		}
	}

	// TeamManager cannot manage customers, settings, plugins
	denied := []struct {
		resource  Resource
		operation Operation
	}{
		{ResourceCustomers, OpCreate},
		{ResourceCustomers, OpDelete},
		{ResourceSettings, OpUpdate},
		{ResourcePlugins, OpUpdate},
		{ResourceUsers, OpCreate},
		{ResourceUsers, OpDelete},
	}
	for _, tt := range denied {
		if IsAllowed(RoleTeamManager, tt.resource, tt.operation) {
			t.Errorf("TeamManager should NOT be allowed %s:%s", tt.resource, tt.operation)
		}
	}
}

func TestIsAllowed_User(t *testing.T) {
	// User can only read VKs and logs
	if !IsAllowed(RoleUser, ResourceVirtualKeys, OpRead) {
		t.Error("User should be able to read VirtualKeys")
	}
	if !IsAllowed(RoleUser, ResourceLogs, OpRead) {
		t.Error("User should be able to read Logs")
	}
	if IsAllowed(RoleUser, ResourceVirtualKeys, OpCreate) {
		t.Error("User should NOT be able to create VirtualKeys")
	}
	if IsAllowed(RoleUser, ResourceUsers, OpRead) {
		t.Error("User should NOT be able to read Users")
	}
	if IsAllowed(RoleUser, ResourceSettings, OpRead) {
		t.Error("User should NOT be able to read Settings")
	}
}

func TestIsAllowed_Viewer(t *testing.T) {
	// Viewer can read everything but cannot create/update/delete
	if !IsAllowed(RoleViewer, ResourceVirtualKeys, OpRead) {
		t.Error("Viewer should be able to read VirtualKeys")
	}
	if !IsAllowed(RoleViewer, ResourceSettings, OpRead) {
		t.Error("Viewer should be able to read Settings")
	}
	if !IsAllowed(RoleViewer, ResourceAuditLogs, OpView) {
		t.Error("Viewer should be able to view AuditLogs")
	}
	if IsAllowed(RoleViewer, ResourceVirtualKeys, OpCreate) {
		t.Error("Viewer should NOT be able to create VirtualKeys")
	}
	if IsAllowed(RoleViewer, ResourceSettings, OpUpdate) {
		t.Error("Viewer should NOT be able to update Settings")
	}
}

func TestIsAllowed_UnknownRole(t *testing.T) {
	if IsAllowed(Role("unknown"), ResourceVirtualKeys, OpRead) {
		t.Error("Unknown role should not be allowed anything")
	}
}

func TestGetAllRoles(t *testing.T) {
	roles := GetAllRoles()
	if len(roles) != 4 {
		t.Errorf("Expected 4 roles, got %d", len(roles))
	}
	names := map[Role]bool{}
	for _, r := range roles {
		names[r.Name] = true
	}
	for _, expected := range []Role{RoleAdmin, RoleTeamManager, RoleUser, RoleViewer} {
		if !names[expected] {
			t.Errorf("Missing role: %s", expected)
		}
	}
}

func TestGetPermissionsMap(t *testing.T) {
	// Admin should have all true
	adminPerms := GetPermissionsMap(RoleAdmin)
	if !adminPerms["VirtualKeys"]["Create"] {
		t.Error("Admin should have VirtualKeys:Create = true")
	}
	if !adminPerms["Settings"]["Update"] {
		t.Error("Admin should have Settings:Update = true")
	}

	// User should have limited permissions
	userPerms := GetPermissionsMap(RoleUser)
	if !userPerms["VirtualKeys"]["Read"] {
		t.Error("User should have VirtualKeys:Read = true")
	}
	if userPerms["VirtualKeys"]["Create"] {
		t.Error("User should NOT have VirtualKeys:Create")
	}
	if userPerms["Settings"]["Read"] {
		t.Error("User should NOT have Settings:Read")
	}
}

func TestCheckRoutePermission(t *testing.T) {
	// Admin should always pass
	if !CheckRoutePermission(RoleAdmin, "DELETE", "/api/governance/customers/123") {
		t.Error("Admin should be able to delete customers")
	}

	// Whitelisted routes should always pass
	if !CheckRoutePermission(RoleUser, "POST", "/api/session/login") {
		t.Error("Session login should be whitelisted for all roles")
	}
	if !CheckRoutePermission(RoleUser, "GET", "/api/enterprise/permissions") {
		t.Error("Enterprise permissions should be whitelisted for all roles")
	}

	// TeamManager can create VKs
	if !CheckRoutePermission(RoleTeamManager, "POST", "/api/governance/virtual-keys") {
		t.Error("TeamManager should be able to create VKs")
	}

	// User cannot create VKs
	if CheckRoutePermission(RoleUser, "POST", "/api/governance/virtual-keys") {
		t.Error("User should NOT be able to create VKs")
	}

	// Viewer can read but not write
	if !CheckRoutePermission(RoleViewer, "GET", "/api/governance/virtual-keys") {
		t.Error("Viewer should be able to read VKs")
	}
	if CheckRoutePermission(RoleViewer, "POST", "/api/governance/virtual-keys") {
		t.Error("Viewer should NOT be able to create VKs")
	}
}
