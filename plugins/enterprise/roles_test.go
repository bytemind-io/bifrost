package enterprise

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupRoleTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	return db
}

func TestRoleStore_SystemRolesSeeded(t *testing.T) {
	db := setupRoleTestDB(t)
	store, err := NewRoleStore(db)
	if err != nil {
		t.Fatalf("failed to create role store: %v", err)
	}

	roles, err := store.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("failed to list roles: %v", err)
	}
	if len(roles) != 3 {
		t.Errorf("expected 3 system roles, got %d", len(roles))
	}

	names := map[string]bool{}
	for _, r := range roles {
		names[r.Name] = true
		if !r.IsSystem {
			t.Errorf("system role %s should have IsSystem=true", r.Name)
		}
	}
	for _, expected := range []string{"Admin", "Developer", "Viewer"} {
		if !names[expected] {
			t.Errorf("missing system role: %s", expected)
		}
	}
}

func TestRoleStore_AdminHasAllPermissions(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)

	for _, res := range AllResources {
		for _, op := range AllOperations {
			if !store.IsAllowed("Admin", res, op) {
				t.Errorf("Admin should be allowed %s:%s", res, op)
			}
		}
	}
}

func TestRoleStore_DeveloperPermissions(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)

	// Developer can manage non-destructive VK operations
	if !store.IsAllowed("Developer", ResourceVirtualKeys, OpView) {
		t.Error("Developer should be able to view VirtualKeys")
	}
	if !store.IsAllowed("Developer", ResourceVirtualKeys, OpCreate) {
		t.Error("Developer should be able to create VirtualKeys")
	}
	if !store.IsAllowed("Developer", ResourceVirtualKeys, OpUpdate) {
		t.Error("Developer should be able to update VirtualKeys")
	}
	if store.IsAllowed("Developer", ResourceVirtualKeys, OpDelete) {
		t.Error("Developer should NOT be able to delete VirtualKeys")
	}
	if store.IsAllowed("Developer", ResourceTeams, OpDelete) {
		t.Error("Developer should NOT be able to delete Teams")
	}
	if store.IsAllowed("Developer", ResourceCustomers, OpDelete) {
		t.Error("Developer should NOT be able to delete Customers")
	}

	// Developer can only view Logs
	if !store.IsAllowed("Developer", ResourceLogs, OpView) {
		t.Error("Developer should be able to view Logs")
	}
	if store.IsAllowed("Developer", ResourceLogs, OpDelete) {
		t.Error("Developer should NOT be able to delete Logs")
	}

	// Developer cannot manage UserProvisioning
	if store.IsAllowed("Developer", ResourceUserProvisioning, OpCreate) {
		t.Error("Developer should NOT be able to create UserProvisioning")
	}
}

func TestRoleStore_ViewerReadOnly(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)

	allowed := map[Resource]bool{
		ResourceDashboard: true,
		ResourceLogs:      true,
		ResourceAuditLogs: true,
	}

	for _, res := range AllResources {
		if allowed[res] != store.IsAllowed("Viewer", res, OpView) {
			t.Errorf("unexpected Viewer View permission for %s", res)
		}
		if store.IsAllowed("Viewer", res, OpCreate) {
			t.Errorf("Viewer should NOT be able to create %s", res)
		}
		if store.IsAllowed("Viewer", res, OpDelete) {
			t.Errorf("Viewer should NOT be able to delete %s", res)
		}
	}
}

func TestRoleStore_UnknownRoleDenied(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)

	if store.IsAllowed("nonexistent", ResourceVirtualKeys, OpView) {
		t.Error("Unknown role should not be allowed anything")
	}
}

func TestRoleStore_CustomRoleCRUD(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)
	ctx := context.Background()

	// Create custom role
	role, err := store.CreateRole(ctx, "Auditor", "Read-only for compliance")
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}
	if role.Name != "Auditor" || role.IsSystem {
		t.Error("custom role should have correct name and IsSystem=false")
	}

	// New role has no permissions
	if store.IsAllowed("Auditor", ResourceAuditLogs, OpView) {
		t.Error("new custom role should have no permissions")
	}

	// Assign permissions
	err = store.SetRolePermissions(ctx, role.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceAuditLogs), string(OpView)},
		{string(ResourceLogs), string(OpView)},
		{string(ResourceUsers), string(OpView)},
	})
	if err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	// Check permissions
	if !store.IsAllowed("Auditor", ResourceAuditLogs, OpView) {
		t.Error("Auditor should now be able to view AuditLogs")
	}
	if store.IsAllowed("Auditor", ResourceAuditLogs, OpDelete) {
		t.Error("Auditor should NOT be able to delete AuditLogs")
	}
	if !store.IsAllowed("Auditor", ResourceLogs, OpView) {
		t.Error("Auditor should be able to view Logs")
	}

	// Update role
	updated, err := store.UpdateRole(ctx, role.ID, "Senior Auditor", "Updated description")
	if err != nil {
		t.Fatalf("failed to update role: %v", err)
	}
	if updated.Name != "Senior Auditor" {
		t.Errorf("expected updated name 'Senior Auditor', got %s", updated.Name)
	}

	// Delete custom role
	if err := store.DeleteRole(ctx, role.ID); err != nil {
		t.Fatalf("failed to delete role: %v", err)
	}

	// Verify deleted
	roles, _ := store.ListRoles(ctx)
	for _, r := range roles {
		if r.Name == "Senior Auditor" {
			t.Error("role should be deleted")
		}
	}
}

func TestRoleStore_CannotDeleteSystemRole(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)
	ctx := context.Background()

	admin := store.GetRoleByName("Admin")
	if admin == nil {
		t.Fatal("Admin role not found")
	}
	if err := store.DeleteRole(ctx, admin.ID); err == nil {
		t.Error("should not be able to delete system role")
	}
}

func TestRoleStore_PermissionsMap(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)

	adminPerms := store.GetPermissionsMap("Admin")
	if !adminPerms["VirtualKeys"]["Create"] {
		t.Error("Admin should have VirtualKeys:Create = true")
	}

	viewerPerms := store.GetPermissionsMap("Viewer")
	if !viewerPerms["Dashboard"]["View"] {
		t.Error("Viewer should have Dashboard:View = true")
	}
	if viewerPerms["VirtualKeys"]["View"] {
		t.Error("Viewer should NOT have VirtualKeys:View")
	}
	if viewerPerms["Dashboard"]["Create"] {
		t.Error("Viewer should NOT have Dashboard:Create")
	}
}

func TestCheckRoutePermission(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)

	// Admin always passes
	if !CheckRoutePermission(store, "Admin", "DELETE", "/api/governance/customers/123") {
		t.Error("Admin should be able to delete customers")
	}

	// Whitelisted routes pass for all
	if !CheckRoutePermission(store, "Viewer", "POST", "/api/session/login") {
		t.Error("Session login should be whitelisted")
	}
	if !CheckRoutePermission(store, "Viewer", "GET", "/api/enterprise/permissions") {
		t.Error("Permissions should be whitelisted")
	}

	// Developer can CRUD VKs
	if !CheckRoutePermission(store, "Developer", "POST", "/api/governance/virtual-keys") {
		t.Error("Developer should be able to create VKs")
	}

	// Viewer can read logs but not governance resources
	if !CheckRoutePermission(store, "Viewer", "GET", "/api/logs") {
		t.Error("Viewer should be able to read logs")
	}
	if CheckRoutePermission(store, "Viewer", "GET", "/api/governance/virtual-keys") {
		t.Error("Viewer should NOT be able to read VKs")
	}
}

func TestRoleStore_SystemRolePermissionsAreSynchronized(t *testing.T) {
	db := setupRoleTestDB(t)
	store, err := NewRoleStore(db)
	if err != nil {
		t.Fatalf("failed to create role store: %v", err)
	}

	viewer := store.GetRoleByName("Viewer")
	if viewer == nil {
		t.Fatal("Viewer role not found")
	}

	// Manually insert an extra permission that is NOT in the Viewer definition
	legacyPerm := TableRolePermission{
		ID:        uuid.New().String(),
		RoleID:    viewer.ID,
		Resource:  string(ResourceVirtualKeys),
		Operation: string(OpView),
	}
	if err := db.Create(&legacyPerm).Error; err != nil {
		t.Fatalf("failed to insert legacy permission: %v", err)
	}

	// Recreate store (simulates server restart) — sync must remove the extra permission
	store, err = NewRoleStore(db)
	if err != nil {
		t.Fatalf("failed to recreate role store: %v", err)
	}

	if store.IsAllowed("Viewer", ResourceVirtualKeys, OpView) {
		t.Fatal("Viewer extra VirtualKeys:View permission should be removed during sync")
	}
	if !store.IsAllowed("Viewer", ResourceDashboard, OpView) {
		t.Fatal("Viewer should retain Dashboard:View permission after sync")
	}
}

func TestCustomRole_DoesNotInheritAliasedPermissions(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)
	ctx := context.Background()

	role, err := store.CreateRole(ctx, "ScopedOps", "Granular enterprise permissions")
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}

	err = store.SetRolePermissions(ctx, role.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceVirtualKeys), string(OpView)},
		{string(ResourceUsers), string(OpView)},
		{string(ResourceAdaptiveRouter), string(OpView)},
	})
	if err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	if !store.IsAllowed("ScopedOps", ResourceVirtualKeys, OpView) {
		t.Error("ScopedOps should be able to view VirtualKeys")
	}
	if store.IsAllowed("ScopedOps", ResourceCustomers, OpView) {
		t.Error("ScopedOps should NOT inherit Customers view from VirtualKeys")
	}
	if store.IsAllowed("ScopedOps", ResourceTeams, OpView) {
		t.Error("ScopedOps should NOT inherit Teams view from VirtualKeys")
	}
	if store.IsAllowed("ScopedOps", ResourceRBAC, OpView) {
		t.Error("ScopedOps should NOT inherit RBAC view from Users")
	}
	if store.IsAllowed("ScopedOps", ResourceRoutingRules, OpView) {
		t.Error("ScopedOps should NOT inherit RoutingRules view from AdaptiveRouter")
	}
}

func TestConfigWriteRequiresSettingsPermission(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)
	ctx := context.Background()

	role, err := store.CreateRole(ctx, "ReadOnlyConfig", "Can only read settings")
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}

	err = store.SetRolePermissions(ctx, role.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceSettings), string(OpView)},
	})
	if err != nil {
		t.Fatalf("failed to set permissions: %v", err)
	}

	if !CheckRoutePermission(store, "ReadOnlyConfig", "GET", "/api/config") {
		t.Error("ReadOnlyConfig should be able to read config")
	}
	if CheckRoutePermission(store, "ReadOnlyConfig", "PUT", "/api/config") {
		t.Error("ReadOnlyConfig should NOT be able to update config")
	}
}

func TestCheckRoutePermission_DashboardAllowsDashboardDataEndpoints(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)
	ctx := context.Background()

	role, err := store.CreateRole(ctx, "DashboardOnly", "Dashboard access only")
	if err != nil {
		t.Fatalf("failed to create role: %v", err)
	}

	err = store.SetRolePermissions(ctx, role.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceDashboard), string(OpView)},
	})
	if err != nil {
		t.Fatalf("failed to set dashboard permission: %v", err)
	}

	if !CheckRoutePermission(store, "DashboardOnly", "GET", "/api/logs/stats") {
		t.Fatal("DashboardOnly should be able to access /api/logs/stats")
	}
	if !CheckRoutePermission(store, "DashboardOnly", "GET", "/api/logs/histogram") {
		t.Fatal("DashboardOnly should be able to access /api/logs/histogram")
	}
	if !CheckRoutePermission(store, "DashboardOnly", "GET", "/api/mcp-logs/stats") {
		t.Fatal("DashboardOnly should be able to access /api/mcp-logs/stats")
	}
	if CheckRoutePermission(store, "DashboardOnly", "GET", "/api/logs") {
		t.Fatal("DashboardOnly should not be able to access raw logs listing")
	}
}

// TestCustomRole_GovernanceModuleAccess covers all governance pages:
// Virtual Keys, Users, Teams, Customers, User Provisioning, Roles & Permissions, Audit Logs
func TestCustomRole_GovernanceModuleAccess(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)
	ctx := context.Background()

	// Create a custom role with only Teams + VirtualKeys + AuditLogs View
	role, _ := store.CreateRole(ctx, "GovernanceViewer", "View governance subset")
	_ = store.SetRolePermissions(ctx, role.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceTeams), string(OpView)},
		{string(ResourceVirtualKeys), string(OpView)},
		{string(ResourceAuditLogs), string(OpView)},
	})

	// --- Routes this role SHOULD be able to access ---
	allowed := []struct {
		method, path, desc string
	}{
		{"GET", "/api/governance/teams", "list teams"},
		{"GET", "/api/governance/teams/some-id", "get team by ID"},
		{"GET", "/api/governance/virtual-keys", "list VKs"},
		{"GET", "/api/governance/virtual-keys/some-id", "get VK by ID"},
		{"GET", "/api/audit-logs", "list audit logs"},
		{"GET", "/api/enterprise/audit-logs", "list enterprise audit logs"},
		// Whitelisted routes
		{"GET", "/api/enterprise/permissions", "get permissions"},
		{"GET", "/api/enterprise/me", "get me"},
		{"POST", "/api/session/login", "login"},
	}
	for _, tc := range allowed {
		if !CheckRoutePermission(store, "GovernanceViewer", tc.method, tc.path) {
			t.Errorf("GovernanceViewer should be able to %s (%s %s)", tc.desc, tc.method, tc.path)
		}
	}

	// --- Routes this role SHOULD NOT be able to access ---
	denied := []struct {
		method, path, desc string
	}{
		// No Users permission
		{"GET", "/api/enterprise/users", "list users"},
		{"POST", "/api/enterprise/users", "create user"},
		// No Customers permission
		{"GET", "/api/governance/customers", "list customers"},
		{"POST", "/api/governance/customers", "create customer"},
		// No UserProvisioning / RBAC permission
		{"GET", "/api/roles", "list roles"},
		{"POST", "/api/roles", "create role"},
		// No write on Teams
		{"POST", "/api/governance/teams", "create team"},
		{"PUT", "/api/governance/teams/some-id", "update team"},
		{"DELETE", "/api/governance/teams/some-id", "delete team"},
		// No write on VKs
		{"POST", "/api/governance/virtual-keys", "create VK"},
		{"DELETE", "/api/governance/virtual-keys/some-id", "delete VK"},
		// No write on Audit Logs
		{"DELETE", "/api/logs", "delete logs"},
		// No Logs / Dashboard / Providers
		{"GET", "/api/logs", "list logs"},
		{"GET", "/api/providers", "list providers"},
		{"GET", "/api/config", "get config"},
	}
	for _, tc := range denied {
		if CheckRoutePermission(store, "GovernanceViewer", tc.method, tc.path) {
			t.Errorf("GovernanceViewer should NOT be able to %s (%s %s)", tc.desc, tc.method, tc.path)
		}
	}
}

// TestCustomRole_FullGovernanceCRUD tests a role that has full CRUD on all governance resources.
func TestCustomRole_FullGovernanceCRUD(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)
	ctx := context.Background()

	role, _ := store.CreateRole(ctx, "GovernanceAdmin", "Full governance access")
	perms := []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{}
	for _, res := range []Resource{
		ResourceVirtualKeys, ResourceUsers, ResourceTeams,
		ResourceCustomers, ResourceUserProvisioning, ResourceRBAC, ResourceAuditLogs,
	} {
		for _, op := range AllOperations {
			perms = append(perms, struct {
				Resource  string `json:"resource"`
				Operation string `json:"operation"`
			}{string(res), string(op)})
		}
	}
	_ = store.SetRolePermissions(ctx, role.ID, perms)

	routes := []struct {
		method, path string
	}{
		// Virtual Keys
		{"GET", "/api/governance/virtual-keys"},
		{"POST", "/api/governance/virtual-keys"},
		{"PUT", "/api/governance/virtual-keys/123"},
		{"DELETE", "/api/governance/virtual-keys/123"},
		// Users
		{"GET", "/api/enterprise/users"},
		{"POST", "/api/enterprise/users"},
		{"PUT", "/api/enterprise/users/123"},
		{"DELETE", "/api/enterprise/users/123"},
		// Teams
		{"GET", "/api/governance/teams"},
		{"POST", "/api/governance/teams"},
		{"PUT", "/api/governance/teams/123"},
		{"DELETE", "/api/governance/teams/123"},
		// Customers
		{"GET", "/api/governance/customers"},
		{"POST", "/api/governance/customers"},
		{"PUT", "/api/governance/customers/123"},
		{"DELETE", "/api/governance/customers/123"},
		// Roles & Permissions
		{"GET", "/api/roles"},
		{"POST", "/api/roles"},
		{"PUT", "/api/roles/123"},
		{"DELETE", "/api/roles/123"},
		// Audit Logs
		{"GET", "/api/audit-logs"},
		{"GET", "/api/enterprise/audit-logs"},
	}
	for _, tc := range routes {
		if !CheckRoutePermission(store, "GovernanceAdmin", tc.method, tc.path) {
			t.Errorf("GovernanceAdmin should be able to %s %s", tc.method, tc.path)
		}
	}

	// Should NOT have access to non-governance resources
	nonGovRoutes := []struct {
		method, path string
	}{
		{"GET", "/api/providers"},
		{"GET", "/api/config"},
		{"GET", "/api/logs"},
		{"DELETE", "/api/logs"},
		{"GET", "/api/plugins"},
		{"GET", "/api/governance/routing-rules"},
	}
	for _, tc := range nonGovRoutes {
		if CheckRoutePermission(store, "GovernanceAdmin", tc.method, tc.path) {
			t.Errorf("GovernanceAdmin should NOT be able to %s %s (no permission)", tc.method, tc.path)
		}
	}
}

// TestSystemRole_CannotModifyPermissions verifies system roles reject permission changes.
func TestSystemRole_CannotModifyPermissions(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)
	ctx := context.Background()

	for _, roleName := range []string{"Admin", "Developer", "Viewer"} {
		role := store.GetRoleByName(roleName)
		if role == nil {
			t.Fatalf("system role %s not found", roleName)
		}
		err := store.SetRolePermissions(ctx, role.ID, []struct {
			Resource  string `json:"resource"`
			Operation string `json:"operation"`
		}{
			{string(ResourceLogs), string(OpView)},
		})
		if err == nil {
			t.Errorf("SetRolePermissions should fail for system role %s", roleName)
		}
	}

	// Custom role should succeed
	custom, _ := store.CreateRole(ctx, "CustomTest", "test")
	err := store.SetRolePermissions(ctx, custom.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceLogs), string(OpView)},
	})
	if err != nil {
		t.Errorf("SetRolePermissions should succeed for custom role: %v", err)
	}
}

// TestDeveloperRole_AllGovernanceRoutes checks Developer has expected governance access.
func TestDeveloperRole_AllGovernanceRoutes(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)

	allowed := []struct {
		method, path string
	}{
		// VKs - no delete
		{"GET", "/api/governance/virtual-keys"},
		{"POST", "/api/governance/virtual-keys"},
		{"PUT", "/api/governance/virtual-keys/123"},
		// Teams - no delete
		{"GET", "/api/governance/teams"},
		{"POST", "/api/governance/teams"},
		{"PUT", "/api/governance/teams/123"},
		// Customers - no delete
		{"GET", "/api/governance/customers"},
		{"POST", "/api/governance/customers"},
		{"PUT", "/api/governance/customers/123"},
		// Users - view only
		{"GET", "/api/enterprise/users"},
		// RBAC - view only
		{"GET", "/api/roles"},
		// Audit logs - view only
		{"GET", "/api/audit-logs"},
	}
	for _, tc := range allowed {
		if !CheckRoutePermission(store, "Developer", tc.method, tc.path) {
			t.Errorf("Developer should be able to %s %s", tc.method, tc.path)
		}
	}

	denied := []struct {
		method, path string
	}{
		// Users - no create/update/delete
		{"POST", "/api/enterprise/users"},
		{"DELETE", "/api/enterprise/users/123"},
		// RBAC - no create/update/delete
		{"POST", "/api/roles"},
		{"DELETE", "/api/roles/123"},
		// Governance destructive deletes are blocked
		{"DELETE", "/api/governance/virtual-keys/123"},
		{"DELETE", "/api/governance/teams/123"},
		{"DELETE", "/api/governance/customers/123"},
		// Audit logs - no delete
		{"DELETE", "/api/logs"},
	}
	for _, tc := range denied {
		if CheckRoutePermission(store, "Developer", tc.method, tc.path) {
			t.Errorf("Developer should NOT be able to %s %s", tc.method, tc.path)
		}
	}
}

// TestGovernancePageCrossDependencies tests the exact API calls each governance page makes.
// VK page calls: /governance/virtual-keys + /governance/teams + /governance/customers
// Teams page calls: /governance/teams + /governance/virtual-keys + /governance/customers
// Customers page calls: /governance/customers + /governance/teams + /governance/virtual-keys
// Users page calls: /enterprise/users + /roles (for role dropdown)
// RBAC page calls: /roles + /roles/{id}/permissions
func TestGovernancePageCrossDependencies(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)
	ctx := context.Background()

	// Scenario 1: Role with ONLY VirtualKeys:View — can see VK page but NOT teams/customers data
	vkOnly, _ := store.CreateRole(ctx, "VKOnly", "only VK")
	_ = store.SetRolePermissions(ctx, vkOnly.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceVirtualKeys), string(OpView)},
	})

	if !CheckRoutePermission(store, "VKOnly", "GET", "/api/governance/virtual-keys") {
		t.Error("VKOnly: should access VK list")
	}
	if CheckRoutePermission(store, "VKOnly", "GET", "/api/governance/teams") {
		t.Error("VKOnly: should NOT access teams (frontend will skip this call)")
	}
	if CheckRoutePermission(store, "VKOnly", "GET", "/api/governance/customers") {
		t.Error("VKOnly: should NOT access customers (frontend will skip this call)")
	}

	// Scenario 2: Role with VK + Teams + Customers View — full VK page experience
	vkFull, _ := store.CreateRole(ctx, "VKFull", "VK with related data")
	_ = store.SetRolePermissions(ctx, vkFull.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceVirtualKeys), string(OpView)},
		{string(ResourceTeams), string(OpView)},
		{string(ResourceCustomers), string(OpView)},
	})

	for _, path := range []string{
		"/api/governance/virtual-keys",
		"/api/governance/teams",
		"/api/governance/customers",
	} {
		if !CheckRoutePermission(store, "VKFull", "GET", path) {
			t.Errorf("VKFull: should access %s", path)
		}
	}
	// But no write access
	if CheckRoutePermission(store, "VKFull", "POST", "/api/governance/virtual-keys") {
		t.Error("VKFull: should NOT create VKs (view-only)")
	}

	// Scenario 3: Role with Users:View — can see users page, needs RBAC:View for role dropdown
	usersOnly, _ := store.CreateRole(ctx, "UsersOnly", "only users view")
	_ = store.SetRolePermissions(ctx, usersOnly.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceUsers), string(OpView)},
	})

	if !CheckRoutePermission(store, "UsersOnly", "GET", "/api/enterprise/users") {
		t.Error("UsersOnly: should access user list")
	}
	if CheckRoutePermission(store, "UsersOnly", "GET", "/api/roles") {
		t.Error("UsersOnly: should NOT access roles (no RBAC:View)")
	}

	// Scenario 4: Role with Users:View + RBAC:View — users page with role dropdown
	usersWithRoles, _ := store.CreateRole(ctx, "UsersWithRoles", "users + roles view")
	_ = store.SetRolePermissions(ctx, usersWithRoles.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceUsers), string(OpView)},
		{string(ResourceRBAC), string(OpView)},
	})

	if !CheckRoutePermission(store, "UsersWithRoles", "GET", "/api/enterprise/users") {
		t.Error("UsersWithRoles: should access user list")
	}
	if !CheckRoutePermission(store, "UsersWithRoles", "GET", "/api/roles") {
		t.Error("UsersWithRoles: should access roles list")
	}

	// Scenario 5: Teams:View only — can see teams page, VK/customer columns will be empty
	teamsOnly, _ := store.CreateRole(ctx, "TeamsOnly", "only teams")
	_ = store.SetRolePermissions(ctx, teamsOnly.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceTeams), string(OpView)},
	})

	if !CheckRoutePermission(store, "TeamsOnly", "GET", "/api/governance/teams") {
		t.Error("TeamsOnly: should access teams list")
	}
	if CheckRoutePermission(store, "TeamsOnly", "GET", "/api/governance/virtual-keys") {
		t.Error("TeamsOnly: should NOT access VKs")
	}
	if CheckRoutePermission(store, "TeamsOnly", "GET", "/api/governance/customers") {
		t.Error("TeamsOnly: should NOT access customers")
	}

	// Scenario 6: Budgets/rate-limits require Governance:View (separate from VK/Teams/Customers)
	if CheckRoutePermission(store, "VKFull", "GET", "/api/governance/budgets") {
		t.Error("VKFull: should NOT access budgets (no Governance:View)")
	}
	if CheckRoutePermission(store, "VKFull", "GET", "/api/governance/rate-limits") {
		t.Error("VKFull: should NOT access rate-limits (no Governance:View)")
	}

	// Scenario 7: Team member management (/api/enterprise/teams/) needs Teams permission
	if CheckRoutePermission(store, "VKOnly", "GET", "/api/enterprise/teams/some-team-id") {
		t.Error("VKOnly: should NOT access team members")
	}
	if !CheckRoutePermission(store, "TeamsOnly", "GET", "/api/enterprise/teams/some-team-id") {
		t.Error("TeamsOnly: should access team members")
	}

	// Scenario 8: UserProvisioning:View should cover the current SCIM page data dependencies
	scimOnly, _ := store.CreateRole(ctx, "SCIMOnly", "user provisioning only")
	_ = store.SetRolePermissions(ctx, scimOnly.ID, []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}{
		{string(ResourceUserProvisioning), string(OpView)},
	})

	for _, path := range []string{
		"/api/enterprise/users/stats",
		"/api/enterprise/users",
		"/api/roles",
		"/api/governance/teams",
	} {
		if !CheckRoutePermission(store, "SCIMOnly", "GET", path) {
			t.Errorf("SCIMOnly: should access %s", path)
		}
	}
	if CheckRoutePermission(store, "SCIMOnly", "GET", "/api/governance/virtual-keys") {
		t.Error("SCIMOnly: should NOT access virtual keys")
	}
}

// TestViewerRole_StrictlyLimited checks Viewer can only access dashboard, logs, audit logs.
func TestViewerRole_StrictlyLimited(t *testing.T) {
	db := setupRoleTestDB(t)
	store, _ := NewRoleStore(db)

	allowed := []struct {
		method, path string
	}{
		{"GET", "/api/logs"},
		{"GET", "/api/logs/stats"},
		{"GET", "/api/logs/histogram"},
		{"GET", "/api/audit-logs"},
		{"GET", "/api/enterprise/audit-logs"},
	}
	for _, tc := range allowed {
		if !CheckRoutePermission(store, "Viewer", tc.method, tc.path) {
			t.Errorf("Viewer should be able to %s %s", tc.method, tc.path)
		}
	}

	denied := []struct {
		method, path string
	}{
		// No governance access at all
		{"GET", "/api/governance/virtual-keys"},
		{"GET", "/api/governance/teams"},
		{"GET", "/api/governance/customers"},
		{"GET", "/api/enterprise/users"},
		{"GET", "/api/roles"},
		// No model/provider access
		{"GET", "/api/providers"},
		{"GET", "/api/models"},
		{"GET", "/api/config"},
		// No write on anything
		{"DELETE", "/api/logs"},
		{"DELETE", "/api/logs"},
		{"POST", "/api/governance/virtual-keys"},
	}
	for _, tc := range denied {
		if CheckRoutePermission(store, "Viewer", tc.method, tc.path) {
			t.Errorf("Viewer should NOT be able to %s %s", tc.method, tc.path)
		}
	}
}
