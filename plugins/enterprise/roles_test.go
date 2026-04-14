package enterprise

import (
	"context"
	"testing"

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

	// Developer can CRUD VirtualKeys
	if !store.IsAllowed("Developer", ResourceVirtualKeys, OpView) {
		t.Error("Developer should be able to view VirtualKeys")
	}
	if !store.IsAllowed("Developer", ResourceVirtualKeys, OpCreate) {
		t.Error("Developer should be able to create VirtualKeys")
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

	for _, res := range AllResources {
		if !store.IsAllowed("Viewer", res, OpView) {
			t.Errorf("Viewer should be able to view %s", res)
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
	if !viewerPerms["VirtualKeys"]["View"] {
		t.Error("Viewer should have VirtualKeys:View = true")
	}
	if viewerPerms["VirtualKeys"]["Create"] {
		t.Error("Viewer should NOT have VirtualKeys:Create")
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

	// Viewer can read but not write
	if !CheckRoutePermission(store, "Viewer", "GET", "/api/governance/virtual-keys") {
		t.Error("Viewer should be able to read VKs")
	}
	if CheckRoutePermission(store, "Viewer", "POST", "/api/governance/virtual-keys") {
		t.Error("Viewer should NOT be able to create VKs")
	}
}
