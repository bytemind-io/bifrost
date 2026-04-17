// Package enterprise provides multi-tenancy with dynamic RBAC for Bifrost.
package enterprise

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Resource represents a protected system resource.
type Resource string

const (
	ResourceLogs                     Resource = "Logs"
	ResourceModelProvider            Resource = "ModelProvider"
	ResourceObservability            Resource = "Observability"
	ResourcePlugins                  Resource = "Plugins"
	ResourceVirtualKeys              Resource = "VirtualKeys"
	ResourceCustomers                Resource = "Customers"
	ResourceTeams                    Resource = "Teams"
	ResourceRBAC                     Resource = "RBAC"
	ResourceGovernance               Resource = "Governance"
	ResourceUserProvisioning         Resource = "UserProvisioning"
	ResourceUsers                    Resource = "Users"
	ResourceAuditLogs                Resource = "AuditLogs"
	ResourceDashboard                Resource = "Dashboard"
	ResourceGuardrailsConfig         Resource = "GuardrailsConfig"
	ResourceGuardrailsProviders      Resource = "GuardrailsProviders"
	ResourceGuardrailRules           Resource = "GuardrailRules"
	ResourcePIIRedactor              Resource = "PIIRedactor"
	ResourceCluster                  Resource = "Cluster"
	ResourceSettings                 Resource = "Settings"
	ResourceAPIKeys                  Resource = "APIKeys"
	ResourceInvitations              Resource = "Invitations"
	ResourceMCPGateway               Resource = "MCPGateway"
	ResourceAdaptiveRouter           Resource = "AdaptiveRouter"
	ResourceRoutingRules             Resource = "RoutingRules"
	ResourcePromptRepository         Resource = "PromptRepository"
	ResourcePromptDeploymentStrategy Resource = "PromptDeploymentStrategy"
)

// AllResources lists every protected resource.
var AllResources = []Resource{
	ResourceLogs,
	ResourceModelProvider,
	ResourceObservability,
	ResourcePlugins,
	ResourceVirtualKeys,
	ResourceCustomers,
	ResourceTeams,
	ResourceRBAC,
	ResourceGovernance,
	ResourceUserProvisioning,
	ResourceUsers,
	ResourceAuditLogs,
	ResourceDashboard,
	ResourceGuardrailsConfig,
	ResourceGuardrailsProviders,
	ResourceGuardrailRules,
	ResourcePIIRedactor,
	ResourceCluster,
	ResourceSettings,
	ResourceAPIKeys,
	ResourceInvitations,
	ResourceMCPGateway,
	ResourceAdaptiveRouter,
	ResourceRoutingRules,
	ResourcePromptRepository,
	ResourcePromptDeploymentStrategy,
}

// Operation represents an action on a resource.
type Operation string

const (
	OpView   Operation = "View"
	OpCreate Operation = "Create"
	OpUpdate Operation = "Update"
	OpDelete Operation = "Delete"
)

// AllOperations lists every operation.
var AllOperations = []Operation{OpView, OpCreate, OpUpdate, OpDelete}

// ---------- DB Models ----------

// TableRole represents a role (system or custom).
type TableRole struct {
	ID          string         `gorm:"primaryKey;type:varchar(255)" json:"id"`
	Name        string         `gorm:"type:varchar(100);uniqueIndex;not null" json:"name"`
	Description string         `gorm:"type:text" json:"description"`
	IsSystem    bool           `gorm:"default:false" json:"is_system"`
	CreatedAt   time.Time      `gorm:"," json:"created_at"`
	UpdatedAt   time.Time      `gorm:"," json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

func (TableRole) TableName() string { return "enterprise_roles" }

// TableRolePermission stores which operations a role has on a resource.
type TableRolePermission struct {
	ID        string `gorm:"primaryKey;type:varchar(255)" json:"id"`
	RoleID    string `gorm:"type:varchar(255);index;not null" json:"role_id"`
	Resource  string `gorm:"type:varchar(100);not null" json:"resource"`
	Operation string `gorm:"type:varchar(50);not null" json:"operation"`
}

func (TableRolePermission) TableName() string { return "enterprise_role_permissions" }

// ---------- RoleStore ----------

// RoleStore manages roles and permissions with in-memory cache.
type RoleStore struct {
	db     *gorm.DB
	mu     sync.RWMutex
	cache  map[string]map[Resource]map[Operation]bool // roleID -> resource -> operation -> allowed
	roles  map[string]*TableRole                      // roleID -> role
	byName map[string]*TableRole                      // roleName -> role
}

type systemRoleDefinition struct {
	name        string
	description string
	permissions map[Resource][]Operation
}

// NewRoleStore creates a new role store, runs migrations, seeds system roles, and loads cache.
func NewRoleStore(db *gorm.DB) (*RoleStore, error) {
	if err := db.AutoMigrate(&TableRole{}, &TableRolePermission{}); err != nil {
		return nil, fmt.Errorf("failed to migrate role tables: %w", err)
	}
	s := &RoleStore{db: db}
	if err := s.seedSystemRoles(); err != nil {
		return nil, err
	}
	if err := s.reloadCache(); err != nil {
		return nil, err
	}
	return s, nil
}

// ---------- System role seeding ----------

func permissionKey(resource Resource, operation Operation) string {
	return string(resource) + ":" + string(operation)
}

func systemRoleDefinitions() []systemRoleDefinition {
	return []systemRoleDefinition{
		{
			name:        "Admin",
			description: "Full access to all resources and operations",
			permissions: func() map[Resource][]Operation {
				p := make(map[Resource][]Operation)
				for _, r := range AllResources {
					p[r] = []Operation{OpView, OpCreate, OpUpdate, OpDelete}
				}
				return p
			}(),
		},
		{
			name:        "Developer",
			description: "Technical resource management without destructive governance deletes, plus view access to logs and cluster",
			permissions: map[Resource][]Operation{
				ResourceLogs:                     {OpView},
				ResourceModelProvider:            {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceObservability:            {OpView},
				ResourcePlugins:                  {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceVirtualKeys:              {OpView, OpCreate, OpUpdate},
				ResourceCustomers:                {OpView, OpCreate, OpUpdate},
				ResourceTeams:                    {OpView, OpCreate, OpUpdate},
				ResourceGovernance:               {OpView},
				ResourceUsers:                    {OpView},
				ResourceRBAC:                     {OpView},
				ResourceAuditLogs:                {OpView},
				ResourceDashboard:                {OpView},
				ResourceGuardrailsConfig:         {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceGuardrailsProviders:      {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceGuardrailRules:           {OpView, OpCreate, OpUpdate, OpDelete},
				ResourcePIIRedactor:              {OpView},
				ResourceCluster:                  {OpView},
				ResourceSettings:                 {OpView},
				ResourceAPIKeys:                  {OpView},
				ResourceMCPGateway:               {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceAdaptiveRouter:           {OpView},
				ResourceRoutingRules:             {OpView, OpCreate, OpUpdate, OpDelete},
				ResourcePromptRepository:         {OpView, OpCreate, OpUpdate, OpDelete},
				ResourcePromptDeploymentStrategy: {OpView, OpCreate, OpUpdate, OpDelete},
			},
		},
		{
			name:        "Viewer",
			description: "Read-only access to dashboard, logs, and audit logs",
			permissions: map[Resource][]Operation{
				ResourceDashboard: {OpView},
				ResourceLogs:      {OpView},
				ResourceAuditLogs: {OpView},
			},
		},
	}
}

// syncSystemRole forces system role permissions to match the code definition exactly.
// Any extra permissions (e.g. from a previous code version) are removed.
func (s *RoleStore) syncSystemRole(role *TableRole, definition systemRoleDefinition) error {
	updates := map[string]interface{}{
		"description": definition.description,
		"updated_at":  time.Now(),
	}
	if err := s.db.Model(&TableRole{}).Where("id = ?", role.ID).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update system role %s metadata: %w", definition.name, err)
	}

	var existingPerms []TableRolePermission
	if err := s.db.Where("role_id = ?", role.ID).Find(&existingPerms).Error; err != nil {
		return fmt.Errorf("failed to load permissions for role %s: %w", definition.name, err)
	}

	desired := make(map[string]struct{})
	for resource, operations := range definition.permissions {
		for _, operation := range operations {
			desired[permissionKey(resource, operation)] = struct{}{}
		}
	}

	existing := make(map[string]TableRolePermission)
	for _, perm := range existingPerms {
		key := permissionKey(Resource(perm.Resource), Operation(perm.Operation))
		if _, seen := existing[key]; !seen {
			existing[key] = perm
		}
	}

	// Remove permissions not in definition
	for key, perm := range existing {
		if _, ok := desired[key]; ok {
			continue
		}
		if err := s.db.Delete(&TableRolePermission{}, "id = ?", perm.ID).Error; err != nil {
			return fmt.Errorf("failed to remove stale permission %s from role %s: %w", key, definition.name, err)
		}
	}

	// Add missing permissions from definition
	for resource, operations := range definition.permissions {
		for _, operation := range operations {
			key := permissionKey(resource, operation)
			if _, ok := existing[key]; ok {
				continue
			}
			perm := TableRolePermission{
				ID:        uuid.New().String(),
				RoleID:    role.ID,
				Resource:  string(resource),
				Operation: string(operation),
			}
			if err := s.db.Create(&perm).Error; err != nil {
				return fmt.Errorf("failed to create permission %s for role %s: %w", key, definition.name, err)
			}
		}
	}

	return nil
}

func (s *RoleStore) seedSystemRoles() error {
	for _, sr := range systemRoleDefinitions() {
		var existing TableRole
		if err := s.db.Where("name = ? AND is_system = ?", sr.name, true).First(&existing).Error; err == nil {
			if err := s.syncSystemRole(&existing, sr); err != nil {
				return err
			}
			continue
		}
		role := TableRole{
			ID:          uuid.New().String(),
			Name:        sr.name,
			Description: sr.description,
			IsSystem:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		if err := s.db.Create(&role).Error; err != nil {
			return fmt.Errorf("failed to seed role %s: %w", sr.name, err)
		}
		for res, ops := range sr.permissions {
			for _, op := range ops {
				perm := TableRolePermission{
					ID:        uuid.New().String(),
					RoleID:    role.ID,
					Resource:  string(res),
					Operation: string(op),
				}
				if err := s.db.Create(&perm).Error; err != nil {
					return fmt.Errorf("failed to seed permission: %w", err)
				}
			}
		}
	}
	return nil
}

// ---------- Cache ----------

func (s *RoleStore) reloadCache() error {
	var roles []TableRole
	if err := s.db.Find(&roles).Error; err != nil {
		return err
	}
	var perms []TableRolePermission
	if err := s.db.Find(&perms).Error; err != nil {
		return err
	}

	cache := make(map[string]map[Resource]map[Operation]bool)
	roleMap := make(map[string]*TableRole)
	nameMap := make(map[string]*TableRole)

	for i := range roles {
		r := &roles[i]
		roleMap[r.ID] = r
		nameMap[strings.ToLower(r.Name)] = r
		cache[r.ID] = make(map[Resource]map[Operation]bool)
	}
	for _, p := range perms {
		if _, ok := cache[p.RoleID]; !ok {
			continue
		}
		res := Resource(p.Resource)
		if cache[p.RoleID][res] == nil {
			cache[p.RoleID][res] = make(map[Operation]bool)
		}
		cache[p.RoleID][res][Operation(p.Operation)] = true
	}

	s.mu.Lock()
	s.cache = cache
	s.roles = roleMap
	s.byName = nameMap
	s.mu.Unlock()
	return nil
}

// ---------- Query ----------

// IsAllowed checks if a role (by name or ID) has permission for a resource+operation.
func (s *RoleStore) IsAllowed(roleNameOrID string, resource Resource, operation Operation) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Resolve by name (case-insensitive) first, then by ID
	role, ok := s.byName[strings.ToLower(roleNameOrID)]
	if !ok {
		role, ok = s.roles[roleNameOrID]
	}
	if !ok {
		return false
	}
	perms, ok := s.cache[role.ID]
	if !ok {
		return false
	}
	if resPerms, ok := perms[resource]; ok {
		return resPerms[operation]
	}
	return false
}

// GetPermissionsMap returns a flat map of resource->operation->bool for frontend RBAC context.
func (s *RoleStore) GetPermissionsMap(roleNameOrID string) map[string]map[string]bool {
	result := make(map[string]map[string]bool)

	for _, res := range AllResources {
		resMap := make(map[string]bool)
		for _, op := range AllOperations {
			resMap[string(op)] = s.IsAllowed(roleNameOrID, res, op)
		}
		result[string(res)] = resMap
	}

	return result
}

// GetRoleByName looks up a role by name.
func (s *RoleStore) GetRoleByName(name string) *TableRole {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byName[strings.ToLower(name)]
}

// ---------- CRUD ----------

// RoleResponse is the API response for a role including permission count.
type RoleResponse struct {
	TableRole
	PermissionCount int `json:"permission_count"`
}

// ListRoles returns all roles with permission counts.
func (s *RoleStore) ListRoles(ctx context.Context) ([]RoleResponse, error) {
	var roles []TableRole
	if err := s.db.WithContext(ctx).Order("is_system DESC, name ASC").Find(&roles).Error; err != nil {
		return nil, err
	}
	result := make([]RoleResponse, len(roles))
	s.mu.RLock()
	for i, r := range roles {
		count := 0
		if perms, ok := s.cache[r.ID]; ok {
			for _, ops := range perms {
				count += len(ops)
			}
		}
		result[i] = RoleResponse{TableRole: r, PermissionCount: count}
	}
	s.mu.RUnlock()
	return result, nil
}

// GetRole returns a single role by ID.
func (s *RoleStore) GetRole(ctx context.Context, id string) (*TableRole, error) {
	var role TableRole
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&role).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

// CreateRole creates a custom role.
func (s *RoleStore) CreateRole(ctx context.Context, name, description string) (*TableRole, error) {
	role := &TableRole{
		ID:          uuid.New().String(),
		Name:        name,
		Description: description,
		IsSystem:    false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := s.db.WithContext(ctx).Create(role).Error; err != nil {
		return nil, err
	}
	_ = s.reloadCache()
	return role, nil
}

// UpdateRole updates a custom role's name/description.
func (s *RoleStore) UpdateRole(ctx context.Context, id, name, description string) (*TableRole, error) {
	role, err := s.GetRole(ctx, id)
	if err != nil {
		return nil, err
	}
	if role.IsSystem {
		// System roles can have permissions changed but not be renamed
	}
	updates := map[string]interface{}{"updated_at": time.Now()}
	if name != "" && !role.IsSystem {
		updates["name"] = name
	}
	if description != "" {
		updates["description"] = description
	}
	if err := s.db.WithContext(ctx).Model(&TableRole{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, err
	}
	_ = s.reloadCache()
	return s.GetRole(ctx, id)
}

// DeleteRole deletes a custom role. System roles cannot be deleted.
func (s *RoleStore) DeleteRole(ctx context.Context, id string) error {
	role, err := s.GetRole(ctx, id)
	if err != nil {
		return err
	}
	if role.IsSystem {
		return fmt.Errorf("cannot delete system role")
	}
	// Delete permissions first
	s.db.WithContext(ctx).Where("role_id = ?", id).Delete(&TableRolePermission{})
	if err := s.db.WithContext(ctx).Where("id = ?", id).Delete(&TableRole{}).Error; err != nil {
		return err
	}
	_ = s.reloadCache()
	return nil
}

// ---------- Permission management ----------

// GetRolePermissions returns all permissions for a role.
func (s *RoleStore) GetRolePermissions(ctx context.Context, roleID string) ([]TableRolePermission, error) {
	var perms []TableRolePermission
	if err := s.db.WithContext(ctx).Where("role_id = ?", roleID).Order("resource, operation").Find(&perms).Error; err != nil {
		return nil, err
	}
	return perms, nil
}

// SetRolePermissions replaces all permissions for a role. System roles cannot be modified.
func (s *RoleStore) SetRolePermissions(ctx context.Context, roleID string, permissions []struct {
	Resource  string `json:"resource"`
	Operation string `json:"operation"`
}) error {
	role, err := s.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}
	if role.IsSystem {
		return fmt.Errorf("cannot modify permissions of system role %q", role.Name)
	}
	// Delete existing
	if err := s.db.WithContext(ctx).Where("role_id = ?", roleID).Delete(&TableRolePermission{}).Error; err != nil {
		return err
	}
	// Insert new
	for _, p := range permissions {
		perm := TableRolePermission{
			ID:        uuid.New().String(),
			RoleID:    roleID,
			Resource:  p.Resource,
			Operation: p.Operation,
		}
		if err := s.db.WithContext(ctx).Create(&perm).Error; err != nil {
			return err
		}
	}
	_ = s.reloadCache()
	return nil
}
