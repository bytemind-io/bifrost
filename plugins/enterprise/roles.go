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
	ResourceLogs             Resource = "Logs"
	ResourceModelProvider    Resource = "ModelProvider"
	ResourceObservability    Resource = "Observability"
	ResourcePlugins          Resource = "Plugins"
	ResourceVirtualKeys      Resource = "VirtualKeys"
	ResourceUserProvisioning Resource = "UserProvisioning"
	ResourceUsers            Resource = "Users"
	ResourceAuditLogs        Resource = "AuditLogs"
	ResourceGuardrailsConfig Resource = "GuardrailsConfig"
	ResourceGuardrailRules   Resource = "GuardrailRules"
	ResourceCluster          Resource = "Cluster"
	ResourceSettings         Resource = "Settings"
	ResourceMCPGateway       Resource = "MCPGateway"
	ResourceAdaptiveRouter   Resource = "AdaptiveRouter"
)

// AllResources lists every protected resource.
var AllResources = []Resource{
	ResourceLogs,
	ResourceModelProvider,
	ResourceObservability,
	ResourcePlugins,
	ResourceVirtualKeys,
	ResourceUserProvisioning,
	ResourceUsers,
	ResourceAuditLogs,
	ResourceGuardrailsConfig,
	ResourceGuardrailRules,
	ResourceCluster,
	ResourceSettings,
	ResourceMCPGateway,
	ResourceAdaptiveRouter,
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

func (s *RoleStore) seedSystemRoles() error {
	systemRoles := []struct {
		name        string
		description string
		permissions map[Resource][]Operation
	}{
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
			description: "CRUD access to technical resources, view access to logs and cluster",
			permissions: map[Resource][]Operation{
				ResourceLogs:             {OpView},
				ResourceModelProvider:    {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceObservability:    {OpView},
				ResourcePlugins:          {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceVirtualKeys:      {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceUsers:            {OpView},
				ResourceAuditLogs:        {OpView},
				ResourceGuardrailsConfig: {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceGuardrailRules:   {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceCluster:          {OpView},
				ResourceSettings:         {OpView},
				ResourceMCPGateway:       {OpView, OpCreate, OpUpdate, OpDelete},
				ResourceAdaptiveRouter:   {OpView},
			},
		},
		{
			name:        "Viewer",
			description: "Read-only access to all resources",
			permissions: func() map[Resource][]Operation {
				p := make(map[Resource][]Operation)
				for _, r := range AllResources {
					p[r] = []Operation{OpView}
				}
				return p
			}(),
		},
	}

	for _, sr := range systemRoles {
		var existing TableRole
		if err := s.db.Where("name = ? AND is_system = ?", sr.name, true).First(&existing).Error; err == nil {
			continue // Already exists
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
		nameMap[r.Name] = r
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

// frontendResourceAliases maps additional frontend resource names to backend resources.
// The frontend sidebar checks these resources; we derive their permissions from related backend resources.
var frontendResourceAliases = map[string]Resource{
	"Customers":                ResourceVirtualKeys,      // Customers are part of VK governance
	"Teams":                    ResourceVirtualKeys,      // Teams are part of VK governance
	"RBAC":                     ResourceUsers,            // RBAC management requires Users access
	"Governance":               ResourceVirtualKeys,      // Governance parent menu
	"RoutingRules":             ResourceAdaptiveRouter,   // Routing rules use AdaptiveRouter
	"GuardrailsProviders":      ResourceGuardrailsConfig, // Guardrails providers use same resource
	"GuardrailRules":           ResourceGuardrailRules,   // Direct mapping (already in AllResources but frontend uses this key)
	"PIIRedactor":              ResourceGuardrailsConfig, // PII redactor is part of guardrails
	"PromptRepository":         ResourcePlugins,          // Prompts are managed as plugins
	"PromptDeploymentStrategy": ResourcePlugins,          // Prompt deployments are part of plugins
	"APIKeys":                  ResourceSettings,         // API keys are settings-level
	"Invitations":              ResourceUsers,            // Invitations relate to users
	"Dashboard":                ResourceObservability,    // Dashboard is observability
}

// GetPermissionsMap returns a flat map of resource->operation->bool for frontend RBAC context.
// Includes both backend resources and frontend-specific aliases.
func (s *RoleStore) GetPermissionsMap(roleNameOrID string) map[string]map[string]bool {
	result := make(map[string]map[string]bool)

	// Backend resources
	for _, res := range AllResources {
		resMap := make(map[string]bool)
		for _, op := range AllOperations {
			resMap[string(op)] = s.IsAllowed(roleNameOrID, res, op)
		}
		result[string(res)] = resMap
	}

	// Frontend aliases — derive from mapped backend resource
	for alias, backendRes := range frontendResourceAliases {
		if _, exists := result[alias]; exists {
			continue // Don't overwrite if already present
		}
		resMap := make(map[string]bool)
		for _, op := range AllOperations {
			resMap[string(op)] = s.IsAllowed(roleNameOrID, backendRes, op)
		}
		result[alias] = resMap
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

// SetRolePermissions replaces all permissions for a role.
func (s *RoleStore) SetRolePermissions(ctx context.Context, roleID string, permissions []struct {
	Resource  string `json:"resource"`
	Operation string `json:"operation"`
}) error {
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
