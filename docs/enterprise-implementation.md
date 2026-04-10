# Bifrost Enterprise Multi-Tenancy Implementation Document

## 1. Overview

### Goals
- Add multi-tenancy with fixed roles (Admin/TeamManager/User/Viewer)
- Track per-user API consumption and costs
- Role-based UI visibility (different users see different pages)
- Zero modification to core/, framework/, existing plugins
- Compatible with upstream merges

### Architecture

```
                     ┌─────────────────────────────────┐
                     │       New: plugins/enterprise/    │
                     │  (Go module, go.work mounted)     │
                     ├─────────────────────────────────┤
                     │  roles.go     → 4 fixed roles    │
                     │  users.go     → User CRUD logic  │
                     │  audit.go     → Audit log logic  │
                     │  middleware.go → RBAC checker     │
                     └──────────┬────────────────────────┘
                                │ imported by
                     ┌──────────▼────────────────────────┐
                     │  Modified: transports/bifrost-http/ │
                     │  + handlers/enterprise.go (new)    │
                     │  ~ server.go (+5 lines)            │
                     │  ~ middlewares.go (+15 lines)       │
                     └────────────────────────────────────┘

                     ┌─────────────────────────────────┐
                     │   New: ui/app/enterprise/         │
                     │   (replaces _fallbacks)           │
                     ├─────────────────────────────────┤
                     │  lib/contexts/rbacContext.tsx     │
                     │  lib/store/apis/index.ts          │
                     │  lib/store/slices/index.ts        │
                     │  lib/store/utils/tokenManager.ts  │
                     │  lib/store/utils/baseQueryWithRefresh.ts │
                     │  lib/store/index.ts               │
                     │  lib/index.ts                     │
                     │  lib/types/largePayload.ts        │
                     │  components/login/loginView.tsx    │
                     │  components/user-groups/usersView.tsx │
                     │  components/rbac/rbacView.tsx      │
                     │  components/audit-logs/auditLogsView.tsx │
                     │  components/scim/scimView.tsx      │
                     │  + stub components (from _fallbacks) │
                     └─────────────────────────────────┘
```

---

## 2. Backend: plugins/enterprise/ Go Module

### 2.1 go.mod

```go
module github.com/workpieces/bifrost/plugins/enterprise

go 1.26.1

require (
    github.com/google/uuid v1.6.0
    github.com/maximhq/bifrost/core v1.4.12
    github.com/maximhq/bifrost/framework v1.2.31
    github.com/valyala/fasthttp v1.68.0
    golang.org/x/crypto v0.49.0
    gorm.io/gorm v1.31.1
)
```

### 2.2 roles.go - Fixed Role Definitions

```go
package enterprise

// Role represents a user role in the system
type Role string

const (
    RoleAdmin       Role = "admin"
    RoleTeamManager Role = "team_manager"
    RoleUser        Role = "user"
    RoleViewer      Role = "viewer"
)

// Resource represents a system resource
type Resource string

const (
    ResourceAll            Resource = "*"
    ResourceVirtualKeys    Resource = "VirtualKeys"
    ResourceTeams          Resource = "Teams"
    ResourceCustomers      Resource = "Customers"
    ResourceUsers          Resource = "Users"
    ResourceLogs           Resource = "Logs"
    ResourceObservability  Resource = "Observability"
    ResourceSettings       Resource = "Settings"
    ResourceModelProvider  Resource = "ModelProvider"
    ResourcePlugins        Resource = "Plugins"
    ResourceMCPGateway     Resource = "MCPGateway"
    ResourceAuditLogs      Resource = "AuditLogs"
    ResourceRBAC           Resource = "RBAC"
    ResourceGovernance     Resource = "Governance"
    ResourceRoutingRules   Resource = "RoutingRules"
)

// Operation represents an action on a resource
type Operation string

const (
    OpAll    Operation = "*"
    OpRead   Operation = "Read"
    OpView   Operation = "View"
    OpCreate Operation = "Create"
    OpUpdate Operation = "Update"
    OpDelete Operation = "Delete"
)

// RolePermissions defines what each role can do
// Admin: everything
// TeamManager: manage own team's VKs, members, view usage
// User: view own VKs and logs only
// Viewer: read-only access
var RolePermissions = map[Role]map[Resource][]Operation{
    RoleAdmin: {
        ResourceAll: {OpAll},
    },
    RoleTeamManager: {
        ResourceVirtualKeys:   {OpRead, OpCreate, OpUpdate, OpDelete}, // scoped to own team
        ResourceTeams:         {OpRead, OpUpdate},                      // own team only
        ResourceUsers:         {OpRead},                                // own team members
        ResourceLogs:          {OpRead},
        ResourceObservability: {OpRead},
        ResourceGovernance:    {OpRead},
    },
    RoleUser: {
        ResourceVirtualKeys: {OpRead}, // own keys only
        ResourceLogs:        {OpRead}, // own logs only
        ResourceGovernance:  {OpRead},
    },
    RoleViewer: {
        ResourceAll: {OpRead, OpView},
    },
}

// RoleInfo describes a role for API responses
type RoleInfo struct {
    Name        Role              `json:"name"`
    Label       string            `json:"label"`
    Description string            `json:"description"`
    Permissions map[Resource][]Operation `json:"permissions"`
}

// GetAllRoles returns info about all available roles
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

// IsAllowed checks if a role has permission for a given resource+operation
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

// GetPermissionsMap returns a flat map of resource->operation->bool for frontend RBAC context
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
```

### 2.3 users.go - User Model & CRUD

```go
package enterprise

import (
    "context"
    "fmt"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"
)

// TableUser represents a user in the enterprise system
type TableUser struct {
    ID        string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
    Email     string    `gorm:"uniqueIndex;type:varchar(255);not null" json:"email"`
    Name      string    `gorm:"type:varchar(255);not null" json:"name"`
    Password  string    `gorm:"type:text;not null" json:"-"` // never expose in JSON
    Role      string    `gorm:"type:varchar(50);not null;default:'user'" json:"role"`
    TeamID    *string   `gorm:"type:varchar(255);index" json:"team_id,omitempty"`
    IsActive  bool      `gorm:"default:true" json:"is_active"`
    CreatedAt time.Time `gorm:"index;not null" json:"created_at"`
    UpdatedAt time.Time `gorm:"index;not null" json:"updated_at"`
}

func (TableUser) TableName() string { return "enterprise_users" }

// UserStore provides CRUD operations for users
type UserStore struct {
    db *gorm.DB
}

func NewUserStore(db *gorm.DB) (*UserStore, error) {
    if err := db.AutoMigrate(&TableUser{}); err != nil {
        return nil, fmt.Errorf("failed to migrate users table: %w", err)
    }
    return &UserStore{db: db}, nil
}

// CreateUser creates a new user with hashed password
func (s *UserStore) CreateUser(ctx context.Context, email, name, password string, role Role, teamID *string) (*TableUser, error) {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return nil, fmt.Errorf("failed to hash password: %w", err)
    }

    user := &TableUser{
        ID:        uuid.New().String(),
        Email:     email,
        Name:      name,
        Password:  string(hashedPassword),
        Role:      string(role),
        TeamID:    teamID,
        IsActive:  true,
        CreatedAt: time.Now(),
        UpdatedAt: time.Now(),
    }

    if err := s.db.WithContext(ctx).Create(user).Error; err != nil {
        return nil, fmt.Errorf("failed to create user: %w", err)
    }
    return user, nil
}

// GetUser retrieves a user by ID
func (s *UserStore) GetUser(ctx context.Context, id string) (*TableUser, error) {
    var user TableUser
    if err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error; err != nil {
        return nil, err
    }
    return &user, nil
}

// GetUserByEmail retrieves a user by email
func (s *UserStore) GetUserByEmail(ctx context.Context, email string) (*TableUser, error) {
    var user TableUser
    if err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
        return nil, err
    }
    return &user, nil
}

// ListUsers returns paginated user list, optionally filtered by team
func (s *UserStore) ListUsers(ctx context.Context, teamID *string, search string, offset, limit int) ([]TableUser, int64, error) {
    var users []TableUser
    var total int64

    query := s.db.WithContext(ctx).Model(&TableUser{})
    if teamID != nil {
        query = query.Where("team_id = ?", *teamID)
    }
    if search != "" {
        query = query.Where("name LIKE ? OR email LIKE ?", "%"+search+"%", "%"+search+"%")
    }

    if err := query.Count(&total).Error; err != nil {
        return nil, 0, err
    }
    if err := query.Order("created_at DESC").Offset(offset).Limit(limit).Find(&users).Error; err != nil {
        return nil, 0, err
    }
    return users, total, nil
}

// UpdateUser updates user fields (name, role, team, active status)
func (s *UserStore) UpdateUser(ctx context.Context, id string, updates map[string]interface{}) (*TableUser, error) {
    updates["updated_at"] = time.Now()
    if err := s.db.WithContext(ctx).Model(&TableUser{}).Where("id = ?", id).Updates(updates).Error; err != nil {
        return nil, err
    }
    return s.GetUser(ctx, id)
}

// UpdatePassword updates user password
func (s *UserStore) UpdatePassword(ctx context.Context, id, newPassword string) error {
    hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
    if err != nil {
        return err
    }
    return s.db.WithContext(ctx).Model(&TableUser{}).Where("id = ?", id).Updates(map[string]interface{}{
        "password":   string(hashed),
        "updated_at": time.Now(),
    }).Error
}

// DeleteUser soft-deletes a user by setting is_active=false
func (s *UserStore) DeleteUser(ctx context.Context, id string) error {
    return s.db.WithContext(ctx).Where("id = ?", id).Delete(&TableUser{}).Error
}

// ValidatePassword checks if the provided password matches the user's stored hash
func (s *UserStore) ValidatePassword(user *TableUser, password string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
    return err == nil
}

// EnsureAdminExists creates a default admin user if no admin exists
func (s *UserStore) EnsureAdminExists(ctx context.Context, email, name, password string) error {
    var count int64
    s.db.WithContext(ctx).Model(&TableUser{}).Where("role = ?", string(RoleAdmin)).Count(&count)
    if count > 0 {
        return nil
    }
    _, err := s.CreateUser(ctx, email, name, password, RoleAdmin, nil)
    return err
}
```

### 2.4 audit.go - Audit Logging

```go
package enterprise

import (
    "context"
    "fmt"
    "time"

    "github.com/google/uuid"
    "gorm.io/gorm"
)

// TableAuditLog records all significant user actions
type TableAuditLog struct {
    ID         string    `gorm:"primaryKey;type:varchar(255)" json:"id"`
    UserID     string    `gorm:"type:varchar(255);index" json:"user_id"`
    UserEmail  string    `gorm:"type:varchar(255)" json:"user_email"`
    Action     string    `gorm:"type:varchar(50);index" json:"action"` // create, update, delete, login, logout
    Resource   string    `gorm:"type:varchar(100);index" json:"resource"` // user, virtual_key, team, customer, etc.
    ResourceID string    `gorm:"type:varchar(255)" json:"resource_id"`
    Details    string    `gorm:"type:text" json:"details"` // JSON string with additional details
    IP         string    `gorm:"type:varchar(100)" json:"ip"`
    CreatedAt  time.Time `gorm:"index;not null" json:"created_at"`
}

func (TableAuditLog) TableName() string { return "enterprise_audit_logs" }

// AuditStore provides CRUD operations for audit logs
type AuditStore struct {
    db *gorm.DB
}

func NewAuditStore(db *gorm.DB) (*AuditStore, error) {
    if err := db.AutoMigrate(&TableAuditLog{}); err != nil {
        return nil, fmt.Errorf("failed to migrate audit logs table: %w", err)
    }
    return &AuditStore{db: db}, nil
}

// Record creates an audit log entry
func (s *AuditStore) Record(ctx context.Context, userID, userEmail, action, resource, resourceID, details, ip string) error {
    log := &TableAuditLog{
        ID:         uuid.New().String(),
        UserID:     userID,
        UserEmail:  userEmail,
        Action:     action,
        Resource:   resource,
        ResourceID: resourceID,
        Details:    details,
        IP:         ip,
        CreatedAt:  time.Now(),
    }
    return s.db.WithContext(ctx).Create(log).Error
}

// AuditLogQuery defines query parameters for audit logs
type AuditLogQuery struct {
    UserID   string
    Action   string
    Resource string
    StartAt  *time.Time
    EndAt    *time.Time
    Search   string
    Offset   int
    Limit    int
}

// Query retrieves audit logs with filtering
func (s *AuditStore) Query(ctx context.Context, q AuditLogQuery) ([]TableAuditLog, int64, error) {
    var logs []TableAuditLog
    var total int64

    query := s.db.WithContext(ctx).Model(&TableAuditLog{})
    if q.UserID != "" {
        query = query.Where("user_id = ?", q.UserID)
    }
    if q.Action != "" {
        query = query.Where("action = ?", q.Action)
    }
    if q.Resource != "" {
        query = query.Where("resource = ?", q.Resource)
    }
    if q.StartAt != nil {
        query = query.Where("created_at >= ?", *q.StartAt)
    }
    if q.EndAt != nil {
        query = query.Where("created_at <= ?", *q.EndAt)
    }
    if q.Search != "" {
        query = query.Where("user_email LIKE ? OR details LIKE ?", "%"+q.Search+"%", "%"+q.Search+"%")
    }

    if err := query.Count(&total).Error; err != nil {
        return nil, 0, err
    }
    if q.Limit == 0 {
        q.Limit = 50
    }
    if err := query.Order("created_at DESC").Offset(q.Offset).Limit(q.Limit).Find(&logs).Error; err != nil {
        return nil, 0, err
    }
    return logs, total, nil
}
```

### 2.5 middleware.go - RBAC Check Logic

```go
package enterprise

import (
    "strings"

    "github.com/valyala/fasthttp"
)

// Context keys for storing user info in request context
const (
    CtxKeyUserID     = "enterprise_user_id"
    CtxKeyUserEmail  = "enterprise_user_email"
    CtxKeyUserRole   = "enterprise_user_role"
    CtxKeyUserTeamID = "enterprise_user_team_id"
)

// RoutePermission maps an API route pattern to a required resource+operation
type RoutePermission struct {
    Method    string
    Prefix    string
    Resource  Resource
    Operation Operation
}

// APIRoutePermissions defines the RBAC requirements for each API endpoint
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

// CheckRoutePermission checks if a role has permission for the given HTTP method + path
func CheckRoutePermission(role Role, method, path string) bool {
    // Admin can do everything
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

// ExtractUserFromContext retrieves user info stored in the fasthttp request context
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
```

---

## 3. Backend: transports/ Changes

### 3.1 NEW FILE: handlers/enterprise.go

```go
package handlers

import (
    "encoding/json"
    "fmt"
    "strconv"
    "time"

    "github.com/bytedance/sonic"
    "github.com/fasthttp/router"
    "github.com/maximhq/bifrost/core/schemas"
    "github.com/maximhq/bifrost/transports/bifrost-http/lib"
    enterprise "github.com/workpieces/bifrost/plugins/enterprise"
    "github.com/valyala/fasthttp"
)

// EnterpriseHandler manages enterprise-specific HTTP endpoints
type EnterpriseHandler struct {
    userStore  *enterprise.UserStore
    auditStore *enterprise.AuditStore
}

func NewEnterpriseHandler(userStore *enterprise.UserStore, auditStore *enterprise.AuditStore) *EnterpriseHandler {
    return &EnterpriseHandler{
        userStore:  userStore,
        auditStore: auditStore,
    }
}

func (h *EnterpriseHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
    // User management
    r.GET("/api/enterprise/users", lib.ChainMiddlewares(h.listUsers, middlewares...))
    r.POST("/api/enterprise/users", lib.ChainMiddlewares(h.createUser, middlewares...))
    r.GET("/api/enterprise/users/{user_id}", lib.ChainMiddlewares(h.getUser, middlewares...))
    r.PUT("/api/enterprise/users/{user_id}", lib.ChainMiddlewares(h.updateUser, middlewares...))
    r.DELETE("/api/enterprise/users/{user_id}", lib.ChainMiddlewares(h.deleteUser, middlewares...))

    // Roles & permissions
    r.GET("/api/enterprise/roles", lib.ChainMiddlewares(h.listRoles, middlewares...))
    r.GET("/api/enterprise/permissions", lib.ChainMiddlewares(h.getMyPermissions, middlewares...))

    // Audit logs
    r.GET("/api/enterprise/audit-logs", lib.ChainMiddlewares(h.queryAuditLogs, middlewares...))
}

// --- User CRUD ---

func (h *EnterpriseHandler) createUser(ctx *fasthttp.RequestCtx) {
    payload := struct {
        Email    string  `json:"email"`
        Name     string  `json:"name"`
        Password string  `json:"password"`
        Role     string  `json:"role"`
        TeamID   *string `json:"team_id,omitempty"`
    }{}
    if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
        SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
        return
    }
    if payload.Email == "" || payload.Name == "" || payload.Password == "" {
        SendError(ctx, fasthttp.StatusBadRequest, "email, name, and password are required")
        return
    }
    if payload.Role == "" {
        payload.Role = "user"
    }

    user, err := h.userStore.CreateUser(ctx, payload.Email, payload.Name, payload.Password, enterprise.Role(payload.Role), payload.TeamID)
    if err != nil {
        SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create user: %v", err))
        return
    }

    // Record audit log
    callerID, callerEmail, _, _ := enterprise.ExtractUserFromContext(ctx)
    h.auditStore.Record(ctx, callerID, callerEmail, "create", "user", user.ID,
        fmt.Sprintf(`{"email":"%s","role":"%s"}`, user.Email, user.Role),
        ctx.RemoteAddr().String())

    SendJSON(ctx, user)
}

func (h *EnterpriseHandler) getUser(ctx *fasthttp.RequestCtx) {
    userID := ctx.UserValue("user_id").(string)
    user, err := h.userStore.GetUser(ctx, userID)
    if err != nil {
        SendError(ctx, fasthttp.StatusNotFound, "User not found")
        return
    }
    SendJSON(ctx, user)
}

func (h *EnterpriseHandler) listUsers(ctx *fasthttp.RequestCtx) {
    search := string(ctx.QueryArgs().Peek("search"))
    offset, _ := strconv.Atoi(string(ctx.QueryArgs().Peek("offset")))
    limit, _ := strconv.Atoi(string(ctx.QueryArgs().Peek("limit")))
    if limit == 0 {
        limit = 20
    }

    // Scope by team for non-admin users
    _, _, role, teamID := enterprise.ExtractUserFromContext(ctx)
    var filterTeamID *string
    if role == enterprise.RoleTeamManager {
        filterTeamID = teamID
    }

    users, total, err := h.userStore.ListUsers(ctx, filterTeamID, search, offset, limit)
    if err != nil {
        SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to list users: %v", err))
        return
    }

    SendJSON(ctx, map[string]interface{}{
        "data":  users,
        "total": total,
    })
}

func (h *EnterpriseHandler) updateUser(ctx *fasthttp.RequestCtx) {
    userID := ctx.UserValue("user_id").(string)
    var updates map[string]interface{}
    if err := sonic.Unmarshal(ctx.PostBody(), &updates); err != nil {
        SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
        return
    }
    // Prevent password update through this endpoint
    delete(updates, "password")
    delete(updates, "id")

    user, err := h.userStore.UpdateUser(ctx, userID, updates)
    if err != nil {
        SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update user: %v", err))
        return
    }

    callerID, callerEmail, _, _ := enterprise.ExtractUserFromContext(ctx)
    h.auditStore.Record(ctx, callerID, callerEmail, "update", "user", userID, "", ctx.RemoteAddr().String())

    SendJSON(ctx, user)
}

func (h *EnterpriseHandler) deleteUser(ctx *fasthttp.RequestCtx) {
    userID := ctx.UserValue("user_id").(string)
    if err := h.userStore.DeleteUser(ctx, userID); err != nil {
        SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to delete user: %v", err))
        return
    }

    callerID, callerEmail, _, _ := enterprise.ExtractUserFromContext(ctx)
    h.auditStore.Record(ctx, callerID, callerEmail, "delete", "user", userID, "", ctx.RemoteAddr().String())

    SendJSON(ctx, map[string]string{"message": "User deleted"})
}

// --- Roles & Permissions ---

func (h *EnterpriseHandler) listRoles(ctx *fasthttp.RequestCtx) {
    SendJSON(ctx, enterprise.GetAllRoles())
}

func (h *EnterpriseHandler) getMyPermissions(ctx *fasthttp.RequestCtx) {
    _, _, role, teamID := enterprise.ExtractUserFromContext(ctx)
    SendJSON(ctx, map[string]interface{}{
        "role":        role,
        "permissions": enterprise.GetPermissionsMap(role),
        "team_id":     teamID,
    })
}

// --- Audit Logs ---

func (h *EnterpriseHandler) queryAuditLogs(ctx *fasthttp.RequestCtx) {
    q := enterprise.AuditLogQuery{
        UserID:   string(ctx.QueryArgs().Peek("user_id")),
        Action:   string(ctx.QueryArgs().Peek("action")),
        Resource: string(ctx.QueryArgs().Peek("resource")),
        Search:   string(ctx.QueryArgs().Peek("search")),
    }
    q.Offset, _ = strconv.Atoi(string(ctx.QueryArgs().Peek("offset")))
    q.Limit, _ = strconv.Atoi(string(ctx.QueryArgs().Peek("limit")))

    if startStr := string(ctx.QueryArgs().Peek("start_at")); startStr != "" {
        if t, err := time.Parse(time.RFC3339, startStr); err == nil {
            q.StartAt = &t
        }
    }
    if endStr := string(ctx.QueryArgs().Peek("end_at")); endStr != "" {
        if t, err := time.Parse(time.RFC3339, endStr); err == nil {
            q.EndAt = &t
        }
    }

    logs, total, err := h.auditStore.Query(ctx, q)
    if err != nil {
        SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to query audit logs: %v", err))
        return
    }
    SendJSON(ctx, map[string]interface{}{
        "data":  logs,
        "total": total,
    })
}
```

### 3.2 MODIFY: server/server.go - RegisterAPIRoutes()

Add after the governance handler registration (~line 1024):

```go
// Enterprise handler (users, RBAC, audit logs)
if s.Config.EnterpriseHandler != nil {
    s.Config.EnterpriseHandler.RegisterRoutes(s.Router, middlewares...)
}
```

And in Bootstrap(), after config store initialization, initialize enterprise stores:

```go
// Initialize enterprise stores if DB is available
if s.Config.ConfigStore != nil {
    db := s.Config.ConfigStore.DB()
    userStore, err := enterprise.NewUserStore(db)
    if err != nil {
        logger.Error("failed to initialize enterprise user store: %v", err)
    }
    auditStore, err := enterprise.NewAuditStore(db)
    if err != nil {
        logger.Error("failed to initialize enterprise audit store: %v", err)
    }
    if userStore != nil && auditStore != nil {
        s.Config.EnterpriseUserStore = userStore
        s.Config.EnterpriseAuditStore = auditStore
        s.Config.EnterpriseHandler = handlers.NewEnterpriseHandler(userStore, auditStore)
    }
}
```

### 3.3 MODIFY: handlers/middlewares.go - Add RBAC enforcement

In the `middleware()` function, after successful session validation (around line 603-606), add:

```go
// Enterprise RBAC: load user from session and check permissions
if s.Config.EnterpriseUserStore != nil {
    // Look up the user associated with this session
    user, err := s.Config.EnterpriseUserStore.GetUserBySessionToken(ctx, sessionToken)
    if err == nil && user != nil {
        ctx.SetUserValue(enterprise.CtxKeyUserID, user.ID)
        ctx.SetUserValue(enterprise.CtxKeyUserEmail, user.Email)
        ctx.SetUserValue(enterprise.CtxKeyUserRole, user.Role)
        ctx.SetUserValue(enterprise.CtxKeyUserTeamID, user.TeamID)

        // Check route permission
        method := string(ctx.Method())
        path := string(ctx.Path())
        if !enterprise.CheckRoutePermission(enterprise.Role(user.Role), method, path) {
            SendError(ctx, fasthttp.StatusForbidden, "Insufficient permissions")
            return
        }
    }
}
```

### 3.4 MODIFY: go.work

```diff
 use (
     ...existing...
+    ./plugins/enterprise
 )
```

---

## 4. Frontend: ui/app/enterprise/

### 4.1 Directory Structure

```
ui/app/enterprise/
├── lib/
│   ├── index.ts                          # Main export (matches _fallbacks contract)
│   ├── contexts/
│   │   └── rbacContext.tsx                # Real RBAC with API call
│   ├── store/
│   │   ├── index.ts
│   │   ├── apis/
│   │   │   ├── index.ts                  # Enterprise APIs (rbacApi, auditLogsApi, etc.)
│   │   │   └── largePayloadApi.ts        # Copy from _fallbacks (stub)
│   │   ├── slices/
│   │   │   └── index.ts                  # Enterprise reducers
│   │   └── utils/
│   │       ├── tokenManager.ts           # Copy from _fallbacks (cookie-based auth, no OAuth needed)
│   │       └── baseQueryWithRefresh.ts   # Copy from _fallbacks (passthrough)
│   └── types/
│       └── largePayload.ts               # Copy from _fallbacks
├── components/
│   ├── login/
│   │   └── loginView.tsx                 # Copy from _fallbacks (already fully implemented!)
│   ├── user-groups/
│   │   └── usersView.tsx                 # Real users management table
│   ├── rbac/
│   │   └── rbacView.tsx                  # Read-only roles table
│   ├── audit-logs/
│   │   └── auditLogsView.tsx             # Audit logs viewer with filters
│   ├── scim/
│   │   └── scimView.tsx                  # Copy from _fallbacks (stub for now)
│   ├── api-keys/
│   │   └── apiKeysIndexView.tsx          # Copy from _fallbacks (stub)
│   ├── adaptive-routing/
│   │   └── adaptiveRoutingView.tsx       # Copy from _fallbacks (stub)
│   ├── alert-channels/
│   │   └── alertChannelsView.tsx         # Copy from _fallbacks (stub)
│   ├── cluster/
│   │   └── clusterView.tsx              # Copy from _fallbacks (stub)
│   ├── data-connectors/
│   │   ├── bigquery/
│   │   │   └── bigqueryConnectorView.tsx # Copy from _fallbacks (stub)
│   │   └── datadog/
│   │       └── datadogConnectorView.tsx  # Copy from _fallbacks (stub)
│   ├── guardrails/
│   │   ├── guardrailsConfigurationView.tsx # Copy from _fallbacks (stub)
│   │   └── guardrailsProviderView.tsx      # Copy from _fallbacks (stub)
│   ├── large-payload/
│   │   └── largePayloadSettingsFragment.tsx # Copy from _fallbacks (stub)
│   ├── mcp-auth-config/
│   │   └── mcpAuthConfigView.tsx          # Copy from _fallbacks (stub)
│   ├── mcp-tool-groups/
│   │   └── mcpToolGroups.tsx             # Copy from _fallbacks (stub)
│   ├── pii-redactor/
│   │   ├── piiRedactorProviderView.tsx   # Copy from _fallbacks (stub)
│   │   └── piiRedactorRulesView.tsx      # Copy from _fallbacks (stub)
│   ├── prompt-deployments/
│   │   └── promptDeploymentView.tsx      # Copy from _fallbacks (stub)
│   └── views/
│       └── contactUsView.tsx             # Copy from _fallbacks (shared "Contact Us" template)
```

### 4.2 lib/contexts/rbacContext.tsx (Real RBAC)

```tsx
"use client";

import { createContext, useContext, useEffect, useState } from "react";

export enum RbacResource {
    GuardrailsConfig = "GuardrailsConfig",
    GuardrailsProviders = "GuardrailsProviders",
    GuardrailRules = "GuardrailRules",
    UserProvisioning = "UserProvisioning",
    Cluster = "Cluster",
    Settings = "Settings",
    Users = "Users",
    Logs = "Logs",
    Observability = "Observability",
    VirtualKeys = "VirtualKeys",
    ModelProvider = "ModelProvider",
    Plugins = "Plugins",
    MCPGateway = "MCPGateway",
    AdaptiveRouter = "AdaptiveRouter",
    AuditLogs = "AuditLogs",
    Customers = "Customers",
    Teams = "Teams",
    RBAC = "RBAC",
    Governance = "Governance",
    RoutingRules = "RoutingRules",
    PIIRedactor = "PIIRedactor",
    PromptRepository = "PromptRepository",
    PromptDeploymentStrategy = "PromptDeploymentStrategy",
}

export enum RbacOperation {
    Read = "Read",
    View = "View",
    Create = "Create",
    Update = "Update",
    Delete = "Delete",
    Download = "Download",
}

interface RbacContextType {
    isAllowed: (resource: RbacResource, operation: RbacOperation) => boolean;
    permissions: Record<string, Record<string, boolean>>;
    isLoading: boolean;
    refetch: () => void;
}

const RbacContext = createContext<RbacContextType | null>(null);

export function RbacProvider({ children }: { children: React.ReactNode }) {
    const [permissions, setPermissions] = useState<Record<string, Record<string, boolean>>>({});
    const [isLoading, setIsLoading] = useState(true);

    const fetchPermissions = async () => {
        try {
            const res = await fetch("/api/enterprise/permissions", { credentials: "include" });
            if (res.ok) {
                const data = await res.json();
                setPermissions(data.permissions || {});
            }
        } catch {
            // If fetch fails, default to empty permissions (deny all)
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchPermissions();
    }, []);

    const isAllowed = (resource: RbacResource, operation: RbacOperation): boolean => {
        return permissions[resource]?.[operation] ?? false;
    };

    return (
        <RbacContext.Provider value={{ isAllowed, permissions, isLoading, refetch: fetchPermissions }}>
            {children}
        </RbacContext.Provider>
    );
}

export function useRbac(resource: RbacResource, operation: RbacOperation): boolean {
    const context = useContext(RbacContext);
    if (!context) {
        return false; // Deny by default if no provider
    }
    if (context.isLoading) {
        return false; // Deny while loading
    }
    return context.isAllowed(resource, operation);
}

export function useRbacContext() {
    const context = useContext(RbacContext);
    if (!context) {
        return {
            isAllowed: () => false,
            permissions: {},
            isLoading: false,
            refetch: () => {},
        };
    }
    return context;
}
```

### 4.3 components/user-groups/usersView.tsx (Real Users Management)

```tsx
"use client";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { RbacOperation, RbacResource, useRbac } from "@enterprise/lib";
import { Edit, Plus, Search, Trash2, Users } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

interface User {
    id: string;
    email: string;
    name: string;
    role: string;
    team_id?: string;
    is_active: boolean;
    created_at: string;
}

interface UsersResponse {
    data: User[];
    total: number;
}

const ROLE_LABELS: Record<string, string> = {
    admin: "Admin",
    team_manager: "Team Manager",
    user: "User",
    viewer: "Viewer",
};

const ROLE_VARIANTS: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
    admin: "destructive",
    team_manager: "default",
    user: "secondary",
    viewer: "outline",
};

export default function UsersView() {
    const [users, setUsers] = useState<User[]>([]);
    const [total, setTotal] = useState(0);
    const [search, setSearch] = useState("");
    const [offset, setOffset] = useState(0);
    const [showDialog, setShowDialog] = useState(false);
    const [editingUser, setEditingUser] = useState<User | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    const hasCreateAccess = useRbac(RbacResource.Users, RbacOperation.Create);
    const hasUpdateAccess = useRbac(RbacResource.Users, RbacOperation.Update);
    const hasDeleteAccess = useRbac(RbacResource.Users, RbacOperation.Delete);

    const PAGE_SIZE = 20;

    const fetchUsers = async () => {
        setIsLoading(true);
        try {
            const params = new URLSearchParams({
                offset: String(offset),
                limit: String(PAGE_SIZE),
                ...(search && { search }),
            });
            const res = await fetch(`/api/enterprise/users?${params}`, { credentials: "include" });
            if (res.ok) {
                const data: UsersResponse = await res.json();
                setUsers(data.data);
                setTotal(data.total);
            }
        } catch {
            toast.error("Failed to load users");
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchUsers();
    }, [search, offset]);

    const handleDelete = async (userId: string) => {
        try {
            const res = await fetch(`/api/enterprise/users/${userId}`, {
                method: "DELETE",
                credentials: "include",
            });
            if (res.ok) {
                toast.success("User deleted");
                fetchUsers();
            } else {
                toast.error("Failed to delete user");
            }
        } catch {
            toast.error("Failed to delete user");
        }
    };

    return (
        <div className="space-y-4 p-6">
            <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Users</h2>
                {hasCreateAccess && (
                    <Button onClick={() => { setEditingUser(null); setShowDialog(true); }}>
                        <Plus className="mr-2 h-4 w-4" /> Add User
                    </Button>
                )}
            </div>

            <div className="relative max-w-sm">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                    placeholder="Search users..."
                    value={search}
                    onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
                    className="pl-9"
                />
            </div>

            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead>Name</TableHead>
                        <TableHead>Email</TableHead>
                        <TableHead>Role</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Created</TableHead>
                        <TableHead className="w-[100px]">Actions</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {users.map((user) => (
                        <TableRow key={user.id}>
                            <TableCell className="font-medium">{user.name}</TableCell>
                            <TableCell>{user.email}</TableCell>
                            <TableCell>
                                <Badge variant={ROLE_VARIANTS[user.role] || "secondary"}>
                                    {ROLE_LABELS[user.role] || user.role}
                                </Badge>
                            </TableCell>
                            <TableCell>
                                <Badge variant={user.is_active ? "default" : "outline"}>
                                    {user.is_active ? "Active" : "Inactive"}
                                </Badge>
                            </TableCell>
                            <TableCell className="text-muted-foreground text-sm">
                                {new Date(user.created_at).toLocaleDateString()}
                            </TableCell>
                            <TableCell>
                                <div className="flex gap-1">
                                    {hasUpdateAccess && (
                                        <Button variant="ghost" size="icon" onClick={() => { setEditingUser(user); setShowDialog(true); }}>
                                            <Edit className="h-4 w-4" />
                                        </Button>
                                    )}
                                    {hasDeleteAccess && (
                                        <Button variant="ghost" size="icon" onClick={() => handleDelete(user.id)}>
                                            <Trash2 className="h-4 w-4 text-destructive" />
                                        </Button>
                                    )}
                                </div>
                            </TableCell>
                        </TableRow>
                    ))}
                    {!isLoading && users.length === 0 && (
                        <TableRow>
                            <TableCell colSpan={6} className="text-center py-8">
                                <Users className="mx-auto h-12 w-12 text-muted-foreground mb-2" />
                                <p className="text-muted-foreground">No users found</p>
                            </TableCell>
                        </TableRow>
                    )}
                </TableBody>
            </Table>

            {/* Pagination */}
            {total > PAGE_SIZE && (
                <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">
                        Showing {offset + 1}-{Math.min(offset + PAGE_SIZE, total)} of {total}
                    </p>
                    <div className="flex gap-2">
                        <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                            Previous
                        </Button>
                        <Button variant="outline" size="sm" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
                            Next
                        </Button>
                    </div>
                </div>
            )}

            {/* Create/Edit Dialog */}
            {showDialog && (
                <UserDialog
                    user={editingUser}
                    onSave={() => { setShowDialog(false); fetchUsers(); }}
                    onCancel={() => setShowDialog(false)}
                />
            )}
        </div>
    );
}

// --- User Create/Edit Dialog ---

function UserDialog({ user, onSave, onCancel }: { user: User | null; onSave: () => void; onCancel: () => void }) {
    const isEditing = !!user;
    const [formData, setFormData] = useState({
        email: user?.email || "",
        name: user?.name || "",
        password: "",
        role: user?.role || "user",
        team_id: user?.team_id || "",
    });
    const [isLoading, setIsLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);
        try {
            const url = isEditing ? `/api/enterprise/users/${user.id}` : "/api/enterprise/users";
            const method = isEditing ? "PUT" : "POST";
            const body = isEditing
                ? { name: formData.name, role: formData.role, team_id: formData.team_id || null }
                : formData;

            const res = await fetch(url, {
                method,
                headers: { "Content-Type": "application/json" },
                credentials: "include",
                body: JSON.stringify(body),
            });
            if (res.ok) {
                toast.success(isEditing ? "User updated" : "User created");
                onSave();
            } else {
                const err = await res.json();
                toast.error(err.error || "Operation failed");
            }
        } catch {
            toast.error("Operation failed");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <Dialog open onOpenChange={onCancel}>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>{isEditing ? "Edit User" : "Create User"}</DialogTitle>
                    <DialogDescription>
                        {isEditing ? "Update user information." : "Add a new user to the system."}
                    </DialogDescription>
                </DialogHeader>
                <form onSubmit={handleSubmit} className="space-y-4">
                    {!isEditing && (
                        <div className="space-y-2">
                            <Label>Email</Label>
                            <Input type="email" value={formData.email} onChange={(e) => setFormData({ ...formData, email: e.target.value })} required />
                        </div>
                    )}
                    <div className="space-y-2">
                        <Label>Name</Label>
                        <Input value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} required />
                    </div>
                    {!isEditing && (
                        <div className="space-y-2">
                            <Label>Password</Label>
                            <Input type="password" value={formData.password} onChange={(e) => setFormData({ ...formData, password: e.target.value })} required />
                        </div>
                    )}
                    <div className="space-y-2">
                        <Label>Role</Label>
                        <Select value={formData.role} onValueChange={(v) => setFormData({ ...formData, role: v })}>
                            <SelectTrigger><SelectValue /></SelectTrigger>
                            <SelectContent>
                                <SelectItem value="admin">Admin</SelectItem>
                                <SelectItem value="team_manager">Team Manager</SelectItem>
                                <SelectItem value="user">User</SelectItem>
                                <SelectItem value="viewer">Viewer</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    <div className="flex justify-end gap-2 pt-4">
                        <Button type="button" variant="outline" onClick={onCancel}>Cancel</Button>
                        <Button type="submit" disabled={isLoading}>
                            {isLoading ? "Saving..." : isEditing ? "Update" : "Create"}
                        </Button>
                    </div>
                </form>
            </DialogContent>
        </Dialog>
    );
}
```

### 4.4 components/rbac/rbacView.tsx (Read-only Roles Table)

```tsx
"use client";

import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useEffect, useState } from "react";

interface RoleInfo {
    name: string;
    label: string;
    description: string;
    permissions: Record<string, string[]>;
}

export default function RBACView() {
    const [roles, setRoles] = useState<RoleInfo[]>([]);

    useEffect(() => {
        fetch("/api/enterprise/roles", { credentials: "include" })
            .then((res) => res.json())
            .then(setRoles)
            .catch(() => {});
    }, []);

    return (
        <div className="space-y-4 p-6">
            <div>
                <h2 className="text-lg font-semibold">Roles & Permissions</h2>
                <p className="text-sm text-muted-foreground">
                    System roles are predefined and cannot be modified. Assign roles to users in the Users page.
                </p>
            </div>

            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead className="w-[150px]">Role</TableHead>
                        <TableHead>Description</TableHead>
                        <TableHead>Permissions</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {roles.map((role) => (
                        <TableRow key={role.name}>
                            <TableCell>
                                <Badge variant={role.name === "admin" ? "destructive" : "secondary"}>
                                    {role.label}
                                </Badge>
                            </TableCell>
                            <TableCell className="text-muted-foreground text-sm">{role.description}</TableCell>
                            <TableCell>
                                <div className="flex flex-wrap gap-1">
                                    {Object.entries(role.permissions).map(([resource, ops]) => (
                                        <Badge key={resource} variant="outline" className="text-xs">
                                            {resource}: {Array.isArray(ops) ? ops.join(", ") : String(ops)}
                                        </Badge>
                                    ))}
                                </div>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </div>
    );
}
```

### 4.5 components/audit-logs/auditLogsView.tsx (Audit Logs Viewer)

```tsx
"use client";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ChevronLeft, ChevronRight, Search, ScrollText } from "lucide-react";
import { useEffect, useState } from "react";

interface AuditLog {
    id: string;
    user_id: string;
    user_email: string;
    action: string;
    resource: string;
    resource_id: string;
    details: string;
    ip: string;
    created_at: string;
}

const ACTION_VARIANTS: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
    create: "default",
    update: "secondary",
    delete: "destructive",
    login: "outline",
    logout: "outline",
};

export default function AuditLogsView() {
    const [logs, setLogs] = useState<AuditLog[]>([]);
    const [total, setTotal] = useState(0);
    const [search, setSearch] = useState("");
    const [actionFilter, setActionFilter] = useState("all");
    const [resourceFilter, setResourceFilter] = useState("all");
    const [offset, setOffset] = useState(0);
    const [isLoading, setIsLoading] = useState(true);

    const PAGE_SIZE = 50;

    const fetchLogs = async () => {
        setIsLoading(true);
        try {
            const params = new URLSearchParams({
                offset: String(offset),
                limit: String(PAGE_SIZE),
                ...(search && { search }),
                ...(actionFilter !== "all" && { action: actionFilter }),
                ...(resourceFilter !== "all" && { resource: resourceFilter }),
            });
            const res = await fetch(`/api/enterprise/audit-logs?${params}`, { credentials: "include" });
            if (res.ok) {
                const data = await res.json();
                setLogs(data.data);
                setTotal(data.total);
            }
        } catch {
            // ignore
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchLogs();
    }, [search, actionFilter, resourceFilter, offset]);

    return (
        <div className="space-y-4 p-6">
            <h2 className="text-lg font-semibold">Audit Logs</h2>

            <div className="flex items-center gap-3">
                <div className="relative max-w-sm">
                    <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                        placeholder="Search by email or details..."
                        value={search}
                        onChange={(e) => { setSearch(e.target.value); setOffset(0); }}
                        className="pl-9"
                    />
                </div>
                <Select value={actionFilter} onValueChange={(v) => { setActionFilter(v); setOffset(0); }}>
                    <SelectTrigger className="w-[140px]"><SelectValue placeholder="Action" /></SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Actions</SelectItem>
                        <SelectItem value="create">Create</SelectItem>
                        <SelectItem value="update">Update</SelectItem>
                        <SelectItem value="delete">Delete</SelectItem>
                        <SelectItem value="login">Login</SelectItem>
                        <SelectItem value="logout">Logout</SelectItem>
                    </SelectContent>
                </Select>
                <Select value={resourceFilter} onValueChange={(v) => { setResourceFilter(v); setOffset(0); }}>
                    <SelectTrigger className="w-[160px]"><SelectValue placeholder="Resource" /></SelectTrigger>
                    <SelectContent>
                        <SelectItem value="all">All Resources</SelectItem>
                        <SelectItem value="user">User</SelectItem>
                        <SelectItem value="virtual_key">Virtual Key</SelectItem>
                        <SelectItem value="team">Team</SelectItem>
                        <SelectItem value="customer">Customer</SelectItem>
                    </SelectContent>
                </Select>
            </div>

            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead>Time</TableHead>
                        <TableHead>User</TableHead>
                        <TableHead>Action</TableHead>
                        <TableHead>Resource</TableHead>
                        <TableHead>Resource ID</TableHead>
                        <TableHead>IP</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {logs.map((log) => (
                        <TableRow key={log.id}>
                            <TableCell className="text-muted-foreground text-sm whitespace-nowrap">
                                {new Date(log.created_at).toLocaleString()}
                            </TableCell>
                            <TableCell>{log.user_email}</TableCell>
                            <TableCell>
                                <Badge variant={ACTION_VARIANTS[log.action] || "secondary"}>
                                    {log.action}
                                </Badge>
                            </TableCell>
                            <TableCell>{log.resource}</TableCell>
                            <TableCell className="font-mono text-xs max-w-[200px] truncate">
                                {log.resource_id}
                            </TableCell>
                            <TableCell className="text-muted-foreground text-sm">{log.ip}</TableCell>
                        </TableRow>
                    ))}
                    {!isLoading && logs.length === 0 && (
                        <TableRow>
                            <TableCell colSpan={6} className="text-center py-8">
                                <ScrollText className="mx-auto h-12 w-12 text-muted-foreground mb-2" />
                                <p className="text-muted-foreground">No audit logs found</p>
                            </TableCell>
                        </TableRow>
                    )}
                </TableBody>
            </Table>

            {total > PAGE_SIZE && (
                <div className="flex items-center justify-between">
                    <p className="text-sm text-muted-foreground">
                        Showing {offset + 1}-{Math.min(offset + PAGE_SIZE, total)} of {total}
                    </p>
                    <div className="flex gap-2">
                        <Button variant="outline" size="icon" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                            <ChevronLeft className="h-4 w-4" />
                        </Button>
                        <Button variant="outline" size="icon" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
                            <ChevronRight className="h-4 w-4" />
                        </Button>
                    </div>
                </div>
            )}
        </div>
    );
}
```

---

## 5. Files Change Summary

### New Files (zero conflict with upstream)

| Location | Files | Purpose |
|----------|-------|---------|
| `plugins/enterprise/` | go.mod, roles.go, users.go, audit.go, middleware.go | Backend enterprise logic |
| `transports/bifrost-http/handlers/enterprise.go` | 1 file | Enterprise API endpoints |
| `ui/app/enterprise/lib/` | ~8 files | RBAC context, store, utils |
| `ui/app/enterprise/components/` | ~20 files | Real + stub components |

### Modified Files (minimal changes)

| File | Change | Lines |
|------|--------|-------|
| `go.work` | Add `./plugins/enterprise` | +1 line |
| `transports/bifrost-http/server/server.go` | Register enterprise handler, init stores | +15 lines |
| `transports/bifrost-http/handlers/middlewares.go` | Add RBAC check after session validation | +15 lines |
| `transports/bifrost-http/lib/config.go` | Add EnterpriseHandler, stores fields to Config | +5 lines |

**Total: 4 existing files modified, ~36 lines added.**

---

## 6. Implementation Order

```
Step 1: plugins/enterprise/ (Go module)
   └── go.mod, roles.go, users.go, audit.go, middleware.go
   └── go.work update

Step 2: transports/ backend changes
   └── handlers/enterprise.go (new)
   └── server.go, middlewares.go, config.go (small mods)

Step 3: ui/app/enterprise/lib/ (frontend core)
   └── rbacContext.tsx, store APIs, utils

Step 4: ui/app/enterprise/components/ (frontend pages)
   └── Real: loginView, usersView, rbacView, auditLogsView
   └── Stub: copy remaining from _fallbacks

Step 5: Test
   └── go build, npm run build
   └── Login as admin → full sidebar
   └── Login as user → limited sidebar
   └── CRUD operations → audit logs recorded
```

---

## 7. User Flow (after implementation)

### Admin first-time setup
1. Start bifrost with enterprise build
2. System creates default admin user (from config or env vars)
3. Admin logs in → sees full dashboard
4. Admin creates Users, assigns roles & teams

### Normal user flow
1. User logs in with email/password
2. Frontend calls `GET /api/enterprise/permissions` → gets role permissions
3. Sidebar only shows allowed menu items
4. API calls to forbidden endpoints return 403
5. All operations logged to audit trail

### Usage tracking
1. Existing governance plugin handles budget/rate-limit tracking per VK/Team/Customer
2. Admin can view usage stats through existing governance UI
3. Users see only their own VK usage (scoped by team)
