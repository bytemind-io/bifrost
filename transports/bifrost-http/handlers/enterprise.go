package handlers

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/fasthttp/router"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"github.com/maximhq/bifrost/framework/configstore/tables"
	"github.com/maximhq/bifrost/framework/encrypt"
	"github.com/maximhq/bifrost/transports/bifrost-http/lib"
	"github.com/valyala/fasthttp"
	"github.com/workpieces/bifrost/plugins/enterprise"
)

// EnterpriseHandler manages enterprise-specific HTTP endpoints.
type EnterpriseHandler struct {
	userStore   *enterprise.UserStore
	auditStore  *enterprise.AuditStore
	roleStore   *enterprise.RoleStore
	configStore configstore.ConfigStore
}

// NewEnterpriseHandler creates a new enterprise handler instance.
func NewEnterpriseHandler(
	userStore *enterprise.UserStore,
	auditStore *enterprise.AuditStore,
	roleStore *enterprise.RoleStore,
	configStore configstore.ConfigStore,
) *EnterpriseHandler {
	return &EnterpriseHandler{
		userStore:   userStore,
		auditStore:  auditStore,
		roleStore:   roleStore,
		configStore: configStore,
	}
}

// GetRoleStore returns the role store (used by governance handler for data filtering).
func (h *EnterpriseHandler) GetRoleStore() *enterprise.RoleStore {
	return h.roleStore
}

// audit emits a configuration_change audit event (most common type).
func (h *EnterpriseHandler) audit(ctx *fasthttp.RequestCtx, action, resource, resourceID, details string) {
	userID, userEmail, role, _ := enterprise.ExtractUserFromContext(ctx)
	if userEmail == "" && role != "" {
		userEmail = role // legacy admin: use role name as identifier
	}
	h.auditStore.Emit(enterprise.AuditEvent{
		EventType:  enterprise.EventTypeConfigurationChange,
		Action:     action,
		Status:     enterprise.StatusSuccess,
		Severity:   enterprise.SeverityLow,
		UserID:     userID,
		UserEmail:  userEmail,
		IP:         ctx.RemoteAddr().String(),
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
	})
}

// auditAuth emits an authentication audit event.
func (h *EnterpriseHandler) auditAuth(ctx *fasthttp.RequestCtx, action, status, severity, userID, email, resource, resourceID, details string) {
	h.auditStore.Emit(enterprise.AuditEvent{
		EventType:  enterprise.EventTypeAuthentication,
		Action:     action,
		Status:     status,
		Severity:   severity,
		UserID:     userID,
		UserEmail:  email,
		IP:         ctx.RemoteAddr().String(),
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
	})
}

// RBACMiddleware returns a middleware that enforces role-based access control.
func (h *EnterpriseHandler) RBACMiddleware() schemas.BifrostHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			path := string(ctx.Path())
			method := string(ctx.Method())

			// Step 1: Resolve user identity from session token (always, regardless of path)
			h.resolveUser(ctx)

			// Step 2: Check if this path needs RBAC enforcement
			if h.isWhitelisted(path, method) {
				next(ctx)
				h.auditMutation(ctx, method, path)
				return
			}

			// Step 3: Enforce route permission
			roleName, _ := ctx.UserValue(enterprise.CtxKeyUserRole).(string)
			if !enterprise.CheckRoutePermission(h.roleStore, roleName, method, path) {
				SendError(ctx, fasthttp.StatusForbidden, "Insufficient permissions")
				return
			}

			next(ctx)
			h.auditMutation(ctx, method, path)
		}
	}
}

// resolveUser extracts session token and resolves the enterprise user or legacy admin.
func (h *EnterpriseHandler) resolveUser(ctx *fasthttp.RequestCtx) {
	sessionToken, _ := ctx.UserValue(schemas.BifrostContextKeySessionToken).(string)
	if sessionToken == "" {
		return
	}

	// Try enterprise user first
	tokenHash := encrypt.HashSHA256(sessionToken)
	user, err := h.userStore.GetUserByTokenHash(ctx, tokenHash)
	if err == nil {
		ctx.SetUserValue(enterprise.CtxKeyUserID, user.ID)
		ctx.SetUserValue(enterprise.CtxKeyUserEmail, user.Email)
		ctx.SetUserValue(enterprise.CtxKeyUserRole, user.Role)
		ctx.SetUserValue(enterprise.CtxKeyUserTeamID, user.TeamID)
		return
	}

	// Fallback: check if it's a valid, non-expired config-store session (legacy admin)
	session, sessErr := h.configStore.GetSession(ctx, sessionToken)
	if sessErr == nil && session != nil && session.ExpiresAt.After(time.Now()) {
		ctx.SetUserValue(enterprise.CtxKeyUserRole, "Admin")
	}
}

// isWhitelisted returns true for paths that skip RBAC enforcement.
// User context is still resolved — only permission checking is skipped.
func (h *EnterpriseHandler) isWhitelisted(path, method string) bool {
	if path == "/health" {
		return true
	}
	whitelisted := []string{
		"/api/session/",
		"/api/enterprise/login",
		"/api/enterprise/logout",
		"/api/enterprise/permissions",
		"/api/enterprise/me",
		"/api/version",
		"/ws",
	}
	for _, w := range whitelisted {
		if strings.HasPrefix(path, w) {
			return true
		}
	}
	// GET /api/config is public; PUT /api/config requires RBAC
	if strings.HasPrefix(path, "/api/config") && method == "GET" {
		return true
	}
	return false
}

// auditMutation records audit events for successful write operations.
func (h *EnterpriseHandler) auditMutation(ctx *fasthttp.RequestCtx, method, path string) {
	if method != "POST" && method != "PUT" && method != "DELETE" {
		return
	}
	if path == "/api/enterprise/login" || path == "/api/enterprise/logout" {
		return
	}
	if ctx.Response.StatusCode() < 200 || ctx.Response.StatusCode() >= 300 {
		return
	}
	h.recordGovernanceAudit(ctx, method, path)
}

// recordGovernanceAudit records audit logs for governance CRUD operations.
func (h *EnterpriseHandler) recordGovernanceAudit(ctx *fasthttp.RequestCtx, method, path string) {
	// Only audit governance and enterprise API mutations
	if !strings.HasPrefix(path, "/api/governance/") && !strings.HasPrefix(path, "/api/enterprise/") {
		return
	}

	userID, userEmail, role, _ := enterprise.ExtractUserFromContext(ctx)
	if userEmail == "" && role != "" {
		userEmail = role
	}

	// Derive action from HTTP method
	action := "update"
	switch method {
	case "POST":
		action = "create"
	case "DELETE":
		action = "delete"
	}

	// Derive resource from path: /api/governance/virtual-keys/... → virtual_key
	resource := "unknown"
	parts := strings.Split(strings.TrimPrefix(path, "/api/"), "/")
	if len(parts) >= 2 {
		resource = strings.ReplaceAll(parts[1], "-", "_")
		// Singularize common plurals
		resource = strings.TrimSuffix(resource, "s")
		if resource == "virtual_key" {
			resource = "virtual_key"
		}
	}

	// Extract resource ID from path (last segment for PUT/DELETE)
	resourceID := ""
	if len(parts) >= 3 {
		resourceID = parts[2]
	}

	h.auditStore.Emit(enterprise.AuditEvent{
		EventType:  enterprise.EventTypeConfigurationChange,
		Action:     action,
		Status:     enterprise.StatusSuccess,
		Severity:   enterprise.SeverityLow,
		UserID:     userID,
		UserEmail:  userEmail,
		IP:         ctx.RemoteAddr().String(),
		Resource:   resource,
		ResourceID: resourceID,
	})
}

// RegisterRoutes registers enterprise API routes.
func (h *EnterpriseHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	// Enterprise login/logout
	r.POST("/api/enterprise/login", lib.ChainMiddlewares(h.login, middlewares...))
	r.POST("/api/enterprise/logout", lib.ChainMiddlewares(h.logout, middlewares...))

	// User profile (me)
	r.GET("/api/enterprise/me", lib.ChainMiddlewares(h.getMe, middlewares...))
	r.PUT("/api/enterprise/me", lib.ChainMiddlewares(h.updateMe, middlewares...))

	// User management
	r.GET("/api/enterprise/users", lib.ChainMiddlewares(h.listUsers, middlewares...))
	r.GET("/api/enterprise/users/stats", lib.ChainMiddlewares(h.getUserStats, middlewares...))
	r.POST("/api/enterprise/users", lib.ChainMiddlewares(h.createUser, middlewares...))
	r.GET("/api/enterprise/users/{user_id}", lib.ChainMiddlewares(h.getUser, middlewares...))
	r.PUT("/api/enterprise/users/{user_id}", lib.ChainMiddlewares(h.updateUser, middlewares...))
	r.DELETE("/api/enterprise/users/{user_id}", lib.ChainMiddlewares(h.deleteUser, middlewares...))

	// Team member management
	r.GET("/api/enterprise/teams/{team_id}/members", lib.ChainMiddlewares(h.listTeamMembers, middlewares...))
	r.POST("/api/enterprise/teams/{team_id}/members", lib.ChainMiddlewares(h.assignTeamMember, middlewares...))
	r.DELETE("/api/enterprise/teams/{team_id}/members/{user_id}", lib.ChainMiddlewares(h.removeTeamMember, middlewares...))

	// Roles CRUD
	r.GET("/api/roles", lib.ChainMiddlewares(h.listRoles, middlewares...))
	r.POST("/api/roles", lib.ChainMiddlewares(h.createRole, middlewares...))
	r.GET("/api/roles/{role_id}", lib.ChainMiddlewares(h.getRole, middlewares...))
	r.PUT("/api/roles/{role_id}", lib.ChainMiddlewares(h.updateRole, middlewares...))
	r.DELETE("/api/roles/{role_id}", lib.ChainMiddlewares(h.deleteRole, middlewares...))
	r.GET("/api/roles/{role_id}/permissions", lib.ChainMiddlewares(h.getRolePermissions, middlewares...))
	r.PUT("/api/roles/{role_id}/permissions", lib.ChainMiddlewares(h.setRolePermissions, middlewares...))

	// Current user permissions (for frontend RBAC context)
	r.GET("/api/enterprise/permissions", lib.ChainMiddlewares(h.getMyPermissions, middlewares...))

	// Audit logs (both paths for backward compat + official docs)
	r.GET("/api/enterprise/audit-logs", lib.ChainMiddlewares(h.queryAuditLogs, middlewares...))
	r.GET("/api/audit-logs", lib.ChainMiddlewares(h.queryAuditLogs, middlewares...))
	r.POST("/api/audit-logs/query", lib.ChainMiddlewares(h.advancedQueryAuditLogs, middlewares...))
	r.GET("/api/enterprise/audit-logs/stats", lib.ChainMiddlewares(h.auditLogStats, middlewares...))
}

// GetUserStore returns the user store.
func (h *EnterpriseHandler) GetUserStore() *enterprise.UserStore {
	return h.userStore
}

// GetAuditStore returns the audit store.
func (h *EnterpriseHandler) GetAuditStore() *enterprise.AuditStore {
	return h.auditStore
}

// =====================
// Enterprise Login/Logout
// =====================

func (h *EnterpriseHandler) login(ctx *fasthttp.RequestCtx) {
	payload := struct {
		Username string `json:"username"` // email or username
		Password string `json:"password"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	// Try enterprise user login first
	user, err := h.userStore.GetUserByEmail(ctx, payload.Username)
	if err != nil || user == nil {
		// Fall through — let the caller try /api/session/login for admin config auth
		h.auditAuth(ctx, "user_login", enterprise.StatusFailed, enterprise.SeverityMedium,
			"", payload.Username, "login", "", `{"reason":"user_not_found"}`)
		SendError(ctx, fasthttp.StatusUnauthorized, "Invalid username or password")
		return
	}

	if !user.IsActive {
		h.auditAuth(ctx, "user_login", enterprise.StatusBlocked, enterprise.SeverityHigh,
			user.ID, user.Email, "login", "", `{"reason":"account_disabled"}`)
		SendError(ctx, fasthttp.StatusForbidden, "Account is disabled")
		return
	}

	if !h.userStore.ValidatePassword(user, payload.Password) {
		h.auditAuth(ctx, "user_login", enterprise.StatusFailed, enterprise.SeverityMedium,
			user.ID, user.Email, "login", "", `{"reason":"invalid_password"}`)
		SendError(ctx, fasthttp.StatusUnauthorized, "Invalid username or password")
		return
	}

	// Create a session in the config store
	sessionToken := uuid.New().String()
	expiresAt := time.Now().Add(time.Hour * 24 * 30) // 30 days
	session := &tables.SessionsTable{
		Token:     sessionToken,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := h.configStore.CreateSession(ctx, session); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create session: %v", err))
		return
	}

	// Create the user-session mapping
	tokenHash := encrypt.HashSHA256(sessionToken)
	if err := h.userStore.CreateUserSession(ctx, user.ID, tokenHash, expiresAt); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create user session: %v", err))
		return
	}

	// Set cookie
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetKey("token")
	cookie.SetValue(sessionToken)
	cookie.SetExpire(expiresAt)
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	if string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" {
		cookie.SetSecure(true)
	}
	ctx.Response.Header.SetCookie(cookie)

	// Record login audit
	h.auditAuth(ctx, "user_login", enterprise.StatusSuccess, enterprise.SeverityLow,
		user.ID, user.Email, "login", "", fmt.Sprintf(`{"role":%q}`, user.Role))

	SendJSON(ctx, map[string]interface{}{
		"message": "Login successful",
		"user": map[string]interface{}{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

func (h *EnterpriseHandler) logout(ctx *fasthttp.RequestCtx) {
	// Get token from Authorization header or cookie
	token := string(ctx.Request.Header.Peek("Authorization"))
	token = strings.TrimPrefix(token, "Bearer ")
	if token == "" {
		token = string(ctx.Request.Header.Cookie("token"))
	}

	// Clear cookie
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetKey("token")
	cookie.SetValue("")
	cookie.SetExpire(time.Now().Add(-time.Hour * 24 * 30))
	cookie.SetPath("/")
	cookie.SetHTTPOnly(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)
	if string(ctx.Request.Header.Peek("X-Forwarded-Proto")) == "https" {
		cookie.SetSecure(true)
	}
	ctx.Response.Header.SetCookie(cookie)

	if token != "" {
		tokenHash := encrypt.HashSHA256(token)
		// Record audit before cleaning up
		_, userEmail, _, _ := enterprise.ExtractUserFromContext(ctx)
		if userEmail != "" {
			h.auditAuth(ctx, "user_logout", enterprise.StatusSuccess, enterprise.SeverityLow, "", userEmail, "session", "", "")
		}
		// Clean up enterprise user-session mapping
		_ = h.userStore.DeleteUserSessionByTokenHash(ctx, tokenHash)
		// Clean up base session
		_ = h.configStore.DeleteSession(ctx, token)
	}

	SendJSON(ctx, map[string]string{"message": "Logout successful"})
}

// =====================
// User Profile (Me)
// =====================

func (h *EnterpriseHandler) getMe(ctx *fasthttp.RequestCtx) {
	userID, _, role, teamID := enterprise.ExtractUserFromContext(ctx)
	if userID == "" {
		// Distinguish legacy admin session (role set to "Admin" by resolveUser)
		// from truly unauthenticated requests (role == ""). Previously both fell
		// into the legacy-admin branch, leaking Admin permissions to anonymous
		// callers who then rendered admin UI based on this response.
		if !strings.EqualFold(role, "Admin") {
			SendError(ctx, fasthttp.StatusUnauthorized, "Not authenticated")
			return
		}
		// Legacy admin session
		SendJSON(ctx, map[string]interface{}{
			"user":        nil,
			"role":        "Admin",
			"permissions": h.roleStore.GetPermissionsMap("Admin"),
			"team_id":     nil,
		})
		return
	}

	user, err := h.userStore.GetUser(ctx, userID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, "User not found")
		return
	}

	SendJSON(ctx, map[string]interface{}{
		"user":        user,
		"role":        role,
		"permissions": h.roleStore.GetPermissionsMap(role),
		"team_id":     teamID,
	})
}

func (h *EnterpriseHandler) updateMe(ctx *fasthttp.RequestCtx) {
	userID, _, _, _ := enterprise.ExtractUserFromContext(ctx)
	if userID == "" {
		SendError(ctx, fasthttp.StatusForbidden, "Legacy admin profile cannot be updated")
		return
	}

	var body map[string]interface{}
	if err := sonic.Unmarshal(ctx.PostBody(), &body); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	// Only allow name and email updates
	updates := make(map[string]interface{})
	if name, ok := body["name"].(string); ok && name != "" {
		updates["name"] = name
	}
	if email, ok := body["email"].(string); ok && email != "" {
		updates["email"] = email
	}
	if len(updates) == 0 {
		SendError(ctx, fasthttp.StatusBadRequest, "No valid fields to update")
		return
	}

	user, err := h.userStore.UpdateUser(ctx, userID, updates)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update profile: %v", err))
		return
	}

	h.audit(ctx, "update", "profile", userID, "")

	SendJSON(ctx, user)
}

func (h *EnterpriseHandler) isAdmin(ctx *fasthttp.RequestCtx) bool {
	_, _, role, _ := enterprise.ExtractUserFromContext(ctx)
	return strings.EqualFold(role, "Admin")
}

// Non-admin enterprise users are scoped to their own team. Self-access is always allowed.
func (h *EnterpriseHandler) canAccessUser(ctx *fasthttp.RequestCtx, target *enterprise.TableUser) bool {
	if target == nil {
		return false
	}
	if h.isAdmin(ctx) {
		return true
	}

	callerID, _, _, callerTeamID := enterprise.ExtractUserFromContext(ctx)
	if callerID == "" {
		return false
	}
	if target.ID == callerID {
		return true
	}
	if callerTeamID == nil || *callerTeamID == "" {
		return false
	}
	return target.TeamID != nil && *target.TeamID == *callerTeamID
}

func (h *EnterpriseHandler) canManageTeamMembers(ctx *fasthttp.RequestCtx, teamID string) bool {
	if h.isAdmin(ctx) {
		return true
	}
	_, _, _, callerTeamID := enterprise.ExtractUserFromContext(ctx)
	return callerTeamID != nil && *callerTeamID != "" && *callerTeamID == teamID
}

// =====================
// User CRUD
// =====================

func (h *EnterpriseHandler) getUserStats(ctx *fasthttp.RequestCtx) {
	stats, err := h.userStore.GetUserStats(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get user stats: %v", err))
		return
	}
	SendJSON(ctx, stats)
}

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
		payload.Role = "Viewer"
	}
	// Validate role exists
	if h.roleStore.GetRoleByName(payload.Role) == nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid role: %s", payload.Role))
		return
	}

	user, err := h.userStore.CreateUser(ctx, payload.Email, payload.Name, payload.Password, payload.Role, payload.TeamID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create user: %v", err))
		return
	}

	h.audit(ctx, "create", "user", user.ID, fmt.Sprintf(`{"email":%q,"role":%q}`, user.Email, user.Role))

	SendJSON(ctx, user)
}

func (h *EnterpriseHandler) getUser(ctx *fasthttp.RequestCtx) {
	userID, ok := ctx.UserValue("user_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid user ID")
		return
	}
	user, err := h.userStore.GetUser(ctx, userID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, "User not found")
		return
	}
	if !h.canAccessUser(ctx, user) {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		return
	}
	SendJSON(ctx, user)
}

func (h *EnterpriseHandler) listUsers(ctx *fasthttp.RequestCtx) {
	params := enterprise.UserListParams{
		Search: string(ctx.QueryArgs().Peek("search")),
		Role:   string(ctx.QueryArgs().Peek("role")),
	}
	params.Offset, _ = strconv.Atoi(string(ctx.QueryArgs().Peek("offset")))
	params.Limit, _ = strconv.Atoi(string(ctx.QueryArgs().Peek("limit")))

	// Filter by active status
	if isActiveStr := string(ctx.QueryArgs().Peek("is_active")); isActiveStr != "" {
		isActive := isActiveStr == "true"
		params.IsActive = &isActive
	}

	// Scope by team for all non-admin users
	if !h.isAdmin(ctx) {
		_, _, _, teamID := enterprise.ExtractUserFromContext(ctx)
		params.TeamID = teamID
	}

	users, total, err := h.userStore.ListUsers(ctx, params)
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
	userID, ok := ctx.UserValue("user_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid user ID")
		return
	}
	var body map[string]interface{}
	if err := sonic.Unmarshal(ctx.PostBody(), &body); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	targetUser, err := h.userStore.GetUser(ctx, userID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, "User not found")
		return
	}
	if !h.canAccessUser(ctx, targetUser) {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		return
	}

	// Handle password reset: admin only
	if newPassword, ok := body["password"].(string); ok && newPassword != "" {
		_, _, callerRole, _ := enterprise.ExtractUserFromContext(ctx)
		if callerRole != "Admin" {
			SendError(ctx, fasthttp.StatusForbidden, "Only admin can reset user passwords")
			return
		}
		if len(newPassword) < 8 {
			SendError(ctx, fasthttp.StatusBadRequest, "Password must be at least 8 characters")
			return
		}
		if err := h.userStore.UpdatePassword(ctx, userID, newPassword); err != nil {
			SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to reset password: %v", err))
			return
		}
	}

	delete(body, "password")
	delete(body, "id")
	if !h.isAdmin(ctx) {
		delete(body, "role")
		delete(body, "team_id")
		delete(body, "is_active")
	}

	user, err := h.userStore.UpdateUser(ctx, userID, body)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update user: %v", err))
		return
	}

	h.audit(ctx, "update", "user", userID, "")

	SendJSON(ctx, user)
}

func (h *EnterpriseHandler) deleteUser(ctx *fasthttp.RequestCtx) {
	userID, ok := ctx.UserValue("user_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid user ID")
		return
	}
	targetUser, err := h.userStore.GetUser(ctx, userID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, "User not found")
		return
	}
	if !h.canAccessUser(ctx, targetUser) {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		return
	}
	if err := h.userStore.DeleteUser(ctx, userID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to delete user: %v", err))
		return
	}

	h.audit(ctx, "delete", "user", userID, "")

	SendJSON(ctx, map[string]string{"message": "User deleted"})
}

// =====================
// Team Member Management
// =====================

func (h *EnterpriseHandler) listTeamMembers(ctx *fasthttp.RequestCtx) {
	teamID, ok := ctx.UserValue("team_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid team ID")
		return
	}
	if !h.canManageTeamMembers(ctx, teamID) {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		return
	}

	users, err := h.userStore.ListUsersByTeam(ctx, teamID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to list team members: %v", err))
		return
	}

	SendJSON(ctx, map[string]interface{}{
		"data":    users,
		"team_id": teamID,
	})
}

func (h *EnterpriseHandler) assignTeamMember(ctx *fasthttp.RequestCtx) {
	teamID, ok := ctx.UserValue("team_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid team ID")
		return
	}
	if !h.canManageTeamMembers(ctx, teamID) {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		return
	}

	payload := struct {
		UserID string `json:"user_id"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	if payload.UserID == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "user_id is required")
		return
	}
	targetUser, err := h.userStore.GetUser(ctx, payload.UserID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, "User not found")
		return
	}
	if !h.isAdmin(ctx) && targetUser.TeamID != nil && *targetUser.TeamID != teamID {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		return
	}

	if err := h.userStore.AssignUserToTeam(ctx, payload.UserID, teamID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to assign member: %v", err))
		return
	}

	h.audit(ctx, "update", "team_member", teamID, fmt.Sprintf(`{"user_id":%q,"action":"assign"}`, payload.UserID))

	SendJSON(ctx, map[string]string{"message": "Member assigned to team"})
}

func (h *EnterpriseHandler) removeTeamMember(ctx *fasthttp.RequestCtx) {
	teamID, ok := ctx.UserValue("team_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid team ID")
		return
	}
	if !h.canManageTeamMembers(ctx, teamID) {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		return
	}
	userID, ok := ctx.UserValue("user_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid user ID")
		return
	}
	targetUser, err := h.userStore.GetUser(ctx, userID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, "User not found")
		return
	}
	if !h.isAdmin(ctx) && (targetUser.TeamID == nil || *targetUser.TeamID != teamID) {
		SendError(ctx, fasthttp.StatusForbidden, "Forbidden")
		return
	}

	if err := h.userStore.RemoveUserFromTeam(ctx, userID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to remove member: %v", err))
		return
	}

	h.audit(ctx, "update", "team_member", teamID, fmt.Sprintf(`{"user_id":%q,"action":"remove"}`, userID))

	SendJSON(ctx, map[string]string{"message": "Member removed from team"})
}

// =====================
// Roles & Permissions
// =====================

func (h *EnterpriseHandler) listRoles(ctx *fasthttp.RequestCtx) {
	roles, err := h.roleStore.ListRoles(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to list roles: %v", err))
		return
	}
	SendJSON(ctx, roles)
}

func (h *EnterpriseHandler) getRole(ctx *fasthttp.RequestCtx) {
	roleID, ok := ctx.UserValue("role_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid role ID")
		return
	}
	role, err := h.roleStore.GetRole(ctx, roleID)
	if err != nil {
		SendError(ctx, fasthttp.StatusNotFound, "Role not found")
		return
	}
	SendJSON(ctx, role)
}

func (h *EnterpriseHandler) createRole(ctx *fasthttp.RequestCtx) {
	payload := struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	if payload.Name == "" {
		SendError(ctx, fasthttp.StatusBadRequest, "name is required")
		return
	}
	role, err := h.roleStore.CreateRole(ctx, payload.Name, payload.Description)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to create role: %v", err))
		return
	}
	h.audit(ctx, "create", "role", role.ID, fmt.Sprintf(`{"name":%q}`, role.Name))
	SendJSON(ctx, role)
}

func (h *EnterpriseHandler) updateRole(ctx *fasthttp.RequestCtx) {
	roleID, ok := ctx.UserValue("role_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid role ID")
		return
	}
	payload := struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}{}
	if err := json.Unmarshal(ctx.PostBody(), &payload); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	role, err := h.roleStore.UpdateRole(ctx, roleID, payload.Name, payload.Description)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update role: %v", err))
		return
	}
	h.audit(ctx, "update", "role", roleID, "")
	SendJSON(ctx, role)
}

func (h *EnterpriseHandler) deleteRole(ctx *fasthttp.RequestCtx) {
	roleID, ok := ctx.UserValue("role_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid role ID")
		return
	}
	if err := h.roleStore.DeleteRole(ctx, roleID); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, err.Error())
		return
	}
	h.audit(ctx, "delete", "role", roleID, "")
	SendJSON(ctx, map[string]string{"message": "Role deleted"})
}

func (h *EnterpriseHandler) getRolePermissions(ctx *fasthttp.RequestCtx) {
	roleID, ok := ctx.UserValue("role_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid role ID")
		return
	}
	perms, err := h.roleStore.GetRolePermissions(ctx, roleID)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get permissions: %v", err))
		return
	}
	SendJSON(ctx, perms)
}

func (h *EnterpriseHandler) setRolePermissions(ctx *fasthttp.RequestCtx) {
	roleID, ok := ctx.UserValue("role_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid role ID")
		return
	}
	var permissions []struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &permissions); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	if err := h.roleStore.SetRolePermissions(ctx, roleID, permissions); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to set permissions: %v", err))
		return
	}
	h.audit(ctx, "update", "role_permissions", roleID, fmt.Sprintf(`{"count":%d}`, len(permissions)))
	SendJSON(ctx, map[string]string{"message": "Permissions updated"})
}

func (h *EnterpriseHandler) getMyPermissions(ctx *fasthttp.RequestCtx) {
	userID, _, role, teamID := enterprise.ExtractUserFromContext(ctx)

	// No user context = not logged in, return empty permissions
	if userID == "" && role == "" {
		SendJSON(ctx, map[string]interface{}{
			"role":        "",
			"permissions": map[string]interface{}{},
			"team_id":     nil,
		})
		return
	}
	// Legacy admin (config-based auth, no enterprise user)
	if role == "" {
		role = "Admin"
	}
	SendJSON(ctx, map[string]interface{}{
		"role":        role,
		"permissions": h.roleStore.GetPermissionsMap(role),
		"team_id":     teamID,
	})
}

// =====================
// Audit Logs
// =====================

func (h *EnterpriseHandler) queryAuditLogs(ctx *fasthttp.RequestCtx) {
	q := enterprise.AuditLogQuery{
		EventType: string(ctx.QueryArgs().Peek("event_type")),
		Action:    string(ctx.QueryArgs().Peek("action")),
		Status:    string(ctx.QueryArgs().Peek("status")),
		Severity:  string(ctx.QueryArgs().Peek("severity")),
		UserID:    string(ctx.QueryArgs().Peek("user_id")),
		Resource:  string(ctx.QueryArgs().Peek("resource")),
		Search:    string(ctx.QueryArgs().Peek("search")),
	}
	q.Offset, _ = strconv.Atoi(string(ctx.QueryArgs().Peek("offset")))
	q.Limit, _ = strconv.Atoi(string(ctx.QueryArgs().Peek("limit")))

	if startStr := string(ctx.QueryArgs().Peek("start_date")); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			q.StartAt = &t
		}
	}
	if endStr := string(ctx.QueryArgs().Peek("end_date")); endStr != "" {
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
		"total_count":    total,
		"returned_count": len(logs),
		"audit_logs":     logs,
	})
}

func (h *EnterpriseHandler) advancedQueryAuditLogs(ctx *fasthttp.RequestCtx) {
	var body struct {
		Filters struct {
			EventTypes []string `json:"event_types"`
			DateRange  struct {
				Start string `json:"start"`
				End   string `json:"end"`
			} `json:"date_range"`
			Actors struct {
				UserIDs []string `json:"user_ids"`
			} `json:"actors"`
			Status   []string `json:"status"`
			Severity []string `json:"severity"`
		} `json:"filters"`
		Limit          int  `json:"limit"`
		IncludeDetails bool `json:"include_details"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &body); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	q := enterprise.AuditLogQuery{
		Limit: body.Limit,
	}
	if q.Limit == 0 {
		q.Limit = 100
	}
	// Use first values from arrays for basic filtering
	if len(body.Filters.EventTypes) > 0 {
		q.EventType = body.Filters.EventTypes[0]
	}
	if len(body.Filters.Status) > 0 {
		q.Status = body.Filters.Status[0]
	}
	if len(body.Filters.Severity) > 0 {
		q.Severity = body.Filters.Severity[0]
	}
	if len(body.Filters.Actors.UserIDs) > 0 {
		q.UserID = body.Filters.Actors.UserIDs[0]
	}
	if body.Filters.DateRange.Start != "" {
		if t, err := time.Parse(time.RFC3339, body.Filters.DateRange.Start); err == nil {
			q.StartAt = &t
		}
	}
	if body.Filters.DateRange.End != "" {
		if t, err := time.Parse(time.RFC3339, body.Filters.DateRange.End); err == nil {
			q.EndAt = &t
		}
	}

	logs, total, err := h.auditStore.Query(ctx, q)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to query: %v", err))
		return
	}
	SendJSON(ctx, map[string]interface{}{
		"total_count":    total,
		"returned_count": len(logs),
		"audit_logs":     logs,
	})
}

func (h *EnterpriseHandler) auditLogStats(ctx *fasthttp.RequestCtx) {
	stats, err := h.auditStore.Stats(ctx)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to get stats: %v", err))
		return
	}
	SendJSON(ctx, stats)
}
