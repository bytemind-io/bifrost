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
	enterprise "github.com/workpieces/bifrost/plugins/enterprise"
)

// EnterpriseHandler manages enterprise-specific HTTP endpoints.
type EnterpriseHandler struct {
	userStore   *enterprise.UserStore
	auditStore  *enterprise.AuditStore
	configStore configstore.ConfigStore
}

// NewEnterpriseHandler creates a new enterprise handler instance.
func NewEnterpriseHandler(userStore *enterprise.UserStore, auditStore *enterprise.AuditStore, configStore configstore.ConfigStore) *EnterpriseHandler {
	return &EnterpriseHandler{
		userStore:   userStore,
		auditStore:  auditStore,
		configStore: configStore,
	}
}

// RBACMiddleware returns a middleware that enforces role-based access control.
// It resolves the enterprise user from the session token hash, injects user info
// into the request context, and checks route permissions.
func (h *EnterpriseHandler) RBACMiddleware() schemas.BifrostHTTPMiddleware {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			path := string(ctx.Path())

			// Skip RBAC for whitelisted paths
			if path == "/health" ||
				strings.HasPrefix(path, "/api/session/") ||
				strings.HasPrefix(path, "/api/enterprise/login") {
				next(ctx)
				return
			}

			sessionToken, _ := ctx.UserValue(schemas.BifrostContextKeySessionToken).(string)

			// No session token means auth is disabled or request was whitelisted
			if sessionToken == "" {
				next(ctx)
				return
			}

			// Look up enterprise user by session token hash
			tokenHash := encrypt.HashSHA256(sessionToken)
			user, err := h.userStore.GetUserByTokenHash(ctx, tokenHash)
			if err != nil {
				// No enterprise user mapping — this is a legacy admin session
				// (logged in via config-based admin credentials). Grant admin role.
				ctx.SetUserValue(enterprise.CtxKeyUserRole, string(enterprise.RoleAdmin))
			} else {
				// Enterprise user found — inject user info into context
				ctx.SetUserValue(enterprise.CtxKeyUserID, user.ID)
				ctx.SetUserValue(enterprise.CtxKeyUserEmail, user.Email)
				ctx.SetUserValue(enterprise.CtxKeyUserRole, user.Role)
				ctx.SetUserValue(enterprise.CtxKeyUserTeamID, user.TeamID)
			}

			// Check route permission
			method := string(ctx.Method())
			role := enterprise.RoleAdmin
			if roleStr, ok := ctx.UserValue(enterprise.CtxKeyUserRole).(string); ok {
				role = enterprise.Role(roleStr)
			}

			if !enterprise.CheckRoutePermission(role, method, path) {
				SendError(ctx, fasthttp.StatusForbidden, "Insufficient permissions")
				return
			}

			next(ctx)

			// Audit logging: record successful governance mutations (POST/PUT/DELETE)
			if (method == "POST" || method == "PUT" || method == "DELETE") &&
				ctx.Response.StatusCode() >= 200 && ctx.Response.StatusCode() < 300 {
				h.recordGovernanceAudit(ctx, method, path)
			}
		}
	}
}

// recordGovernanceAudit records audit logs for governance CRUD operations.
func (h *EnterpriseHandler) recordGovernanceAudit(ctx *fasthttp.RequestCtx, method, path string) {
	// Only audit governance and enterprise API mutations
	if !strings.HasPrefix(path, "/api/governance/") && !strings.HasPrefix(path, "/api/enterprise/") {
		return
	}

	userID, userEmail, _, _ := enterprise.ExtractUserFromContext(ctx)
	if userEmail == "" {
		userEmail = "admin" // legacy admin session
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

	_ = h.auditStore.Record(ctx, userID, userEmail, action, resource, resourceID, "", ctx.RemoteAddr().String())
}

// RegisterRoutes registers enterprise API routes.
func (h *EnterpriseHandler) RegisterRoutes(r *router.Router, middlewares ...schemas.BifrostHTTPMiddleware) {
	// Enterprise login (separate from /api/session/login, supports enterprise users)
	r.POST("/api/enterprise/login", lib.ChainMiddlewares(h.login, middlewares...))

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

// GetUserStore returns the user store.
func (h *EnterpriseHandler) GetUserStore() *enterprise.UserStore {
	return h.userStore
}

// GetAuditStore returns the audit store.
func (h *EnterpriseHandler) GetAuditStore() *enterprise.AuditStore {
	return h.auditStore
}

// --- Enterprise Login ---

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
		SendError(ctx, fasthttp.StatusUnauthorized, "Invalid username or password")
		return
	}

	if !user.IsActive {
		SendError(ctx, fasthttp.StatusForbidden, "Account is disabled")
		return
	}

	if !h.userStore.ValidatePassword(user, payload.Password) {
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

	// Record audit log
	_ = h.auditStore.Record(ctx, user.ID, user.Email, "login", "session", "",
		fmt.Sprintf(`{"role":%q}`, user.Role), ctx.RemoteAddr().String())

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

	callerID, callerEmail, _, _ := enterprise.ExtractUserFromContext(ctx)
	_ = h.auditStore.Record(ctx, callerID, callerEmail, "create", "user", user.ID,
		fmt.Sprintf(`{"email":%q,"role":%q}`, user.Email, user.Role),
		ctx.RemoteAddr().String())

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
	userID, ok := ctx.UserValue("user_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid user ID")
		return
	}
	var updates map[string]interface{}
	if err := sonic.Unmarshal(ctx.PostBody(), &updates); err != nil {
		SendError(ctx, fasthttp.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	delete(updates, "password")
	delete(updates, "id")

	user, err := h.userStore.UpdateUser(ctx, userID, updates)
	if err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to update user: %v", err))
		return
	}

	callerID, callerEmail, _, _ := enterprise.ExtractUserFromContext(ctx)
	_ = h.auditStore.Record(ctx, callerID, callerEmail, "update", "user", userID, "", ctx.RemoteAddr().String())

	SendJSON(ctx, user)
}

func (h *EnterpriseHandler) deleteUser(ctx *fasthttp.RequestCtx) {
	userID, ok := ctx.UserValue("user_id").(string)
	if !ok {
		SendError(ctx, fasthttp.StatusBadRequest, "Invalid user ID")
		return
	}
	if err := h.userStore.DeleteUser(ctx, userID); err != nil {
		SendError(ctx, fasthttp.StatusInternalServerError, fmt.Sprintf("Failed to delete user: %v", err))
		return
	}

	callerID, callerEmail, _, _ := enterprise.ExtractUserFromContext(ctx)
	_ = h.auditStore.Record(ctx, callerID, callerEmail, "delete", "user", userID, "", ctx.RemoteAddr().String())

	SendJSON(ctx, map[string]string{"message": "User deleted"})
}

// --- Roles & Permissions ---

func (h *EnterpriseHandler) listRoles(ctx *fasthttp.RequestCtx) {
	SendJSON(ctx, enterprise.GetAllRoles())
}

func (h *EnterpriseHandler) getMyPermissions(ctx *fasthttp.RequestCtx) {
	_, _, role, teamID := enterprise.ExtractUserFromContext(ctx)
	if role == "" {
		// No enterprise user context — return admin permissions (legacy/config-based auth)
		SendJSON(ctx, map[string]interface{}{
			"role":        enterprise.RoleAdmin,
			"permissions": enterprise.GetPermissionsMap(enterprise.RoleAdmin),
			"team_id":     nil,
		})
		return
	}
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
