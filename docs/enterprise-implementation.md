# Bifrost Enterprise Implementation Reality Document

## 1. Purpose

This document describes the actual enterprise implementation currently present in this Bifrost-derived repository.

It replaces the older fixed-role design description and should be treated as a reality-based architecture document, not a greenfield proposal.

The most important correction is this:

- the current backend does not use a hard-coded `Admin / TeamManager / User / Viewer` authorization model
- the current enterprise backend uses dynamic roles stored in the database
- the system seeds a small set of system roles (`Admin`, `Developer`, `Viewer`) and allows custom roles with editable permissions
- the frontend enterprise surface is only partially implemented; some routes use real auth/RBAC wiring, while many enterprise pages are still fallback or contact-us placeholders

## 2. Current high-level architecture

The enterprise implementation is split across four main layers:

1. `plugins/enterprise`
   - persistent enterprise domain primitives
   - users
   - sessions
   - roles
   - role permissions
   - audit logs
   - route-permission matching helpers

2. `transports/bifrost-http/handlers/enterprise.go`
   - HTTP API for enterprise login, current user, users, roles, permissions, and audit logs
   - audit emission for auth and governance mutations

3. `transports/bifrost-http/server/server.go`
   - enterprise bootstrap and dependency wiring
   - creation of `UserStore`, `AuditStore`, and `RoleStore`
   - registration of `EnterpriseHandler`
   - insertion of enterprise RBAC middleware after auth middleware

4. `ui` enterprise alias/fallback structure
   - `@enterprise/*` imports are expected across the UI
   - `ui/tsconfig.json` maps `@enterprise/*` to `ui/app/enterprise/*` first, then to `ui/app/_fallbacks/enterprise/*`
   - today, the fallback tree provides most of the enterprise UI surface
   - some of those fallback pages are real enough to support login wiring, but many are only upsell/contact-us placeholders

## 3. What is actually implemented today

### 3.1 Backend storage and data model

The enterprise backend is not a stub. It already creates and uses dedicated tables for:

- `enterprise_users`
- `enterprise_user_sessions`
- `enterprise_roles`
- `enterprise_role_permissions`
- `enterprise_audit_logs`

These are created via `AutoMigrate` in the enterprise stores.

### 3.2 Enterprise users

Implemented in `plugins/enterprise/users.go`.

Current capabilities include:

- create enterprise users
- retrieve user by ID
- retrieve user by email
- list users with filters
- aggregate user stats
- update user fields
- update password
- delete user
- list users by team
- assign/remove team membership helpers
- validate password using bcrypt
- map auth sessions to enterprise users via token hash
- create/delete enterprise user sessions
- ensure a default admin exists

Important implementation details:

- passwords are stored as bcrypt hashes
- enterprise session linkage is done through `enterprise_user_sessions`
- session lookup is based on SHA-256 hash of the existing auth token
- `Role` is stored as a string on the user record and is validated by handler/store logic against the role system
- `TeamID` exists and is nullable, so team-scoped filtering is partially modeled at the data level

### 3.3 Enterprise roles and permissions

Implemented in `plugins/enterprise/roles.go`.

This is the biggest place where the old document was wrong.

The current system uses dynamic RBAC:

- roles are persisted in `enterprise_roles`
- permissions are persisted in `enterprise_role_permissions`
- a `RoleStore` loads them into an in-memory cache
- permission checks are resolved by role name or role ID
- system roles are seeded automatically on startup
- custom roles can be created, updated, deleted, and assigned permissions

Seeded system roles currently are:

- `Admin`
- `Developer`
- `Viewer`

Current backend resources include:

- `Logs`
- `ModelProvider`
- `Observability`
- `Plugins`
- `VirtualKeys`
- `UserProvisioning`
- `Users`
- `AuditLogs`
- `GuardrailsConfig`
- `GuardrailRules`
- `Cluster`
- `Settings`
- `MCPGateway`
- `AdaptiveRouter`

Current operations include:

- `View`
- `Create`
- `Update`
- `Delete`

Notes:

- the old document described `Read` and wildcard-style fixed role matrices; that is not the current main model
- current enforcement is dynamic and database-backed
- some frontend-facing aliases are synthesized from backend resources for UI compatibility

### 3.4 Frontend resource aliases already exist in backend RBAC mapping

The backend already knows that the frontend uses additional resource labels that do not exactly match backend resource names.

`RoleStore.GetPermissionsMap()` derives alias permissions for labels such as:

- `Customers`
- `Teams`
- `RBAC`
- `Governance`
- `RoutingRules`
- `GuardrailsProviders`
- `GuardrailRules`
- `PIIRedactor`
- `PromptRepository`
- `PromptDeploymentStrategy`
- `APIKeys`
- `Invitations`
- `Dashboard`

This means the backend is already compensating for frontend vocabulary drift.

That is useful, but it also means the contract is still partly implicit and should be normalized later.

### 3.5 Route-level RBAC enforcement

Implemented in `plugins/enterprise/middleware.go` and attached in `transports/bifrost-http/handlers/enterprise.go`.

Current behavior:

- API routes are mapped to required `{resource, operation}` pairs
- `CheckRoutePermission()` resolves permission based on the current user role
- `Admin` has an explicit fast-path allow
- unauthenticated users are denied except for whitelisted routes
- some routes are globally whitelisted for authenticated enterprise sessions

Current mapped route groups include at least:

- enterprise users
- enterprise audit logs
- enterprise team membership operations
- governance virtual keys
- governance teams
- governance customers
- governance budgets and rate limits
- governance routing rules
- governance model configs and providers
- settings/config
- providers/models/keys
- plugins
- logs
- MCP client management
- prompt repo
- oauth/cache related routes

This route map is already useful and non-trivial, but it is still hand-maintained and should be considered an area for future hardening.

### 3.6 Audit logging

Implemented in `plugins/enterprise/audit.go` plus usage in `handlers/enterprise.go`.

Current capabilities include:

- `enterprise_audit_logs` table
- asynchronous event channel with background worker
- synchronous `Record()` path for tests and critical paths
- event typing
- severity levels
- status tracking
- query with filters
- aggregate stats
- recent activity retrieval

Current audit event families include:

- `authentication`
- `authorization`
- `configuration_change`
- `data_access`
- `security_event`

Current status values include:

- `success`
- `failed`
- `blocked`

Current severity values include:

- `low`
- `medium`
- `high`
- `critical`

In `handlers/enterprise.go`, audit is already emitted for:

- login success/failure/block conditions
- governance and enterprise mutation paths after successful write operations

## 4. HTTP API currently exposed

The enterprise handler in `transports/bifrost-http/handlers/enterprise.go` already registers real routes.

### 4.1 Auth and current user

- `POST /api/enterprise/login`
- `POST /api/enterprise/logout`
- `GET /api/enterprise/me`
- `PUT /api/enterprise/me`
- `GET /api/enterprise/permissions`

Behavior notes:

- login uses enterprise user lookup by email/username field
- password validation uses bcrypt comparison
- successful login creates a normal session in the config store
- the session token is then hashed and linked to enterprise user identity
- cookie key is `token`

### 4.2 Users

- `GET /api/enterprise/users`
- `GET /api/enterprise/users/stats`
- `POST /api/enterprise/users`
- `GET /api/enterprise/users/{user_id}`
- `PUT /api/enterprise/users/{user_id}`
- `DELETE /api/enterprise/users/{user_id}`

### 4.3 Team membership

- `GET /api/enterprise/teams/{team_id}/members`
- `POST /api/enterprise/teams/{team_id}/members`
- `DELETE /api/enterprise/teams/{team_id}/members/{user_id}`

### 4.4 Roles

Note: roles currently register under `/api/roles`, not under `/api/enterprise/roles`.

Routes:

- `GET /api/roles`
- `POST /api/roles`
- `GET /api/roles/{role_id}`
- `PUT /api/roles/{role_id}`
- `DELETE /api/roles/{role_id}`
- `GET /api/roles/{role_id}/permissions`
- `PUT /api/roles/{role_id}/permissions`

This mixed prefix scheme is part of the current implementation reality and should be cleaned up later.

### 4.5 Audit logs

Currently exposed routes include:

- `GET /api/enterprise/audit-logs`
- `GET /api/audit-logs`
- `POST /api/audit-logs/query`
- `GET /api/enterprise/audit-logs/stats`

The duplicate paths suggest backward compatibility or transitional API exposure.

## 5. Server bootstrap and middleware wiring

In `transports/bifrost-http/server/server.go`, the server bootstrap already does the following when a config store database is available:

1. initialize `enterprise.NewUserStore(db)`
2. initialize `enterprise.NewAuditStore(db)`
3. initialize `enterprise.NewRoleStore(db)`
4. construct `handlers.NewEnterpriseHandler(...)`
5. seed a default admin user if no admin exists
6. append enterprise RBAC middleware after auth middleware

Important current default seed behavior:

- email: `admin@bifrost.local`
- name: `Admin`
- password: `admin`

This is acceptable only as a development bootstrap mechanism.
It is not production-safe.

## 6. Current auth and RBAC request flow

The current request flow for enterprise-protected APIs is approximately:

1. request hits auth middleware
2. auth middleware resolves a session token
3. enterprise RBAC middleware reads the session token from context
4. token is SHA-256 hashed
5. `UserStore.GetUserByTokenHash()` resolves the enterprise user
6. middleware injects into request context:
   - user ID
   - user email
   - user role
   - team ID
7. middleware checks whether the route is whitelisted
8. if not whitelisted, `CheckRoutePermission()` verifies role permission against the route map
9. on success, request continues
10. successful mutation paths may emit governance/configuration audit events

There is also a backward-compatibility behavior:

- if a session exists but no enterprise user mapping is found, middleware falls back to role `Admin`

That behavior helps legacy admin sessions continue to work, but it also means the system is still in a transitional state between legacy admin auth and full enterprise identity.

## 7. UI implementation reality

The UI layer is not fully implemented as a real enterprise application yet.

### 7.1 Alias-based enterprise import model

The main UI imports enterprise modules through `@enterprise/*`.

`ui/tsconfig.json` maps these imports to:

1. `ui/app/enterprise/*`
2. `ui/app/_fallbacks/enterprise/*`

This means:

- if a real enterprise implementation exists under `ui/app/enterprise`, it wins
- otherwise the fallback implementation is used

Today, the fallback tree is still carrying most of the enterprise UI surface.

### 7.2 What is real vs placeholder in fallback UI

Based on current repository inspection:

Real wiring exists at least in:

- `components/login/loginView.tsx`
  - real client component
  - auth state query
  - login mutation
  - token validity handling
  - redirect behavior
  - error state handling

Placeholder/upsell views currently exist at least in:

- `components/rbac/rbacView.tsx`
- `components/user-groups/usersView.tsx`
- `components/audit-logs/auditLogsView.tsx`

Those views currently render a `ContactUsView` instead of a production enterprise management screen.

This means the frontend maturity is mixed:

- authentication path is partly real
- permissions context integration points exist
- many enterprise pages are still sales placeholders rather than working product screens

### 7.3 Fallback RBAC context is permissive

`ui/app/_fallbacks/enterprise/lib/contexts/rbacContext.tsx` is intentionally permissive.

Current fallback behavior includes:

- `RbacProvider` always allows all permissions
- `useRbac()` always returns `true`
- `useRbacContext()` returns permissive defaults outside a provider

This file is useful as an OSS fallback, but it must not be mistaken for actual enforced frontend authorization.

Backend enforcement is real.
Frontend fallback authorization is currently mostly a compatibility stub.

## 8. What the old document got wrong

The older version of this document is outdated in several important ways.

### 8.1 Fixed-role model is no longer accurate

Old description:

- `Admin`
- `TeamManager`
- `User`
- `Viewer`
- hard-coded permission matrix

Current reality:

- DB-backed dynamic roles
- seeded system roles are `Admin`, `Developer`, `Viewer`
- custom roles can be created and permissioned

### 8.2 Enterprise UI is not fully replaced yet

Old description implied a clean move to `ui/app/enterprise/` with complete real components.

Current reality:

- aliasing exists
- fallback tree is still heavily used
- several major enterprise pages are still contact-us placeholders

### 8.3 Middleware integration is broader than originally described

Old description framed middleware as a small isolated extension.

Current reality:

- enterprise RBAC is wired into the main HTTP server boot path
- it depends on session auth, config store DB, and route-level governance APIs
- audit logging is coupled to enterprise mutations and authentication events

### 8.4 Enterprise is no longer just a UI visibility feature

Old description emphasized page visibility and fixed-role UI gating.

Current reality:

- backend role enforcement exists
- route permission checks exist
- role CRUD exists
- user CRUD exists
- audit querying and stats exist
- the biggest gap is now end-to-end closure and frontend replacement, not raw backend existence

## 9. Current gaps and incompletions

Even though the backend is meaningfully implemented, the enterprise system is not yet complete.

### 9.1 Contract drift between backend and frontend

There is still vocabulary drift between:

- backend canonical resources
- route permission map
- frontend sidebar/resource names
- fallback RBAC enums

The backend currently compensates with aliases, but this should be normalized into a single source of truth.

### 9.2 Mixed route prefixes

Examples:

- users use `/api/enterprise/users`
- roles use `/api/roles`
- audit logs use both `/api/enterprise/audit-logs` and `/api/audit-logs`

This works, but the API surface is inconsistent.

### 9.3 Production bootstrap is not hardened

The current automatic default admin creation with password `admin` is not production-safe.

A production-ready enterprise version should instead require one of:

- first-run bootstrap flow
- environment-driven one-time bootstrap credentials
- forced password rotation on first login
- bootstrap disable flag after initial provisioning

### 9.4 Team/customer scope is only partially closed-loop

The data model contains `TeamID`, and the route permissions reference governance concepts like teams and customers.

But full data-scope enforcement and end-to-end team/customer isolation rules are not yet fully documented or proven across all governance endpoints.

### 9.5 Frontend enterprise pages are still incomplete

Users, RBAC, and audit-log management pages still need real implementations that talk to the backend APIs rather than rendering marketing placeholders.

### 9.6 OSS fallback remains permissive by design

That is fine for fallback behavior, but if the goal is a real enterprise product, a dedicated `ui/app/enterprise` implementation must replace permissive fallback components for enterprise builds.

## 10. Recommended interpretation for future work

Anyone continuing enterprise development in this repository should assume the following:

1. enterprise backend primitives already exist and should be extended, not rewritten from scratch
2. the current authorization model is dynamic RBAC, not fixed roles
3. the main unfinished area is frontend and contract normalization, not basic persistence
4. `plugins/enterprise` is the core domain layer for enterprise identity, role, and audit concerns
5. `handlers/enterprise.go` is already the active control-plane API entrypoint
6. `server.go` already wires enterprise into the main runtime
7. the fallback UI is a transitional compatibility layer, not the target enterprise product surface

## 11. Immediate documentation and engineering priorities

The next logical implementation priorities are:

1. normalize the resource/operation contract across backend and frontend
2. replace placeholder enterprise pages with real implementations for:
   - users
   - RBAC
   - audit logs
3. harden production bootstrap and default-admin provisioning
4. document and enforce team/customer scope rules consistently
5. reduce route-prefix inconsistency where practical
6. add fuller test coverage for:
   - role CRUD
   - permission updates
   - user lifecycle
   - auth/session mapping
   - audit query/stats
   - end-to-end RBAC enforcement

## 12. Summary

The enterprise implementation in this repository is already real, but uneven.

What already exists:

- enterprise users
- enterprise sessions
- dynamic roles
- dynamic permissions
- route-level RBAC
- enterprise login/logout/me
- role APIs
- user APIs
- audit logging and querying
- server bootstrap wiring

What is still incomplete:

- a fully real enterprise frontend library
- real users/RBAC/audit management pages
- contract cleanup between backend/frontend resource names
- production-safe bootstrap
- fully documented scope rules for governance data filtering

So the correct framing is not:

- "enterprise needs to be built from zero"

The correct framing is:

- "enterprise backend foundations already exist, and the remaining work is to close the product, frontend, and operational gaps around them"
