# Bifrost Enterprise Module

Dynamic RBAC with role management for Bifrost.

## Architecture

```
Layer 1: Authentication — Session token / Cookie
Layer 2: Route RBAC    — Role × Resource × Operation
Layer 3: Data Filtering — Team-scoped data access
```

## Roles

### System Roles (seeded on startup)

| Role | Permissions | Description |
|------|------------|-------------|
| Admin | 56 (all) | Full access to all resources and operations |
| Developer | 27 | CRUD access to technical resources, view access to logs and cluster |
| Viewer | 14 | Read-only access to all resources |

System roles cannot be deleted. Their permissions can be customized.

### Custom Roles

Create custom roles via API or UI for specialized access patterns:
- **Auditor** — AuditLogs (View), Logs (View), Users (View)
- **QA Team** — GuardrailsConfig (CRUD), VirtualKeys (View)
- **Ops** — Cluster (CRUD), Observability (View), Settings (View, Update)

## Protected Resources (14)

| Resource | Description |
|----------|-------------|
| Logs | Request and response logs |
| ModelProvider | AI model provider configurations |
| Observability | Monitoring and metrics dashboards |
| Plugins | Plugin configurations and management |
| VirtualKeys | Virtual key management |
| UserProvisioning | User and group provisioning settings |
| Users | User account management |
| AuditLogs | Audit trail and compliance logs |
| GuardrailsConfig | Guardrail configurations |
| GuardrailRules | Individual guardrail rules |
| Cluster | Cluster configuration and nodes |
| Settings | Workspace settings |
| MCPGateway | MCP Gateway configurations |
| AdaptiveRouter | Adaptive routing settings |

## Operations (4)

| Operation | Description |
|-----------|-------------|
| View | Read-only access to view the resource |
| Create | Ability to create new instances |
| Update | Ability to modify existing resources |
| Delete | Ability to remove resources |

## API Endpoints

### Roles CRUD

```
GET    /api/roles                      — List all roles with permission counts
POST   /api/roles                      — Create custom role
GET    /api/roles/{id}                 — Get role details
PUT    /api/roles/{id}                 — Update role name/description
DELETE /api/roles/{id}                 — Delete custom role (system roles protected)
GET    /api/roles/{id}/permissions     — Get role's permissions
PUT    /api/roles/{id}/permissions     — Set role's permissions (replace all)
```

### User Management

```
GET    /api/enterprise/users           — List users (?search=&role=&is_active=)
GET    /api/enterprise/users/stats     — User statistics
POST   /api/enterprise/users           — Create user (role validated against RoleStore)
PUT    /api/enterprise/users/{id}      — Update user (admin can reset password)
DELETE /api/enterprise/users/{id}      — Delete user
GET    /api/enterprise/me              — Current user profile + permissions
PUT    /api/enterprise/me              — Update own profile
```

### Auth

```
POST   /api/enterprise/login           — Enterprise login (email/password)
POST   /api/enterprise/logout          — Logout (clean session)
GET    /api/enterprise/permissions      — Current user's permission map (for frontend RBAC)
```

### Team Members

```
GET    /api/enterprise/teams/{id}/members         — List team members
POST   /api/enterprise/teams/{id}/members         — Assign user to team
DELETE /api/enterprise/teams/{id}/members/{uid}    — Remove user from team
```

### Audit Logs

```
GET    /api/enterprise/audit-logs      — Query audit logs (?action=&resource=&search=)
```

## Database Tables

| Table | Description |
|-------|-------------|
| `enterprise_roles` | Role definitions (system + custom) |
| `enterprise_role_permissions` | Role → Resource × Operation mappings |
| `enterprise_users` | User accounts (bcrypt passwords, role name, team_id) |
| `enterprise_user_sessions` | Session token hash → user ID |
| `enterprise_audit_logs` | Audit trail (async, event-driven) |

## Data-Level Filtering

| Role | Virtual Keys | Teams | Customers |
|------|-------------|-------|-----------|
| Admin | All | All | All |
| Developer | Own team only | Own team only | Own team's customer |
| Viewer | All (read-only) | All | All |
| Custom | Depends on team_id | Depends on team_id | Depends on team_id |

## Files

```
plugins/enterprise/
  roles.go        — RoleStore with DB + in-memory cache, system role seeding
  users.go        — UserStore CRUD, sessions, team members, stats
  audit.go        — AuditStore with event-driven async recording
  middleware.go   — Route permission mapping, 14 resources, context extraction
```
