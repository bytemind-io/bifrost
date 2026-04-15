# Enterprise Permission Matrix

## Protected Resources (14)

| Resource | Description | Scope |
|----------|-------------|-------|
| Logs | Request and response logs | Global |
| ModelProvider | AI model provider configurations | Global |
| Observability | Monitoring and metrics dashboards | Global |
| Plugins | Plugin configurations and management | Global |
| VirtualKeys | Virtual key management | Team-scoped for Developer |
| UserProvisioning | User and group provisioning settings | Admin only |
| Users | User account management | Admin only (mutations) |
| AuditLogs | Audit trail and compliance logs | Admin only |
| GuardrailsConfig | Guardrail configurations | Global |
| GuardrailRules | Individual guardrail rules | Global |
| Cluster | Cluster configuration and nodes | Global |
| Settings | Workspace settings | Admin only (mutations) |
| MCPGateway | MCP Gateway configurations | Global |
| AdaptiveRouter | Adaptive routing settings | Global |

## Operations (4)

| Operation | Description |
|-----------|-------------|
| View | Read-only access |
| Create | Create new instances |
| Update | Modify existing resources |
| Delete | Remove resources |

## System Roles

### Admin (56 permissions)
All resources, all operations.

### Developer (31 permissions)

| Resource | View | Create | Update | Delete |
|----------|------|--------|--------|--------|
| Logs | Y | - | - | - |
| ModelProvider | Y | Y | Y | Y |
| Observability | Y | - | - | - |
| Plugins | Y | Y | Y | Y |
| VirtualKeys | Y | Y | Y | Y |
| Users | Y | - | - | - |
| AuditLogs | Y | - | - | - |
| GuardrailsConfig | Y | Y | Y | Y |
| GuardrailRules | Y | Y | Y | Y |
| Cluster | Y | - | - | - |
| Settings | Y | - | - | - |
| MCPGateway | Y | Y | Y | Y |
| AdaptiveRouter | Y | - | - | - |

### Viewer (14 permissions)
All resources: View only.

## Data-Level Filtering

| Resource | Admin | Developer | Viewer |
|----------|-------|-----------|--------|
| Virtual Keys | All | Own team only | All (read-only) |
| Teams | All | Own team only | All |
| Customers | All | Own team's customer | All |
| Others | All | All (as allowed by route RBAC) | All (read-only) |

## Frontend Resource Aliases

These frontend resources map to backend resources for sidebar visibility:

| Frontend | Backend |
|----------|---------|
| Customers | VirtualKeys |
| Teams | VirtualKeys |
| RBAC | Users |
| Governance | VirtualKeys |
| RoutingRules | AdaptiveRouter |
| GuardrailsProviders | GuardrailsConfig |
| PIIRedactor | GuardrailsConfig |
| PromptRepository | Plugins |
| PromptDeploymentStrategy | Plugins |

## Route Whitelist (any authenticated user)

```
/api/session/*
/api/enterprise/login
/api/enterprise/logout
/api/enterprise/permissions
/api/enterprise/me
/api/config
/api/version
/ws
/health
GET /api/roles (read-only)
```

## API Endpoints

### Enterprise Identity
| Method | Path | Resource | Operation |
|--------|------|----------|-----------|
| POST | /api/enterprise/login | - | Whitelisted |
| POST | /api/enterprise/logout | - | Whitelisted |
| GET | /api/enterprise/me | - | Whitelisted |
| PUT | /api/enterprise/me | - | Whitelisted |
| GET | /api/enterprise/permissions | - | Whitelisted |
| GET | /api/enterprise/users | Users | View |
| POST | /api/enterprise/users | Users | Create |
| PUT | /api/enterprise/users/{id} | Users | Update |
| DELETE | /api/enterprise/users/{id} | Users | Delete |
| GET | /api/enterprise/users/stats | Users | View |

### Roles
| Method | Path | Resource | Operation |
|--------|------|----------|-----------|
| GET | /api/roles | - | Read-only public |
| POST | /api/roles | Users | Create |
| PUT | /api/roles/{id} | Users | Update |
| DELETE | /api/roles/{id} | Users | Delete |
| GET | /api/roles/{id}/permissions | - | Read-only public |
| PUT | /api/roles/{id}/permissions | Users | Update |

### Audit
| Method | Path | Resource | Operation |
|--------|------|----------|-----------|
| GET | /api/audit-logs | AuditLogs | View |
| POST | /api/audit-logs/query | AuditLogs | View |
| GET | /api/enterprise/audit-logs/stats | AuditLogs | View |

Note: Audit log endpoints additionally enforce Admin-only access in the handler.
