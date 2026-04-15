# Enterprise Operations Guide

## Bootstrap

### First-Time Setup

1. Set admin credentials via environment variables:
```bash
export BIFROST_ADMIN_EMAIL=admin@yourcompany.com
export BIFROST_ADMIN_PASSWORD=your-secure-password
```

2. Start Bifrost:
```bash
./bifrost-http -port 8080
```

3. Open `http://localhost:8080` and login with your admin credentials.

### Development Mode

Without environment variables, Bifrost seeds a default admin:
- Email: `admin@bifrost.local`
- Password: `admin`

**Do not use default credentials in production.**

## Configuration

### config.json

```json
{
  "$schema": "https://www.getbifrost.ai/schema",
  "config_store": {
    "enabled": true,
    "type": "sqlite",
    "config": { "path": "/data/config.db" }
  },
  "logs_store": {
    "enabled": true,
    "type": "sqlite",
    "config": { "path": "/data/logs.db" }
  },
  "client": {
    "enable_logging": true,
    "log_retention_days": 365,
    "allowed_origins": ["*"]
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BIFROST_ADMIN_EMAIL` | Admin email for first-time seed | `admin@bifrost.local` |
| `BIFROST_ADMIN_PASSWORD` | Admin password for first-time seed | `admin` |
| `APP_PORT` | Server port | `8080` |
| `BIFROST_HOST` | Server host | `localhost` |
| `LOG_LEVEL` | Log level (info/debug/warn/error) | `info` |

## Role Management

### System Roles

| Role | Permissions | Editable |
|------|------------|----------|
| Admin | 56 (all) | Permissions yes, name no, cannot delete |
| Developer | 31 | Permissions yes, name no, cannot delete |
| Viewer | 14 | Permissions yes, name no, cannot delete |

### Custom Roles

Create via UI (Governance > Roles & Permissions > Add Role) or API:

```bash
# Create role
curl -X POST http://localhost:8080/api/roles \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Auditor", "description": "Compliance auditing"}'

# Assign permissions
curl -X PUT http://localhost:8080/api/roles/{id}/permissions \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '[{"resource":"AuditLogs","operation":"View"},{"resource":"Logs","operation":"View"}]'
```

## User Management

### Create User

```bash
curl -X POST http://localhost:8080/api/enterprise/users \
  -H "Content-Type: application/json" \
  -b cookie.txt \
  -d '{"email":"user@example.com","name":"User","password":"securepass","role":"Developer","team_id":"optional-team-id"}'
```

### Reset Password (Admin only)

```bash
curl -X PUT http://localhost:8080/api/enterprise/users/{id} \
  -H "Content-Type: application/json" \
  -b cookie.txt \
  -d '{"password":"new-password"}'
```

## Database Tables

| Table | Purpose |
|-------|---------|
| `enterprise_users` | User accounts |
| `enterprise_user_sessions` | Session-to-user mapping |
| `enterprise_roles` | Role definitions |
| `enterprise_role_permissions` | Role permission assignments |
| `enterprise_audit_logs` | Immutable audit trail |

## Audit Logs

Audit logs are:
- **Immutable** — no delete API exists
- **Admin-only** — only Admin role can query
- **Async** — recorded via event channel, non-blocking
- **Comprehensive** — authentication, configuration changes, privilege changes

Query via API:
```bash
curl "http://localhost:8080/api/audit-logs?event_type=authentication&severity=medium&limit=50" \
  -b cookie.txt
```

## Backup

```bash
# SQLite databases
cp /data/config.db /backup/config-$(date +%Y%m%d).db
cp /data/logs.db /backup/logs-$(date +%Y%m%d).db
```

## Upgrade

1. Stop the current instance
2. Replace the binary
3. Start — GORM auto-migrates new columns/tables
4. Verify: `curl http://localhost:8080/health`
