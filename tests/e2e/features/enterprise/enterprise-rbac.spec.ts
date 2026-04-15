import { test, expect } from '@playwright/test'

const BASE = process.env.BIFROST_URL || 'http://localhost:8080'

// Helper: login and return cookie header (extract just the token value)
async function login(request: any, email: string, password: string): Promise<string> {
  const res = await request.post(`${BASE}/api/enterprise/login`, {
    data: { username: email, password },
  })
  const raw = res.headers()['set-cookie'] || ''
  // Extract "token=xxx" from "token=xxx; Path=/; HttpOnly; ..."
  const match = raw.match(/token=([^;]+)/)
  return match ? `token=${match[1]}` : raw
}

// Helper: make authenticated request
async function authGet(request: any, path: string, cookie: string) {
  return request.get(`${BASE}${path}`, {
    headers: { Cookie: cookie },
  })
}

async function authPost(request: any, path: string, cookie: string, data: any) {
  return request.post(`${BASE}${path}`, {
    headers: { Cookie: cookie, 'Content-Type': 'application/json' },
    data,
  })
}

async function authDelete(request: any, path: string, cookie: string) {
  return request.delete(`${BASE}${path}`, {
    headers: { Cookie: cookie },
  })
}

test.describe('Enterprise RBAC E2E', () => {
  let adminCookie: string

  test.beforeAll(async ({ request }) => {
    // Login as admin
    adminCookie = await login(request, 'admin@bifrost.local', 'admin')
    expect(adminCookie).toBeTruthy()
  })

  test('unauthenticated: permissions returns empty', async ({ request }) => {
    const res = await request.get(`${BASE}/api/enterprise/permissions`)
    expect(res.ok()).toBeTruthy()
    const data = await res.json()
    expect(data.role).toBe('')
    expect(Object.keys(data.permissions)).toHaveLength(0)
  })

  test('unauthenticated: non-whitelisted routes return 403', async ({ request }) => {
    const res = await request.get(`${BASE}/api/governance/virtual-keys`)
    expect(res.status()).toBe(403)
  })

  test('unauthenticated: whitelisted routes work', async ({ request }) => {
    const res = await request.get(`${BASE}/api/config`)
    expect(res.ok()).toBeTruthy()
  })

  test('admin: has full permissions', async ({ request }) => {
    const res = await authGet(request, '/api/enterprise/permissions', adminCookie)
    expect(res.ok()).toBeTruthy()
    const data = await res.json()
    expect(data.permissions.VirtualKeys.View).toBe(true)
    expect(data.permissions.VirtualKeys.Create).toBe(true)
    expect(data.permissions.VirtualKeys.Delete).toBe(true)
    expect(data.permissions.Settings.Update).toBe(true)
  })

  test('admin: can list roles', async ({ request }) => {
    const res = await authGet(request, '/api/roles', adminCookie)
    expect(res.ok()).toBeTruthy()
    const roles = await res.json()
    expect(roles.length).toBeGreaterThanOrEqual(3)
    const names = roles.map((r: any) => r.name)
    expect(names).toContain('Admin')
    expect(names).toContain('Developer')
    expect(names).toContain('Viewer')
  })

  test('admin: can create custom role and assign permissions', async ({ request }) => {
    const roleName = `E2E-Auditor-${Date.now()}`

    // Create custom role
    const createRes = await authPost(request, '/api/roles', adminCookie, {
      name: roleName,
      description: 'E2E test role',
    })
    expect(createRes.ok()).toBeTruthy()
    const role = await createRes.json()
    expect(role.name).toBe(roleName)
    expect(role.is_system).toBe(false)

    // Assign permissions
    const permRes = await request.put(`${BASE}/api/roles/${role.id}/permissions`, {
      headers: { Cookie: adminCookie, 'Content-Type': 'application/json' },
      data: [
        { resource: 'AuditLogs', operation: 'View' },
        { resource: 'Logs', operation: 'View' },
      ],
    })
    expect(permRes.ok()).toBeTruthy()

    // Verify permissions
    const getPermRes = await authGet(request, `/api/roles/${role.id}/permissions`, adminCookie)
    const perms = await getPermRes.json()
    expect(perms.length).toBe(2)

    // Cleanup
    await authDelete(request, `/api/roles/${role.id}`, adminCookie)
  })

  test('admin: cannot delete system role', async ({ request }) => {
    const rolesRes = await authGet(request, '/api/roles', adminCookie)
    const roles = await rolesRes.json()
    const admin = roles.find((r: any) => r.name === 'Admin')
    expect(admin).toBeTruthy()

    const delRes = await authDelete(request, `/api/roles/${admin.id}`, adminCookie)
    expect(delRes.status()).toBe(400)
  })

  test('admin: can create user and login as that user', async ({ request }) => {
    // Create developer user
    const createRes = await authPost(request, '/api/enterprise/users', adminCookie, {
      email: 'e2e-dev@test.com',
      name: 'E2E Developer',
      password: 'testpass123',
      role: 'Developer',
    })
    if (!createRes.ok()) {
      // User might already exist from previous run
      return
    }
    const user = await createRes.json()
    expect(user.role).toBe('Developer')

    // Login as developer
    const devCookie = await login(request, 'e2e-dev@test.com', 'testpass123')

    // Developer permissions should be limited
    const permRes = await authGet(request, '/api/enterprise/permissions', devCookie)
    const data = await permRes.json()
    expect(data.permissions.VirtualKeys.View).toBe(true)
    expect(data.permissions.VirtualKeys.Create).toBe(true)
    expect(data.permissions.Settings.Update).toBe(false)

    // Developer cannot access audit logs
    const auditRes = await authGet(request, '/api/audit-logs?limit=1', devCookie)
    expect(auditRes.status()).toBe(403)

    // Cleanup
    await authDelete(request, `/api/enterprise/users/${user.id}`, adminCookie)
  })

  test('viewer: read-only access', async ({ request }) => {
    // Create viewer user
    const createRes = await authPost(request, '/api/enterprise/users', adminCookie, {
      email: 'e2e-viewer@test.com',
      name: 'E2E Viewer',
      password: 'testpass123',
      role: 'Viewer',
    })
    if (!createRes.ok()) return

    const user = await createRes.json()
    const viewerCookie = await login(request, 'e2e-viewer@test.com', 'testpass123')

    // Viewer can read VKs
    const vkRes = await authGet(request, '/api/governance/virtual-keys', viewerCookie)
    expect(vkRes.ok()).toBeTruthy()

    // Viewer cannot create VK
    const createVkRes = await authPost(request, '/api/governance/virtual-keys', viewerCookie, {
      name: 'e2e-hack-key',
    })
    expect(createVkRes.status()).toBe(403)

    // Viewer cannot delete customer
    const delRes = await authDelete(request, '/api/governance/customers/fake-id', viewerCookie)
    expect(delRes.status()).toBe(403)

    // Cleanup
    await authDelete(request, `/api/enterprise/users/${user.id}`, adminCookie)
  })

  test('admin: password reset works', async ({ request }) => {
    // Create user
    const createRes = await authPost(request, '/api/enterprise/users', adminCookie, {
      email: 'e2e-pwreset@test.com',
      name: 'PW Reset Test',
      password: 'oldpass123',
      role: 'Viewer',
    })
    if (!createRes.ok()) return
    const user = await createRes.json()

    // Reset password
    const resetRes = await request.put(`${BASE}/api/enterprise/users/${user.id}`, {
      headers: { Cookie: adminCookie, 'Content-Type': 'application/json' },
      data: { password: 'newpass456' },
    })
    expect(resetRes.ok()).toBeTruthy()

    // Login with new password
    const loginRes = await request.post(`${BASE}/api/enterprise/login`, {
      data: { username: 'e2e-pwreset@test.com', password: 'newpass456' },
    })
    expect(loginRes.ok()).toBeTruthy()

    // Old password should fail
    const oldLoginRes = await request.post(`${BASE}/api/enterprise/login`, {
      data: { username: 'e2e-pwreset@test.com', password: 'oldpass123' },
    })
    expect(oldLoginRes.status()).toBe(401)

    // Cleanup
    await authDelete(request, `/api/enterprise/users/${user.id}`, adminCookie)
  })

  test('audit: login events are recorded', async ({ request }) => {
    // Make a failed login
    await request.post(`${BASE}/api/enterprise/login`, {
      data: { username: 'nonexistent@test.com', password: 'wrong' },
    })

    // Check audit logs
    const res = await authGet(request, '/api/audit-logs?event_type=authentication&limit=5', adminCookie)
    expect(res.ok()).toBeTruthy()
    const data = await res.json()
    expect(data.total_count).toBeGreaterThan(0)
    const failed = data.audit_logs.find((l: any) => l.status === 'failed')
    expect(failed).toBeTruthy()
    expect(failed.event_type).toBe('authentication')
  })

  test('audit: stats endpoint works', async ({ request }) => {
    const res = await authGet(request, '/api/enterprise/audit-logs/stats', adminCookie)
    expect(res.ok()).toBeTruthy()
    const stats = await res.json()
    expect(stats.total).toBeGreaterThan(0)
    expect(stats.by_event_type).toBeDefined()
    expect(stats.by_severity).toBeDefined()
    expect(stats.by_status).toBeDefined()
  })

  test('data filtering: developer sees only own team data', async ({ request }) => {
    // Create team
    const teamRes = await authPost(request, '/api/governance/teams', adminCookie, {
      name: 'E2E-FilterTeam',
    })
    if (!teamRes.ok()) return
    const team = (await teamRes.json()).team

    // Create VK under team
    const vkRes = await authPost(request, '/api/governance/virtual-keys', adminCookie, {
      name: 'e2e-team-vk',
      team_id: team.id,
      provider_configs: [{ provider: 'openai' }],
    })
    const vk = vkRes.ok() ? (await vkRes.json()).virtual_key : null

    // Create developer in team
    const devRes = await authPost(request, '/api/enterprise/users', adminCookie, {
      email: 'e2e-scoped@test.com',
      name: 'Scoped Dev',
      password: 'testpass123',
      role: 'Developer',
      team_id: team.id,
    })
    if (!devRes.ok()) return
    const dev = await devRes.json()

    // Login as developer
    const devCookie = await login(request, 'e2e-scoped@test.com', 'testpass123')

    // Developer should only see team's VKs
    const vksRes = await authGet(request, '/api/governance/virtual-keys', devCookie)
    const vks = (await vksRes.json()).virtual_keys || []
    for (const v of vks) {
      expect(v.team_id).toBe(team.id)
    }

    // Developer should only see own team
    const teamsRes = await authGet(request, '/api/governance/teams', devCookie)
    const teams = (await teamsRes.json()).teams || []
    expect(teams.length).toBe(1)

    // Cleanup
    if (vk) await authDelete(request, `/api/governance/virtual-keys/${vk.id}`, adminCookie)
    await authDelete(request, `/api/enterprise/users/${dev.id}`, adminCookie)
    await authDelete(request, `/api/governance/teams/${team.id}`, adminCookie)
  })
})
