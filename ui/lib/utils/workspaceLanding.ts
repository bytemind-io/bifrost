import { RbacOperation, RbacResource } from "@enterprise/lib";

type PermissionMap = Record<string, Record<string, boolean>>;

interface PermissionRequirement {
	resource: RbacResource;
	operation: RbacOperation;
}

interface LandingRule {
	url: string;
	requirements: PermissionRequirement[];
	entity?: string;
	match?: "exact" | "prefix";
}

type WorkspaceSection = "config" | "governance" | "guardrails";

const view = (resource: RbacResource): PermissionRequirement => ({
	resource,
	operation: RbacOperation.View,
});

const GOVERNANCE_REQUIREMENTS: PermissionRequirement[] = [
	view(RbacResource.Governance),
	view(RbacResource.VirtualKeys),
	view(RbacResource.Users),
	view(RbacResource.Teams),
	view(RbacResource.Customers),
	view(RbacResource.UserProvisioning),
	view(RbacResource.RBAC),
	view(RbacResource.AuditLogs),
];

const GUARDRAILS_REQUIREMENTS: PermissionRequirement[] = [
	view(RbacResource.GuardrailsConfig),
	view(RbacResource.GuardrailsProviders),
];

const SECTION_LANDING_CANDIDATES: Record<WorkspaceSection, string[]> = {
	config: ["/workspace/config/client-settings", "/workspace/config/api-keys"],
	governance: [
		"/workspace/governance/virtual-keys",
		"/workspace/governance/users",
		"/workspace/governance/teams",
		"/workspace/governance/customers",
		"/workspace/scim",
		"/workspace/governance/rbac",
		"/workspace/audit-logs",
	],
	guardrails: ["/workspace/guardrails/configuration", "/workspace/guardrails/providers"],
};

const LANDING_RULES: LandingRule[] = [
	{ url: "/workspace/dashboard", requirements: [view(RbacResource.Dashboard)], entity: "dashboard" },
	{ url: "/workspace/logs", requirements: [view(RbacResource.Logs)], entity: "logs" },
	{ url: "/workspace/model-catalog", requirements: [view(RbacResource.ModelProvider)], entity: "model catalog" },
	{ url: "/workspace/providers", requirements: [view(RbacResource.ModelProvider)], entity: "model providers" },
	{ url: "/workspace/mcp-registry", requirements: [view(RbacResource.MCPGateway)], entity: "MCP catalog" },
	{ url: "/workspace/plugins", requirements: [view(RbacResource.Plugins)], entity: "plugins" },
	{ url: "/workspace/governance/virtual-keys", requirements: [view(RbacResource.VirtualKeys)], entity: "virtual keys" },
	{ url: "/workspace/governance/users", requirements: [view(RbacResource.Users)], entity: "users" },
	{ url: "/workspace/governance/teams", requirements: [view(RbacResource.Teams)], entity: "teams" },
	{ url: "/workspace/governance/customers", requirements: [view(RbacResource.Customers)], entity: "customers" },
	{ url: "/workspace/scim", requirements: [view(RbacResource.UserProvisioning)], entity: "user provisioning" },
	{ url: "/workspace/governance/rbac", requirements: [view(RbacResource.RBAC)], entity: "roles and permissions" },
	{ url: "/workspace/audit-logs", requirements: [view(RbacResource.AuditLogs)], entity: "audit logs" },
	{ url: "/workspace/guardrails/configuration", requirements: [view(RbacResource.GuardrailsConfig)], entity: "guardrails rules" },
	{ url: "/workspace/guardrails/providers", requirements: [view(RbacResource.GuardrailsProviders)], entity: "guardrails providers" },
	{ url: "/workspace/pii-redactor", requirements: [view(RbacResource.PIIRedactor)], entity: "PII redactor" },
	{ url: "/workspace/cluster", requirements: [view(RbacResource.Cluster)], entity: "cluster configuration" },
	{ url: "/workspace/adaptive-routing", requirements: [view(RbacResource.AdaptiveRouter)], entity: "adaptive routing" },
	{ url: "/workspace/routing-rules", requirements: [view(RbacResource.RoutingRules)], entity: "routing rules" },
	{ url: "/workspace/prompt-repo/prompts", requirements: [view(RbacResource.PromptRepository)], entity: "prompts" },
	{ url: "/workspace/prompt-repo/deployments", requirements: [view(RbacResource.PromptDeploymentStrategy)], entity: "prompt deployments" },
	{ url: "/workspace/config/api-keys", requirements: [view(RbacResource.APIKeys)], entity: "API keys" },
	{ url: "/workspace/config", requirements: [view(RbacResource.Settings)], entity: "configuration" },
];

const ROUTE_RULES: LandingRule[] = [
	{ url: "/workspace/docs", requirements: [], entity: "documentation", match: "prefix" },
	{ url: "/workspace/dashboard", requirements: [view(RbacResource.Dashboard)], entity: "dashboard" },
	{ url: "/workspace/observability", requirements: [view(RbacResource.Observability)], entity: "observability" },
	{ url: "/workspace/alert-channels", requirements: [view(RbacResource.Observability)], entity: "alert channels", match: "prefix" },
	{ url: "/workspace/logs/dashboard", requirements: [view(RbacResource.Dashboard)], entity: "dashboard" },
	{ url: "/workspace/logs/connectors", requirements: [view(RbacResource.Observability)], entity: "observability connectors" },
	{ url: "/workspace/logs/mcp-logs", requirements: [view(RbacResource.Logs)], entity: "MCP logs" },
	{ url: "/workspace/mcp-logs", requirements: [view(RbacResource.Logs)], entity: "MCP logs" },
	{ url: "/workspace/logs", requirements: [view(RbacResource.Logs)], entity: "logs", match: "prefix" },
	{ url: "/workspace/model-catalog", requirements: [view(RbacResource.ModelProvider)], entity: "model catalog", match: "prefix" },
	{ url: "/workspace/providers/routing-rules", requirements: [view(RbacResource.RoutingRules)], entity: "routing rules" },
	{ url: "/workspace/providers/model-limits", requirements: [view(RbacResource.Governance)], entity: "budgets and limits" },
	{ url: "/workspace/providers", requirements: [view(RbacResource.ModelProvider)], entity: "model providers", match: "prefix" },
	{ url: "/workspace/model-limits", requirements: [view(RbacResource.Governance)], entity: "budgets and limits", match: "prefix" },
	{ url: "/workspace/routing-rules", requirements: [view(RbacResource.RoutingRules)], entity: "routing rules", match: "prefix" },
	{ url: "/workspace/mcp-registry", requirements: [view(RbacResource.MCPGateway)], entity: "MCP catalog", match: "prefix" },
	{ url: "/workspace/mcp-tool-groups", requirements: [view(RbacResource.MCPGateway)], entity: "MCP tool groups", match: "prefix" },
	{ url: "/workspace/mcp-auth-config", requirements: [view(RbacResource.MCPGateway)], entity: "MCP auth config", match: "prefix" },
	{ url: "/workspace/mcp-settings", requirements: [view(RbacResource.MCPGateway)], entity: "MCP settings", match: "prefix" },
	{ url: "/workspace/plugins", requirements: [view(RbacResource.Plugins)], entity: "plugins", match: "prefix" },
	{ url: "/workspace/governance/virtual-keys", requirements: [view(RbacResource.VirtualKeys)], entity: "virtual keys", match: "prefix" },
	{ url: "/workspace/virtual-keys", requirements: [view(RbacResource.VirtualKeys)], entity: "virtual keys", match: "prefix" },
	{ url: "/workspace/governance/users", requirements: [view(RbacResource.Users)], entity: "users", match: "prefix" },
	{ url: "/workspace/governance/teams", requirements: [view(RbacResource.Teams)], entity: "teams", match: "prefix" },
	{ url: "/workspace/governance/customers", requirements: [view(RbacResource.Customers)], entity: "customers", match: "prefix" },
	{ url: "/workspace/scim", requirements: [view(RbacResource.UserProvisioning)], entity: "user provisioning", match: "prefix" },
	{ url: "/workspace/governance/rbac", requirements: [view(RbacResource.RBAC)], entity: "roles and permissions", match: "prefix" },
	{ url: "/workspace/rbac", requirements: [view(RbacResource.RBAC)], entity: "roles and permissions", match: "prefix" },
	{ url: "/workspace/audit-logs", requirements: [view(RbacResource.AuditLogs)], entity: "audit logs", match: "prefix" },
	{ url: "/workspace/governance", requirements: GOVERNANCE_REQUIREMENTS, entity: "governance", match: "prefix" },
	{ url: "/workspace/guardrails/configuration", requirements: [view(RbacResource.GuardrailsConfig)], entity: "guardrails rules", match: "prefix" },
	{ url: "/workspace/guardrails/providers", requirements: [view(RbacResource.GuardrailsProviders)], entity: "guardrails providers", match: "prefix" },
	{ url: "/workspace/guardrails", requirements: GUARDRAILS_REQUIREMENTS, entity: "guardrails", match: "prefix" },
	{ url: "/workspace/cluster", requirements: [view(RbacResource.Cluster)], entity: "cluster configuration", match: "prefix" },
	{ url: "/workspace/adaptive-routing", requirements: [view(RbacResource.AdaptiveRouter)], entity: "adaptive routing", match: "prefix" },
	{ url: "/workspace/prompt-repo/prompts", requirements: [view(RbacResource.PromptRepository)], entity: "prompts", match: "prefix" },
	{ url: "/workspace/prompt-repo/deployments", requirements: [view(RbacResource.PromptDeploymentStrategy)], entity: "prompt deployments", match: "prefix" },
	{ url: "/workspace/pii-redactor", requirements: [view(RbacResource.PIIRedactor)], entity: "PII redactor", match: "prefix" },
	{ url: "/workspace/config/api-keys", requirements: [view(RbacResource.APIKeys)], entity: "API keys", match: "prefix" },
	{ url: "/workspace/config", requirements: [view(RbacResource.Settings)], entity: "configuration", match: "prefix" },
	{ url: "/workspace/custom-pricing", requirements: [view(RbacResource.Settings)], entity: "pricing configuration", match: "prefix" },
];

const hasPermission = (permissions: PermissionMap, resource: RbacResource, operation: RbacOperation) => {
	return permissions[resource]?.[operation] === true;
};

const matchesPath = (pathname: string, rule: LandingRule) => {
	if (rule.match === "prefix") {
		return pathname === rule.url || pathname.startsWith(`${rule.url}/`);
	}
	return pathname === rule.url;
};

export function canAccessWorkspaceRoute(pathname: string, permissions: PermissionMap, role?: string): boolean {
	if (role && role.toLowerCase() === "admin") {
		return true;
	}

	const rule = ROUTE_RULES.find((candidate) => matchesPath(pathname, candidate));
	if (!rule) {
		return false;
	}
	if (rule.requirements.length === 0) {
		return true;
	}

	return rule.requirements.some((requirement) =>
		hasPermission(permissions, requirement.resource, requirement.operation),
	);
}

export function getWorkspaceRoutePermission(pathname: string): { entity: string } | undefined {
	const rule = ROUTE_RULES.find((candidate) => matchesPath(pathname, candidate));
	if (!rule?.entity) {
		return undefined;
	}

	return { entity: rule.entity };
}

export function canAccessWorkspaceLanding(permissions: PermissionMap, role: string | undefined, url: string): boolean {
	if (role && role.toLowerCase() === "admin") {
		return true;
	}

	const rule = LANDING_RULES.find((candidate) => candidate.url === url);
	if (!rule) {
		return false;
	}
	if (rule.requirements.length === 0) {
		return true;
	}

	return rule.requirements.some((requirement) => hasPermission(permissions, requirement.resource, requirement.operation));
}

export function getWorkspaceLandingPath(permissions: PermissionMap, role?: string): string {
	if (role && role.toLowerCase() === "admin") {
		return "/workspace/dashboard";
	}

	for (const rule of LANDING_RULES) {
		if (rule.requirements.some((requirement) => hasPermission(permissions, requirement.resource, requirement.operation))) {
			return rule.url;
		}
	}

	return "/workspace/dashboard";
}

export function getWorkspaceSectionLandingPath(
	section: WorkspaceSection,
	permissions: PermissionMap,
	role?: string,
): string | undefined {
	for (const url of SECTION_LANDING_CANDIDATES[section]) {
		if (canAccessWorkspaceLanding(permissions, role, url)) {
			return url;
		}
	}

	return undefined;
}
