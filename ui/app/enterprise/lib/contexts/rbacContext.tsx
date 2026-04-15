"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";

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
	APIKeys = "APIKeys",
	Invitations = "Invitations",
	Dashboard = "Dashboard",
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
	const [loaded, setLoaded] = useState(false);

	const fetchPermissions = useCallback(async () => {
		setIsLoading(true);
		try {
			const res = await fetch("/api/enterprise/permissions", { credentials: "include" });
			if (res.ok) {
				const data = await res.json();
				if (data && typeof data === "object") {
					const perms = data.permissions || data;
					setPermissions(perms);
					setLoaded(true);
					if (!data.role && Object.keys(perms).length === 0) {
						const pathname = window.location.pathname;
						if (pathname !== "/login" && !pathname.startsWith("/login")) {
							window.location.href = "/login";
						}
					}
				}
			}
		} catch {
			// If fetching fails, leave permissions empty
		} finally {
			setIsLoading(false);
		}
	}, []);

	useEffect(() => { fetchPermissions(); }, [fetchPermissions]);

	const isAllowed = useCallback(
		(resource: RbacResource, operation: RbacOperation): boolean => {
			if (!loaded) return true;
			if (Object.keys(permissions).length === 0) return true;
			const resourcePerms = permissions[resource];
			if (!resourcePerms) return false;
			return resourcePerms[operation] === true;
		},
		[permissions, loaded],
	);

	return (
		<RbacContext.Provider value={{ isAllowed, permissions, isLoading, refetch: fetchPermissions }}>
			{children}
		</RbacContext.Provider>
	);
}

export function useRbac(resource: RbacResource, operation: RbacOperation): boolean {
	const context = useContext(RbacContext);
	if (!context) return true;
	return context.isAllowed(resource, operation);
}

export function useRbacContext() {
	const context = useContext(RbacContext);
	if (!context) {
		return { isAllowed: () => true as boolean, permissions: {} as Record<string, Record<string, boolean>>, isLoading: false, refetch: () => {} };
	}
	return context;
}
