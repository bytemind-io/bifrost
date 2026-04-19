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
	AccessProfiles = "AccessProfiles",
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
	loaded: boolean;
	role?: string;
	refetch: () => void;
}

const RbacContext = createContext<RbacContextType | null>(null);

export function RbacProvider({ children }: { children: React.ReactNode }) {
	const [permissions, setPermissions] = useState<Record<string, Record<string, boolean>>>({});
	const [isLoading, setIsLoading] = useState(true);
	const [loaded, setLoaded] = useState(false);
	const [role, setRole] = useState<string | undefined>(undefined);

	const fetchPermissions = useCallback(async () => {
		setIsLoading(true);
		try {
			const res = await fetch("/api/enterprise/permissions", { credentials: "include" });
			if (res.ok) {
				const data = await res.json();
				if (data && typeof data === "object") {
					const perms = data.permissions || data;
					setPermissions(perms);
					setRole(typeof data.role === "string" ? data.role : undefined);
					setLoaded(true);
				}
			} else if (res.status === 401 || res.status === 403) {
				setPermissions({});
				setRole(undefined);
				setLoaded(true);
			}
		} catch {
			// If fetching fails, leave permissions empty
			setLoaded(true);
		} finally {
			setIsLoading(false);
		}
	}, []);

	useEffect(() => { fetchPermissions(); }, [fetchPermissions]);

	useEffect(() => {
		const handleFocus = () => {
			void fetchPermissions();
		};
		const handleVisibilityChange = () => {
			if (document.visibilityState === "visible") {
				void fetchPermissions();
			}
		};

		window.addEventListener("focus", handleFocus);
		document.addEventListener("visibilitychange", handleVisibilityChange);

		return () => {
			window.removeEventListener("focus", handleFocus);
			document.removeEventListener("visibilitychange", handleVisibilityChange);
		};
	}, [fetchPermissions]);

	const isAllowed = useCallback(
		(resource: RbacResource, operation: RbacOperation): boolean => {
			if (!loaded) return false;
			if (Object.keys(permissions).length === 0) return false;
			const resourcePerms = permissions[resource];
			if (!resourcePerms) return false;
			return resourcePerms[operation] === true;
		},
		[permissions, loaded],
	);

	return (
		<RbacContext.Provider value={{ isAllowed, permissions, isLoading, loaded, role, refetch: fetchPermissions }}>
			{children}
		</RbacContext.Provider>
	);
}

export function useRbac(resource: RbacResource, operation: RbacOperation): boolean {
	const context = useContext(RbacContext);
	if (!context) return false;
	return context.isAllowed(resource, operation);
}

export function useRbacContext() {
	const context = useContext(RbacContext);
	if (!context) {
		return {
			isAllowed: () => false as boolean,
			permissions: {} as Record<string, Record<string, boolean>>,
			isLoading: false,
			loaded: false,
			role: undefined,
			refetch: () => {},
		};
	}
	return context;
}
