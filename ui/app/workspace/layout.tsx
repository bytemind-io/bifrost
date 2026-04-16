"use client";

import FullPageLoader from "@/components/fullPageLoader";
import { NoPermissionView } from "@/components/noPermissionView";
import { canAccessWorkspaceRoute, getWorkspaceRoutePermission } from "@/lib/utils/workspaceLanding";
import { useRbacContext } from "@enterprise/lib";
import { ClientLayout } from "../clientLayout";
import { usePathname } from "next/navigation";

function WorkspaceContentGuard({ children }: { children: React.ReactNode }) {
	const pathname = usePathname();
	const { permissions, loaded, role } = useRbacContext();

	if (!loaded) {
		return <FullPageLoader />;
	}

	const access = canAccessWorkspaceRoute(pathname, permissions, role);
	const routePermission = getWorkspaceRoutePermission(pathname);

	if (access === false && routePermission) {
		return <NoPermissionView entity={routePermission.entity} />;
	}

	return <>{children}</>;
}

export default function WorkspaceLayout({ children }: { children: React.ReactNode }) {
	return (
		<ClientLayout>
			<WorkspaceContentGuard>{children}</WorkspaceContentGuard>
		</ClientLayout>
	);
}
