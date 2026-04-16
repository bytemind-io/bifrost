"use client";

import FullPageLoader from "@/components/fullPageLoader";
import { NoPermissionView } from "@/components/noPermissionView";
import { getWorkspaceSectionLandingPath } from "@/lib/utils/workspaceLanding";
import { useRbacContext } from "@enterprise/lib";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function ConfigPage() {
	const router = useRouter();
	const { permissions, loaded, role } = useRbacContext();
	const targetRoute = getWorkspaceSectionLandingPath("config", permissions, role);

	useEffect(() => {
		if (loaded && targetRoute) {
			router.replace(targetRoute);
		}
	}, [loaded, router, targetRoute]);

	if (!loaded) {
		return <FullPageLoader />;
	}

	if (!targetRoute) {
		return <NoPermissionView entity="configuration" />;
	}

	return <FullPageLoader />;
}
