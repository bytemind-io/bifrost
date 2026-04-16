"use client";

import FullPageLoader from "@/components/fullPageLoader";
import { NoPermissionView } from "@/components/noPermissionView";
import { getWorkspaceSectionLandingPath } from "@/lib/utils/workspaceLanding";
import GuardrailsConfigurationView from "@enterprise/components/guardrails/guardrailsConfigurationView";
import { useRbacContext } from "@enterprise/lib";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function GuardrailsPage() {
	const router = useRouter();
	const { permissions, loaded, role } = useRbacContext();
	const targetRoute = getWorkspaceSectionLandingPath("guardrails", permissions, role);
	const shouldShowConfiguration = targetRoute === "/workspace/guardrails/configuration";

	useEffect(() => {
		if (loaded && targetRoute && targetRoute !== "/workspace/guardrails/configuration") {
			router.replace(targetRoute);
		}
	}, [loaded, router, targetRoute]);

	if (!loaded) {
		return <FullPageLoader />;
	}

	if (!targetRoute || !shouldShowConfiguration) {
		if (!targetRoute) {
			return <NoPermissionView entity="guardrails" />;
		}
		return <FullPageLoader />;
	}

	return (
		<div className="mx-auto w-full max-w-7xl">
			<GuardrailsConfigurationView />
		</div>
	);
}
