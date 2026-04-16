"use client";

import FullPageLoader from "@/components/fullPageLoader";
import { getWorkspaceLandingPath } from "@/lib/utils/workspaceLanding";
import { useRbacContext } from "@enterprise/lib";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

export default function WorkspacePage() {
	const router = useRouter();
	const { permissions, loaded, role } = useRbacContext();

	useEffect(() => {
		if (!loaded) {
			return;
		}
		router.replace(getWorkspaceLandingPath(permissions, role));
	}, [loaded, permissions, role, router]);

	return <FullPageLoader />;
}
