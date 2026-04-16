"use client"

import FullPageLoader from "@/components/fullPageLoader";
import { NoPermissionView } from "@/components/noPermissionView";
import { getWorkspaceSectionLandingPath } from "@/lib/utils/workspaceLanding";
import { useRbacContext } from "@enterprise/lib";
import { useRouter } from "next/navigation"
import { useEffect } from "react"

export default function GovernancePage() {
  const router = useRouter()
  const { permissions, loaded, role } = useRbacContext()
  const targetRoute = getWorkspaceSectionLandingPath("governance", permissions, role)

  useEffect(() => {
    if (loaded && targetRoute) {
      router.replace(targetRoute)
    }
  }, [loaded, router, targetRoute])

  if (!loaded) {
    return <FullPageLoader />
  }

  if (!targetRoute) {
    return <NoPermissionView entity="governance" />
  }

  return <FullPageLoader />
}
