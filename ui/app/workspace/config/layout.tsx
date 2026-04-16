"use client"

import FullPageLoader from "@/components/fullPageLoader"
import { useGetCoreConfigQuery } from "@/lib/store"

export default function ConfigLayout({ children }: { children: React.ReactNode }) {
  const { isLoading } = useGetCoreConfigQuery({ fromDB: true })

  if (isLoading) {
    return <FullPageLoader />
  }

  return <div>{children}</div>
}
