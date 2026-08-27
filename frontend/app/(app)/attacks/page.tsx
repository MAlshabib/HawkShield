"use client"

/**
 * `/attacks` was V1's name for the detection ledger. The page now lives at
 * `/threats`, which is what the navigation, the dictionary namespace and the
 * product's own vocabulary all call it.
 *
 * This stub stays because the old path is in bookmarks and in the V1 report
 * footer. A static export has no server to send a 301, so the redirect is a
 * client one — and a plain link is rendered underneath it so the route is not a
 * dead end for a reader who arrives with JavaScript disabled.
 */
import * as React from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"

import { useT } from "@/lib/i18n"

export default function AttacksRedirect() {
  const router = useRouter()
  const t = useT()

  React.useEffect(() => {
    router.replace("/threats")
  }, [router])

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-2 px-4 py-6 lg:px-8">
      <p className="hs-label">{t("state.loading")}</p>
      <Link href="/threats" className="text-hs-azure text-sm underline underline-offset-4">
        {t("threats.title")}
      </Link>
    </div>
  )
}
