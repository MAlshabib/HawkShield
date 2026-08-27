"use client"

/**
 * The application shell: bar on top, page below.
 *
 * A client component because the skip link's label goes through `useT()` like
 * every other string — locale lives on the client in a static export, so any
 * layout that renders copy has to be a client component too.
 */
import type React from "react"

import { Navbar } from "@/components/navbar"
import { useT } from "@/lib/i18n"

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const t = useT()

  return (
    <div className="min-h-screen">
      {/* Off-screen until focused. `start-4` rather than `left-4` so it appears
          on the correct edge in Arabic. */}
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:start-4 focus:z-[60] focus:rounded-md focus:border focus:border-[color:var(--hairline)] focus:bg-[color:var(--surface)] focus:px-3 focus:py-2 focus:text-sm focus:text-[color:var(--ink)]"
      >
        {t("nav.skipToContent")}
      </a>

      <Navbar />

      <main id="main">{children}</main>
    </div>
  )
}
