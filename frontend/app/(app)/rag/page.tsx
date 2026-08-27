"use client"

/**
 * `/rag` is gone; Saqr replaced it. This is the forwarding stub.
 *
 * A client-side redirect rather than a `redirects` entry in `next.config.ts`:
 * the build is `output: "export"` and is served by FastAPI's `StaticFiles`, so
 * there is no Next server left to honour a config redirect at runtime. The
 * anchor is not decoration — it is what a reader with JavaScript disabled, or
 * an indexer, actually follows.
 */
import * as React from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"

import { useT } from "@/lib/i18n"

export default function RagRedirectPage() {
  const router = useRouter()
  const t = useT()

  React.useEffect(() => {
    // `replace`, not `push`: Back should return to wherever the stale link was
    // followed from, not bounce through this page again.
    router.replace("/saqr")
  }, [router])

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-2 px-4 py-6 lg:px-8">
      <p className="text-ink-dim text-sm">{t("saqr.moved")}</p>
      <Link href="/saqr" className="text-hs-azure text-sm underline underline-offset-4">
        {t("saqr.title")}
      </Link>
    </div>
  )
}
