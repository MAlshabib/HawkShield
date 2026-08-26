"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"

/**
 * `/` is just an entry point that lands on the Home page.
 *
 * This is a client-side redirect on purpose: `redirect()` from `next/navigation`
 * is a server-side redirect and is not supported by `output: "export"`.
 */
export default function RootPage() {
  const router = useRouter()

  useEffect(() => {
    router.replace("/home")
  }, [router])

  return (
    <>
      <noscript>
        <meta httpEquiv="refresh" content="0; url=/home" />
      </noscript>
      <div className="flex min-h-screen items-center justify-center text-cyan-400">
        Loading HawkShield...
      </div>
    </>
  )
}
