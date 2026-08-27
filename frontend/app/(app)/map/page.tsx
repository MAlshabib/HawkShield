"use client"

/**
 * The map, promoted off the dashboard onto a route of its own.
 *
 * It was a widget wedged under eight other instruments, where a 480px map got
 * about a third of the attention it needs and none of the controls it wanted.
 * Trilateration is a question an operator asks deliberately — "where is this
 * source" — so it gets a page, a source picker and a window selector.
 *
 * The page frame is all this file owns. Fetching, the HTTP-200 rejection shape
 * and the empty-configuration case all live in `MapTrilateration`.
 */
import * as React from "react"

import { StatusPill } from "@/components/hs/status-pill"
import MapTrilateration from "@/components/MapTrilateration"
import { useHealth, type ConnectionState } from "@/hooks/use-health"
import { useT, type TranslationKey } from "@/lib/i18n"

const STATE_KEY: Record<ConnectionState, TranslationKey> = {
  unknown: "dashboard.sensor.unknown",
  online: "dashboard.sensor.online",
  degraded: "dashboard.sensor.degraded",
  offline: "dashboard.sensor.offline",
}

const STATE_TONE = {
  unknown: "neutral",
  online: "info",
  degraded: "high",
  offline: "critical",
} as const

export default function MapPage() {
  const t = useT()
  const { state } = useHealth()

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-3 px-4 py-6 sm:gap-4 lg:px-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-ink font-display text-2xl leading-none font-medium sm:text-3xl">
            {t("map.title")}
          </h1>
          <p className="text-ink-dim max-w-prose text-sm">{t("map.subtitle")}</p>
        </div>

        <StatusPill tone={STATE_TONE[state]} dot>
          {t(STATE_KEY[state])}
        </StatusPill>
      </header>

      <MapTrilateration />

      <p className="text-ink-faint max-w-prose text-xs">{t("map.spatial")}</p>
    </div>
  )
}
