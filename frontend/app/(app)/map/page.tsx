"use client"

/**
 * The map, on a route of its own.
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

import { AccentWord } from "@/components/hs/accent-word"
import { SectionHead } from "@/components/hs/section-head"
import { StatusPill } from "@/components/hs/status-pill"
import { ControlSpacer, ControlStrip, PageFrame } from "@/components/console/frame"
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
    <PageFrame>
      <SectionHead
        as="h1"
        eyebrow={t("map.title")}
        title={
          <>
            {t("map.head.lead")}
            <AccentWord>{t("map.head.accent")}</AccentWord>
          </>
        }
        body={t("map.subtitle")}
      />

      <ControlStrip>
        <StatusPill tone={STATE_TONE[state]} dot>
          {t(STATE_KEY[state])}
        </StatusPill>
        <ControlSpacer />
        {/* The map is drawn LTR in both languages; this is the one place the
            page says so out loud rather than leaving it to be noticed. Set as
            prose, not as an eyebrow — `hs-label` is uppercase mono and this is
            a sentence. */}
        <span className="text-ink-2 hidden max-w-[56ch] text-end text-xs lg:inline">
          {t("map.spatial")}
        </span>
      </ControlStrip>

      <MapTrilateration />

      <p className="text-ink-2 max-w-[72ch] text-xs lg:hidden">{t("map.spatial")}</p>
    </PageFrame>
  )
}
