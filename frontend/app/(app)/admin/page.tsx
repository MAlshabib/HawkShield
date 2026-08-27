"use client"

/**
 * The operator console at `/admin`.
 *
 * Deliberately unlinked — not in the navbar, not on the dashboard, not in the
 * footer. It is reachable only by typing the URL, because the simulate lever
 * writes real rows through the real model into the real database, and that is
 * not a control a visitor should stumble onto.
 *
 * The connection chip and banner used to live in `components/connection-status`
 * with hardcoded English and a cyan/amber palette from V1. They are inlined
 * here on `StatusPill` and the existing `conn.*` copy: one page uses them, and a
 * two-function file of bespoke chip markup was exactly the thing the primitives
 * exist to delete.
 *
 * The backend readout is a `DataCard` rather than a panel of rows. It is the
 * one genuinely printed-slip object on this page — a handful of facts about a
 * running process, read top to bottom — and it lets the page open with the
 * answer to "is this thing alive" instead of with a lever.
 */
import * as React from "react"
import Link from "next/link"
import { ArrowRight, RefreshCw } from "lucide-react"

import { AccentWord } from "@/components/hs/accent-word"
import { DataCard, DataCardNote, DataCardRow, DataCardRows } from "@/components/hs/data-card"
import { Panel, PanelGrid } from "@/components/hs/panel"
import { SectionHead } from "@/components/hs/section-head"
import { StatusPill } from "@/components/hs/status-pill"
import {
  ControlSpacer,
  ControlStrip,
  Moment,
  PageFrame,
  Phrase,
  Readout,
  ReadoutRow,
  Unreported,
} from "@/components/console/frame"
import { SimulatePanel } from "@/components/simulate-panel"
import { Button } from "@/components/ui/button"
import { useHealth, type ConnectionState } from "@/hooks/use-health"
import { useFormatters } from "@/lib/format"
import { apiTimeMs } from "@/lib/detections"
import { useLocale, useT, type TranslationKey } from "@/lib/i18n"

const STATE_KEY: Record<ConnectionState, TranslationKey> = {
  unknown: "conn.connecting",
  online: "conn.live",
  degraded: "conn.degraded",
  offline: "conn.offline",
}

const STATE_TONE = {
  unknown: "neutral",
  online: "info",
  degraded: "high",
  offline: "critical",
} as const

export default function AdminPage() {
  const t = useT()
  const f = useFormatters()
  const { isRTL } = useLocale()
  const { state, health, lastOkAt, refresh } = useHealth()
  const [runs, setRuns] = React.useState(0)

  const models = health?.models ?? null
  const present = models
    ? Object.entries(models)
        .filter(([, ok]) => ok)
        .map(([name]) => name)
    : []

  const lastPacketMs = apiTimeMs(health?.latest_packet_ts ?? null)
  const settled = state !== "online" && state !== "unknown"

  return (
    <PageFrame className="max-w-[980px]">
      <SectionHead
        as="h1"
        eyebrow={t("admin.title")}
        title={
          <>
            {t("admin.head.lead")}
            <AccentWord>{t("admin.head.accent")}</AccentWord>
          </>
        }
        body={t("admin.subtitle")}
      />

      <ControlStrip>
        <StatusPill tone={STATE_TONE[state]} dot>
          {t(STATE_KEY[state])}
        </StatusPill>
        <span className="hs-label hidden sm:inline">{t("admin.urlOnly")}</span>
        <ControlSpacer />
        <Button size="sm" variant="outline" onClick={refresh}>
          <RefreshCw aria-hidden="true" />
          {t("common.refresh")}
        </Button>
      </ControlStrip>

      {/* The calm banner: it explains why the figures stopped moving, and never
          blanks the page or invents a value to fill the gap. The tinted edge is
          the same colour-mix the status pill uses, so the two agree. */}
      {settled && (
        <Panel
          label={t("admin.connection")}
          className={
            state === "degraded"
              ? "border-[color-mix(in_oklch,var(--sev-high)_38%,transparent)]"
              : "border-[color-mix(in_oklch,var(--sev-critical)_38%,transparent)]"
          }
        >
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="text-ink-1 min-w-0 flex-1 text-sm">
              {state === "degraded"
                ? t("conn.bannerDegraded")
                : t("conn.bannerOffline", {
                    ago: lastOkAt ? f.relative(lastOkAt) : t("conn.noDataYet"),
                  })}
            </span>
            <span className="text-ink-2 text-xs">{t("admin.simulate.stillWorks")}</span>
          </div>
        </Panel>
      )}

      {/* ---- what is running ---------------------------------------------- */}
      <PanelGrid className="lg:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
        <DataCard
          label={health?.status ?? t("admin.unreachable")}
          title={t("admin.backend")}
          status={
            <StatusPill tone={STATE_TONE[state]} dot>
              {t(STATE_KEY[state])}
            </StatusPill>
          }
          className="h-fit"
        >
          <DataCardRows>
            <DataCardRow
              label={t("admin.database")}
              value={
                health?.database === true ? (
                  <Phrase>{t("admin.reachable")}</Phrase>
                ) : health?.database === false ? (
                  <Phrase>{t("admin.notAnswering")}</Phrase>
                ) : (
                  "—"
                )
              }
              tone={health?.database === false ? "critical" : "default"}
            />
            <DataCardRow
              label={t("admin.storedPackets")}
              value={typeof health?.packets === "number" ? f.number(health.packets) : "—"}
            />
            <DataCardRow
              label={t("admin.latestPacket")}
              value={
                lastPacketMs === null ? (
                  "—"
                ) : (
                  <Moment value={lastPacketMs} format="relative" className="text-sm" />
                )
              }
            />
            <DataCardRow label={t("admin.apiVersion")} value={health?.version ?? "—"} />
          </DataCardRows>
          <DataCardNote>{t("time.timezone")}</DataCardNote>
        </DataCard>

        {/* The version is the panel's subject, so it sits in the header rather
            than as a first row repeating the panel's own label back at it. */}
        <Panel
          label={t("admin.modelInService")}
          title={
            health?.model_version && health.model_version !== "none" ? (
              <span className="hs-ltr font-mono">{health.model_version}</span>
            ) : (
              <Unreported />
            )
          }
        >
          <Readout>
            <ReadoutRow label={t("admin.specVersion")}>
              {health?.spec_version ? (
                <span className="hs-num">{health.spec_version}</span>
              ) : (
                <Unreported />
              )}
            </ReadoutRow>
            <ReadoutRow label={t("admin.modelArtefacts")}>
              {models === null ? (
                <Unreported />
              ) : present.length === 0 ? (
                <span className="text-sev-high text-sm">{t("admin.nonePresent")}</span>
              ) : (
                // Artefact names are identifiers; the row of them mirrors with
                // the page, each name stays LTR inside it.
                <span className="flex flex-wrap justify-end gap-1">
                  {present.map((name) => (
                    <StatusPill key={name} tone="neutral" className="hs-ltr">
                      {name}
                    </StatusPill>
                  ))}
                </span>
              )}
            </ReadoutRow>
          </Readout>

          {runs > 0 && (
            <p className="text-ink-2 mt-4 text-xs">
              {t("admin.runsThisSession", { n: f.number(runs) })}
            </p>
          )}
        </Panel>
      </PanelGrid>

      {/* ---- the lever ----------------------------------------------------- */}
      <SimulatePanel
        onSimulated={() => {
          setRuns((n) => n + 1)
          refresh()
        }}
      />

      <div className="border-rule flex flex-wrap items-center justify-between gap-3 border-t pt-4">
        <p className="text-ink-2 text-xs sm:hidden">{t("admin.urlOnly")}</p>
        <Link
          href="/dashboard"
          className="text-accent-cta hover:text-ink-0 ms-auto inline-flex items-center gap-1.5 text-sm transition-colors"
        >
          {t("admin.openDashboard")}
          {/* The arrow points along the reading direction, so it flips. */}
          <ArrowRight className={isRTL ? "size-3.5 rotate-180" : "size-3.5"} aria-hidden="true" />
        </Link>
      </div>
    </PageFrame>
  )
}
