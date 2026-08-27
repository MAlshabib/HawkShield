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
 */
import * as React from "react"
import Link from "next/link"
import { ArrowRight, RefreshCw } from "lucide-react"

import { Module, ModuleGrid } from "@/components/hs/module"
import { StatusPill } from "@/components/hs/status-pill"
import { SimulatePanel } from "@/components/simulate-panel"
import { Button } from "@/components/ui/button"
import { useHealth, type ConnectionState } from "@/hooks/use-health"
import { Timestamp, useFormatters } from "@/lib/format"
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

/** "Not reported" rather than a dash that reads as a zero. */
function Unreported() {
  const t = useT()
  return <span className="text-ink-faint text-xs">{t("landing.notReported")}</span>
}

function Field({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="border-hairline flex items-baseline justify-between gap-4 border-b py-1.5 last:border-0">
      <span className="hs-label shrink-0">{label}</span>
      <span className="text-ink min-w-0 text-end text-sm">{children}</span>
    </div>
  )
}

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
    <div className="mx-auto flex max-w-4xl flex-col gap-3 px-4 py-6 sm:gap-4 lg:px-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="text-ink font-display text-2xl leading-none font-medium sm:text-3xl">
            {t("admin.title")}
          </h1>
          <p className="text-ink-dim max-w-prose text-sm">{t("admin.subtitle")}</p>
        </div>

        <div className="flex items-center gap-2">
          <StatusPill tone={STATE_TONE[state]} dot>
            {t(STATE_KEY[state])}
          </StatusPill>
          <Button size="sm" variant="secondary" onClick={refresh}>
            <RefreshCw aria-hidden="true" />
            {t("common.refresh")}
          </Button>
        </div>
      </header>

      {/* The calm banner: it explains why the figures stopped moving, and never
          blanks the page or invents a value to fill the gap. */}
      {settled && (
        <div className="border-hairline bg-surface flex flex-wrap items-center gap-2 rounded-md border px-3 py-2">
          <StatusPill tone={STATE_TONE[state]} dot>
            {t(STATE_KEY[state])}
          </StatusPill>
          <span className="text-ink-dim min-w-0 flex-1 text-sm">
            {state === "degraded"
              ? t("conn.bannerDegraded")
              : t("conn.bannerOffline", {
                  ago: lastOkAt ? f.relative(lastOkAt) : t("conn.noDataYet"),
                })}{" "}
            <span className="text-ink-faint">{t("admin.simulate.stillWorks")}</span>
          </span>
        </div>
      )}

      <SimulatePanel onSimulated={() => { setRuns((n) => n + 1); refresh() }} />

      <ModuleGrid className="lg:grid-cols-2">
        <Module label={t("admin.backend")}>
          <div className="flex flex-col">
            <Field label={t("admin.status")}>
              {health?.status ? (
                <span className="hs-ltr font-mono">{health.status}</span>
              ) : state === "offline" ? (
                <span className="text-sev-critical text-sm">{t("admin.unreachable")}</span>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("admin.database")}>
              {health?.database === true ? (
                <StatusPill tone="info">{t("admin.reachable")}</StatusPill>
              ) : health?.database === false ? (
                <StatusPill tone="high">{t("admin.notAnswering")}</StatusPill>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("admin.storedPackets")}>
              {typeof health?.packets === "number" ? (
                <span className="hs-num">{f.number(health.packets)}</span>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("admin.latestPacket")}>
              {lastPacketMs === null ? <Unreported /> : <Timestamp value={lastPacketMs} />}
            </Field>
            <Field label={t("admin.apiVersion")}>
              {health?.version ? <span className="hs-num">{health.version}</span> : <Unreported />}
            </Field>
          </div>
        </Module>

        <Module label={t("admin.modelInService")}>
          <div className="flex flex-col">
            <Field label={t("admin.modelInService")}>
              {health?.model_version && health.model_version !== "none" ? (
                <span className="hs-ltr font-mono">{health.model_version}</span>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("admin.specVersion")}>
              {health?.spec_version ? (
                <span className="hs-num">{health.spec_version}</span>
              ) : (
                <Unreported />
              )}
            </Field>
            <Field label={t("admin.modelArtefacts")}>
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
            </Field>
          </div>

          {runs > 0 && (
            <p className="text-ink-faint mt-3 text-xs">
              {t("admin.runsThisSession", { n: f.number(runs) })}
            </p>
          )}
        </Module>
      </ModuleGrid>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-ink-faint text-xs">{t("admin.urlOnly")}</p>
        <Link
          href="/dashboard"
          className="text-hs-azure hover:text-ink inline-flex items-center gap-1.5 text-sm transition-colors"
        >
          {t("admin.openDashboard")}
          {/* The arrow points along the reading direction, so it flips. */}
          <ArrowRight className={isRTL ? "size-3.5 rotate-180" : "size-3.5"} aria-hidden="true" />
        </Link>
      </div>
    </div>
  )
}
