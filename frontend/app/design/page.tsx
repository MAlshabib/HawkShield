"use client"

import * as React from "react"
import { Download, Filter, RefreshCw } from "lucide-react"

import { Logo, Wordmark } from "@/components/brand/logo"
import { useLocale } from "@/components/providers/locale-provider"
import { useTheme } from "@/components/providers/theme-provider"
import { DataTable, type DataTableColumn, type DataTableSort } from "@/components/hs/data-table"
import { Hairline } from "@/components/hs/hairline"
import { Metric } from "@/components/hs/metric"
import { Module, ModuleGrid } from "@/components/hs/module"
import { Radar } from "@/components/hs/radar"
import { Sparkline } from "@/components/hs/sparkline"
import { StatusPill } from "@/components/hs/status-pill"
import { TerminalLine } from "@/components/hs/terminal-line"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet"
import {
  Toast,
  ToastDescription,
  ToastProvider,
  ToastTitle,
  ToastViewport,
} from "@/components/ui/toast"
import { attackColors, attackLabels, attackTypes, severityOf } from "@/lib/colors"
import { cn } from "@/lib/utils"

/**
 * Falcon Ops style sheet — the design system rendered as one page.
 *
 * Dev-only surface. Copy is hardcoded English on purpose: this is a reference
 * for the team, not a shipped screen, and it is the one place in the repo where
 * literal strings in a component are correct.
 *
 * NOTE ON ROUTING: the App Router treats a leading underscore as a *private*
 * folder and excludes it from the route tree, so this file compiles and
 * type-checks but does not serve at `/design`. Rename the segment to `design`
 * (or reach it as `/%5Fdesign`) when it needs to be opened in a browser.
 *
 * The theme and direction switches are local `useState` on a wrapper element,
 * not a provider — this page must stay reviewable while the real theme and i18n
 * providers are still being built. That works because the whole theme lives in
 * custom properties: putting `.dark` on any element re-themes its subtree.
 * The one gap is Radix portals (Dialog, Sheet, Select, Popover), which mount on
 * `document.body` and therefore follow the `<html>` class rather than the
 * wrapper. Their triggers are live below; judge their palette in the app.
 */

/* -------------------------------------------------------------------------- */
/* Local scaffolding                                                          */
/* -------------------------------------------------------------------------- */

function Section({
  label,
  title,
  children,
}: {
  label: string
  title: string
  children: React.ReactNode
}) {
  return (
    <section className="flex flex-col gap-4">
      <Hairline label={label} strong />
      <h2 className="text-ink text-xl leading-none font-medium">{title}</h2>
      {children}
    </section>
  )
}

function Row({ caption, children }: { caption: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      <span className="hs-label">{caption}</span>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  )
}

const substrateTokens = [
  { name: "--bg", dark: "#070B12", light: "#F5F7FA" },
  { name: "--surface", dark: "#0D1420", light: "#FFFFFF" },
  { name: "--surface-raised", dark: "#151C29", light: "#F6F9FD" },
  { name: "--surface-sunken", dark: "#09101B", light: "#F0F3F8" },
  { name: "--hairline", dark: "#1A2434", light: "#DDE3EB" },
  { name: "--hairline-strong", dark: "#2B3646", light: "#C0C6CE" },
]

const inkTokens = [
  { name: "--ink", dark: "#E8EEF6", light: "#101A2B" },
  { name: "--ink-dim", dark: "#7E8FA6", light: "#5A6B82" },
  { name: "--ink-faint", dark: "#717E90", light: "#69778A" },
]

const accentTokens = [
  { name: "--hs-navy", dark: "#0E2A55", light: "#0E2A55" },
  { name: "--hs-azure", dark: "#2E8FDD", light: "#1E6FBF" },
  { name: "--sev-critical", dark: "#E5484D", light: "#C62A2F" },
  { name: "--sev-high", dark: "#F0A020", light: "#B87400" },
  { name: "--sev-info", dark: "#2E8FDD", light: "#1E6FBF" },
]

function TokenTable({
  rows,
  dark,
}: {
  rows: { name: string; dark: string; light: string }[]
  dark: boolean
}) {
  return (
    <div className="border-hairline overflow-x-auto rounded-md border">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-hairline border-b">
            <th className="hs-label h-8 w-10 px-3 text-start"> </th>
            <th className="hs-label h-8 px-3 text-start">Token</th>
            <th className="hs-label h-8 px-3 text-start">Dark</th>
            <th className="hs-label h-8 px-3 text-start">Light</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.name} className="border-hairline border-b last:border-0">
              <td className="px-3 py-1.5">
                <span
                  className="border-hairline-strong block size-5 rounded-sm border"
                  style={{ background: `var(${row.name})` }}
                />
              </td>
              <td className="hs-num text-ink px-3 py-1.5 text-xs">{row.name}</td>
              <td className={cn("hs-num px-3 py-1.5 text-xs", dark ? "text-ink" : "text-ink-faint")}>
                {row.dark}
              </td>
              <td className={cn("hs-num px-3 py-1.5 text-xs", dark ? "text-ink-faint" : "text-ink")}>
                {row.light}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const typeSteps: { token: string; cls: string; sample: string }[] = [
  { token: "--text-display", cls: "text-[length:var(--text-display)] font-display", sample: "Falcon Ops" },
  { token: "--text-5xl / h1", cls: "text-5xl font-display", sample: "Every packet matters" },
  { token: "--text-3xl / h2", cls: "text-3xl font-display", sample: "Detections" },
  { token: "--text-xl / h3", cls: "text-xl font-display", sample: "Sensor health" },
  { token: "--text-lg / h4", cls: "text-lg font-display", sample: "Interface wlan1mon" },
  { token: "--text-base / body", cls: "text-base", sample: "HawkShield detects, classifies and reports wireless intrusions." },
  { token: "--text-sm", cls: "text-sm", sample: "Secondary body and table cells." },
  { token: "--text-xs", cls: "text-xs", sample: "Captions, deltas, dense metadata." },
  { token: "--text-micro / .hs-label", cls: "hs-label", sample: "Micro label" },
]

type Detection = {
  id: string
  time: string
  type: (typeof attackTypes)[number]
  bssid: string
  channel: number
  frames: number
  confidence: number
}

const detections: Detection[] = [
  { id: "d-1041", time: "14:02:11", type: "evil_twin", bssid: "A4:2B:8C:11:04:9F", channel: 6, frames: 412, confidence: 0.97 },
  { id: "d-1040", time: "14:01:48", type: "deauth", bssid: "18:D6:C7:0A:71:32", channel: 11, frames: 1284, confidence: 0.99 },
  { id: "d-1039", time: "13:58:02", type: "krack", bssid: "F0:9F:C2:3D:88:10", channel: 1, frames: 96, confidence: 0.88 },
  { id: "d-1038", time: "13:55:37", type: "ssdp", bssid: "3C:71:BF:52:6E:04", channel: 6, frames: 33, confidence: 0.71 },
  { id: "d-1037", time: "13:51:20", type: "rogueap", bssid: "8C:1F:64:A0:2B:77", channel: 9, frames: 208, confidence: 0.93 },
]

const trend = [4, 6, 5, 9, 8, 14, 11, 19, 16, 22, 27, 24]

/* -------------------------------------------------------------------------- */

export default function DesignPage() {
  /* Drives the real providers rather than a local wrapper class. A wrapper works
     for everything inside it, but `<body>`'s own background sits outside — so a
     "light" wrapper on a dark document read as broken. Going through the
     providers also means this page exercises the same code path the CommandBar
     does, which is the point of a style sheet. */
  const { resolved, setTheme } = useTheme()
  const { locale, setLocale } = useLocale()
  const dark = resolved === "dark"
  const rtl = locale === "ar"
  const setDark = (next: (v: boolean) => boolean) => setTheme(next(dark) ? "dark" : "light")
  const setRtl = (next: (v: boolean) => boolean) => setLocale(next(rtl) ? "ar" : "en")
  const [sort, setSort] = React.useState<DataTableSort | null>({ columnId: "time", direction: "desc" })
  const [selected, setSelected] = React.useState<React.Key | null>("d-1040")
  const [arrivalKey, setArrivalKey] = React.useState(0)
  const [live, setLive] = React.useState(true)

  const columns: DataTableColumn<Detection>[] = React.useMemo(
    () => [
      { id: "time", header: "Time", sortable: true, width: "6.5rem", cell: (r) => <span className="hs-num text-ink-dim">{r.time}</span> },
      {
        id: "type",
        header: "Class",
        cell: (r) => (
          <span className="inline-flex items-center gap-2">
            <span
              aria-hidden="true"
              className="size-2 shrink-0 rounded-full"
              style={{ background: attackColors[r.type] }}
            />
            <span className="text-ink">{attackLabels[r.type]}</span>
          </span>
        ),
      },
      { id: "severity", header: "Severity", cell: (r) => <StatusPill tone={severityOf(r.type)}>{severityOf(r.type)}</StatusPill> },
      { id: "bssid", header: "BSSID", hideBelow: "md", cell: (r) => <span className="hs-num text-ink-dim">{r.bssid}</span> },
      { id: "channel", header: "Ch", numeric: true, sortable: true, width: "4rem", cell: (r) => r.channel },
      { id: "frames", header: "Frames", numeric: true, sortable: true, width: "6rem", cell: (r) => r.frames.toLocaleString() },
      {
        id: "confidence",
        header: "Conf.",
        numeric: true,
        sortable: true,
        width: "5.5rem",
        cell: (r) => `${(r.confidence * 100).toFixed(0)}%`,
      },
    ],
    []
  )

  return (
    <div className={cn(dark && "dark")} dir={rtl ? "rtl" : "ltr"} lang={rtl ? "ar" : "en"}>
      <div className="bg-bg text-ink min-h-screen">
        {/* ---- chrome ---------------------------------------------------- */}
        <header className="border-hairline bg-surface sticky top-0 z-20 flex flex-wrap items-center gap-3 border-b px-4 py-2.5">
          <Logo size={26} decorative />
          <Wordmark size="sm" split />
          <span className="hs-label text-ink-faint hidden sm:inline">style sheet</span>

          <div className="ms-auto flex items-center gap-2">
            <Radar size={12} active={live} label={live ? "Sensor live" : "Sensor stopped"} />
            <Button size="sm" variant="ghost" onClick={() => setLive((v) => !v)}>
              {live ? "Stop sweep" : "Start sweep"}
            </Button>
            <Button size="sm" variant="secondary" onClick={() => setDark((v) => !v)}>
              {dark ? "Light" : "Dark"}
            </Button>
            <Button size="sm" variant="secondary" onClick={() => setRtl((v) => !v)}>
              {rtl ? "LTR" : "RTL"}
            </Button>
          </div>
        </header>

        <main className="mx-auto flex max-w-6xl flex-col gap-12 px-4 py-10">
          {/* ---- masthead ------------------------------------------------ */}
          <div className="flex flex-col gap-4">
            <span className="hs-label">Falcon Ops — tactical instrument</span>
            <h1 className="text-ink">Every packet matters</h1>
            <p className="text-ink-dim max-w-prose text-base">
              HawkShield is an intrusion <em>detection</em> system. It detects, classifies and
              reports; it never blocks or prevents. Structure on this page comes from hairlines and
              tabular data — not from cards, gradients or glass.
            </p>
          </div>

          {/* ---- tokens -------------------------------------------------- */}
          <Section label="01 — Colour" title="Tokens">
            <p className="text-ink-dim max-w-prose text-sm">
              Two brand hues sampled off the real mark, plus two warm severity hues. Every other
              step is an <code>oklch()</code> derivation of one of those four. Swatches below render
              the <em>current</em> theme; the two hex columns list both.
            </p>
            <div className="grid gap-4 lg:grid-cols-3">
              <div className="flex flex-col gap-2">
                <span className="hs-label">Substrate</span>
                <TokenTable rows={substrateTokens} dark={dark} />
              </div>
              <div className="flex flex-col gap-2">
                <span className="hs-label">Ink</span>
                <TokenTable rows={inkTokens} dark={dark} />
              </div>
              <div className="flex flex-col gap-2">
                <span className="hs-label">Brand &amp; severity</span>
                <TokenTable rows={accentTokens} dark={dark} />
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <span className="hs-label">Threat class ramp — navy to azure, plus two warm anchors</span>
              <div className="border-hairline grid grid-cols-2 gap-px overflow-hidden rounded-md border bg-[var(--hairline)] sm:grid-cols-3 lg:grid-cols-5">
                {attackTypes.map((type) => (
                  <div key={type} className="bg-surface flex flex-col gap-1.5 p-3">
                    <span className="block h-6 rounded-sm" style={{ background: attackColors[type] }} />
                    <span className="text-ink text-xs font-medium">{attackLabels[type]}</span>
                    <span className="hs-num text-ink-faint text-[0.6875rem]">{attackColors[type]}</span>
                    <StatusPill tone={severityOf(type)}>{severityOf(type)}</StatusPill>
                  </div>
                ))}
              </div>
            </div>
          </Section>

          {/* ---- type ---------------------------------------------------- */}
          <Section label="02 — Type" title="Scale and faces">
            <div className="border-hairline flex flex-col divide-y divide-[var(--hairline)] rounded-md border">
              {typeSteps.map((step) => (
                <div key={step.token} className="flex flex-col gap-1 p-3 sm:flex-row sm:items-baseline sm:gap-6">
                  <span className="hs-label w-48 shrink-0">{step.token}</span>
                  <span className={cn("min-w-0 break-words", step.cls)}>{step.sample}</span>
                </div>
              ))}
            </div>

            <div className="grid gap-3 md:grid-cols-3">
              <Module label="Display — Space Grotesk">
                <p className="font-display text-2xl">Sensor · Detections · Reports</p>
                <p className="font-display hs-num text-ink-dim mt-2 text-sm">0123456789</p>
              </Module>
              <Module label="Body — IBM Plex Sans">
                <p className="text-sm">
                  Classified 1,284 deauthentication frames on channel 11 within a 20-second window.
                </p>
                <p className="hs-num text-ink-dim mt-2 text-sm">0123456789</p>
              </Module>
              <Module label="Arabic — IBM Plex Sans Arabic">
                <div dir="rtl" lang="ar">
                  <p className="text-sm">
                    يكتشف هوك شيلد هجمات الشبكات اللاسلكية، ويصنّفها، ويرفع عنها التقارير. كل حزمة
                    مهمة.
                  </p>
                  <p className="text-ink-dim mt-2 text-sm">الوكيل: صقر</p>
                  <p className="hs-num text-ink-dim mt-2 text-sm">0123456789</p>
                </div>
              </Module>
            </div>

            <div className="border-hairline rounded-md border p-3">
              <span className="hs-label">Mono — IBM Plex Mono, tabular</span>
              <div className="mt-2 flex flex-col">
                <span className="hs-num text-sm">14:02:11  A4:2B:8C:11:04:9F  ch06  1,284</span>
                <span className="hs-num text-sm">13:58:02  F0:9F:C2:3D:88:10  ch01     96</span>
                <span className="hs-num text-sm">13:51:20  8C:1F:64:A0:2B:77  ch09    208</span>
              </div>
            </div>
          </Section>

          {/* ---- geometry ------------------------------------------------ */}
          <Section label="03 — Geometry" title="Radius, surfaces, elevation">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Module label="Radius 0 — tables">
                <div className="border-hairline-strong bg-surface-sunken h-12 rounded-sm border" />
              </Module>
              <Module label="Radius 2 — modules">
                <div className="border-hairline-strong bg-surface-sunken h-12 rounded-md border" />
              </Module>
              <Module label="Radius 999 — pills only">
                <div className="border-hairline-strong bg-surface-sunken h-12 rounded-full border" />
              </Module>
              <Module label="Elevation">
                <div className="bg-surface-raised border-hairline hs-elev h-12 rounded-md border" />
                <p className="text-ink-faint mt-2 text-xs">
                  One step. Resolves to nothing in dark — lift is the surface change.
                </p>
              </Module>
            </div>

            <div className="flex flex-wrap items-stretch gap-3">
              {["--bg", "--surface", "--surface-raised", "--surface-sunken"].map((token) => (
                <div
                  key={token}
                  className="border-hairline flex min-w-40 flex-1 flex-col justify-end rounded-md border p-3"
                  style={{ background: `var(${token})` }}
                >
                  <span className="hs-label">{token}</span>
                </div>
              ))}
            </div>
          </Section>

          {/* ---- motion -------------------------------------------------- */}
          <Section label="04 — Motion" title="Three behaviours, one loop">
            <p className="text-ink-dim max-w-prose text-sm">
              120 / 220 / 400ms on <code>cubic-bezier(0.16, 1, 0.3, 1)</code>. Everything collapses
              to its end state under <code>prefers-reduced-motion</code>.
            </p>
            <div className="grid gap-3 md:grid-cols-3">
              <Module label="Radar — 4s ambient sweep">
                <div className="flex items-center gap-4 py-2">
                  <Radar size={40} active={live} label="Sensor live" />
                  <Radar size={20} active={live} label="Sensor live" />
                  <Radar size={12} active={live} label="Sensor live" />
                  <Radar size={20} active={false} label="Sensor stopped" />
                </div>
                <p className="text-ink-faint text-xs">
                  The only ambient loop in the product. Never mount it over a dead sensor.
                </p>
              </Module>

              <Module
                label="Arrival — 220ms in, 900ms decay"
                actions={
                  <Button size="sm" variant="ghost" onClick={() => setArrivalKey((k) => k + 1)}>
                    <RefreshCw />
                    Replay
                  </Button>
                }
              >
                <div className="flex flex-col gap-1">
                  {(["critical", "high", "info"] as const).map((tone, i) => (
                    <div
                      key={`${tone}-${arrivalKey}`}
                      className="hs-arrival border-hairline flex items-center justify-between gap-2 rounded-sm border px-2 py-1.5"
                      style={
                        {
                          "--hs-arrival-tint": `var(--sev-${tone})`,
                          animationDelay: `${i * 140}ms`,
                        } as React.CSSProperties
                      }
                    >
                      <span className="text-sm">Detection {1041 + i}</span>
                      <StatusPill tone={tone}>{tone}</StatusPill>
                    </div>
                  ))}
                </div>
              </Module>

              <Module label="Hairline scan — loading">
                <div className="hs-scan border-hairline grid h-28 place-items-center rounded-sm border">
                  <span className="hs-label">Reading capture</span>
                </div>
                <p className="text-ink-faint mt-2 text-xs">Replaces the spinner everywhere.</p>
              </Module>
            </div>
          </Section>

          {/* ---- instrument primitives ----------------------------------- */}
          <Section label="05 — Primitives" title="components/hs">
            <ModuleGrid className="lg:grid-cols-3">
              <Module label="Module" title="With title + actions" actions={<Button size="sm" variant="ghost"><Filter />Filter</Button>}>
                <p className="text-ink-dim text-sm">
                  The core repeating unit: hairline border, mono micro-label header, optional
                  inline-end actions slot.
                </p>
              </Module>
              <Module label="Module" title="Loading" loading>
                <p className="text-ink-dim text-sm">
                  Content stays mounted under the scan, so column widths never jump.
                </p>
              </Module>
              <Module label="Module — flush" flush>
                <div className="divide-y divide-[var(--hairline)]">
                  {["wlan1mon", "wlan0", "eth0"].map((iface) => (
                    <div key={iface} className="flex items-center justify-between px-3 py-2 text-sm">
                      <span className="hs-num">{iface}</span>
                      <StatusPill tone={iface === "wlan1mon" ? "info" : "neutral"} dot>
                        {iface === "wlan1mon" ? "capturing" : "idle"}
                      </StatusPill>
                    </div>
                  ))}
                </div>
              </Module>
            </ModuleGrid>

            <ModuleGrid className="lg:grid-cols-3">
              <Module label="Metric">
                <div className="grid grid-cols-2 gap-4">
                  <Metric
                    label="Detections / 24h"
                    value={1284}
                    delta={137}
                    deltaLabel="vs. yesterday"
                    footer={<Sparkline values={trend} width={92} height={20} area />}
                  />
                  <Metric label="Critical" value={9} tone="critical" delta={-3} deltaLabel="vs. yesterday" />
                </div>
              </Module>

              <Module label="Sparkline">
                <div className="flex flex-col gap-3">
                  <div className="flex items-center gap-3">
                    <span className="hs-label w-24">line</span>
                    <Sparkline values={trend} label="Detections trending up" />
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="hs-label w-24">area</span>
                    <Sparkline values={trend} area />
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="hs-label w-24">critical</span>
                    <Sparkline values={[9, 7, 8, 4, 6, 3, 5, 2]} stroke="var(--sev-critical)" />
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="hs-label w-24">no history</span>
                    <Sparkline values={[3]} />
                  </div>
                </div>
              </Module>

              <Module label="Status pill">
                <div className="flex flex-col gap-3">
                  <Row caption="quiet">
                    <StatusPill tone="critical">critical</StatusPill>
                    <StatusPill tone="high">high</StatusPill>
                    <StatusPill tone="info">info</StatusPill>
                    <StatusPill tone="neutral">idle</StatusPill>
                  </Row>
                  <Row caption="solid">
                    <StatusPill tone="critical" variant="solid">critical</StatusPill>
                    <StatusPill tone="high" variant="solid">high</StatusPill>
                    <StatusPill tone="info" variant="solid">info</StatusPill>
                    <StatusPill tone="neutral" variant="solid">idle</StatusPill>
                  </Row>
                  <Row caption="with dot">
                    <StatusPill tone="info" dot>capturing</StatusPill>
                    <StatusPill tone="neutral" dot>stopped</StatusPill>
                  </Row>
                </div>
              </Module>
            </ModuleGrid>

            <ModuleGrid className="lg:grid-cols-2">
              <Module label="Hairline">
                <div className="flex flex-col gap-4">
                  <Hairline />
                  <Hairline label="Labelled, start-aligned" />
                  <Hairline label="Centred" align="center" />
                  <Hairline strong label="Strong" />
                  <div className="flex h-10 items-center gap-3">
                    <span className="text-sm">vertical</span>
                    <Hairline orientation="vertical" />
                    <span className="text-sm">rule</span>
                  </div>
                </div>
              </Module>

              <Module label="Terminal line" title="Saqr tool trace">
                <div className="flex flex-col">
                  <TerminalLine stamp="14:02:11" tone="muted">session start · model=lightgbm-v3</TerminalLine>
                  <TerminalLine stamp="14:02:11" tone="accent">tool_call query_detections(window=&quot;15m&quot;)</TerminalLine>
                  <TerminalLine stamp="14:02:12" tone="muted" depth={1}>returned 42 rows in 118ms</TerminalLine>
                  <TerminalLine stamp="14:02:12" tone="critical">evil_twin · A4:2B:8C:11:04:9F · conf 0.97</TerminalLine>
                  <TerminalLine stamp="14:02:12" tone="high">deauth burst · 1,284 frames · ch11</TerminalLine>
                  <TerminalLine stamp="14:02:13" pending tone="muted">composing report</TerminalLine>
                </div>
              </Module>
            </ModuleGrid>
          </Section>

          {/* ---- data table ---------------------------------------------- */}
          <Section label="06 — Data table" title="Four states, built in">
            <Module
              label="Detections"
              title="Last 15 minutes"
              flush
              actions={
                <>
                  <Radar size={11} active={live} label="Live" />
                  <Button size="sm" variant="ghost"><Download />Export</Button>
                </>
              }
            >
              <DataTable
                columns={columns}
                rows={detections}
                rowKey={(row) => row.id}
                emptyLabel="No detections in window"
                sort={sort}
                onSortChange={setSort}
                selectedKey={selected}
                onRowSelect={(row) => setSelected(row.id)}
                isArriving={(row) => row.id === "d-1041"}
                tintOf={(row) => attackColors[row.type]}
              />
            </Module>

            <div className="grid gap-3 lg:grid-cols-3">
              <Module label="State — loading" flush>
                <DataTable
                  columns={columns.slice(0, 3)}
                  rows={[]}
                  rowKey={(row) => row.id}
                  state="loading"
                  emptyLabel="No detections in window"
                  loadingLabel="Reading capture"
                />
              </Module>
              <Module label="State — empty" flush>
                <DataTable
                  columns={columns.slice(0, 3)}
                  rows={[]}
                  rowKey={(row) => row.id}
                  emptyLabel="No detections in window"
                />
              </Module>
              <Module label="State — error" flush>
                <DataTable
                  columns={columns.slice(0, 3)}
                  rows={[]}
                  rowKey={(row) => row.id}
                  state="error"
                  emptyLabel="No detections in window"
                  errorLabel="Sensor unreachable"
                />
              </Module>
            </div>
          </Section>

          {/* ---- controls ------------------------------------------------ */}
          <Section label="07 — Controls" title="components/ui">
            <Module label="Button" title="variant × state">
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-sm">
                  <thead>
                    <tr className="border-hairline border-b">
                      <th className="hs-label h-8 px-3 text-start">Variant</th>
                      <th className="hs-label h-8 px-3 text-start">Default</th>
                      <th className="hs-label h-8 px-3 text-start">Hover</th>
                      <th className="hs-label h-8 px-3 text-start">Focus</th>
                      <th className="hs-label h-8 px-3 text-start">Disabled</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(
                      [
                        ["default", "bg-[color-mix(in_oklab,var(--primary)_88%,var(--ink))]"],
                        ["destructive", "bg-[color-mix(in_oklab,var(--destructive)_88%,var(--ink))]"],
                        ["outline", "bg-surface-raised"],
                        ["secondary", "bg-surface-raised"],
                        ["ghost", "bg-surface-raised text-ink"],
                        ["link", "underline"],
                      ] as const
                    ).map(([variant, hoverClass]) => (
                      <tr key={variant} className="border-hairline border-b last:border-0">
                        <td className="hs-label px-3 py-2">{variant}</td>
                        <td className="px-3 py-2">
                          <Button variant={variant}>Run scan</Button>
                        </td>
                        {/* Hover and focus are painted statically: a style sheet has to
                            show the state without asking the reader to hold a mouse still. */}
                        <td className="px-3 py-2">
                          <Button variant={variant} className={hoverClass}>Run scan</Button>
                        </td>
                        <td className="px-3 py-2">
                          <Button variant={variant} className="outline-2 outline-offset-2 outline-[var(--ring)]">
                            Run scan
                          </Button>
                        </td>
                        <td className="px-3 py-2">
                          <Button variant={variant} disabled>Run scan</Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="mt-4 flex flex-col gap-2">
                <span className="hs-label">Sizes</span>
                <div className="flex flex-wrap items-center gap-2">
                  <Button size="sm">Small</Button>
                  <Button size="default">Default</Button>
                  <Button size="lg">Large</Button>
                  <Button size="icon" aria-label="Refresh"><RefreshCw /></Button>
                </div>
              </div>
            </Module>

            <ModuleGrid className="lg:grid-cols-2">
              <Module label="Badge" title="names a thing — square">
                <div className="flex flex-wrap gap-2">
                  <Badge>wlan1mon</Badge>
                  <Badge variant="secondary">802.11</Badge>
                  <Badge variant="outline">ch 11</Badge>
                  <Badge variant="destructive">unverified</Badge>
                </div>
                <p className="text-ink-faint mt-3 text-xs">
                  Square corners; a StatusPill grades and is round. The radius is the difference.
                </p>
              </Module>

              <Module label="Field" title="input / checkbox / select">
                <div className="flex flex-col gap-3">
                  <div className="flex flex-col gap-1.5">
                    <span className="hs-label">Default</span>
                    <Input placeholder="Filter by BSSID" />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <span className="hs-label">Filled</span>
                    <Input defaultValue="A4:2B:8C:11:04:9F" className="hs-num" />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <span className="hs-label">Invalid</span>
                    <Input defaultValue="not-a-bssid" aria-invalid />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <span className="hs-label">Disabled</span>
                    <Input placeholder="Filter by BSSID" disabled />
                  </div>

                  <div className="flex flex-wrap items-center gap-4">
                    <label className="flex items-center gap-2 text-sm">
                      <Checkbox defaultChecked /> Checked
                    </label>
                    <label className="flex items-center gap-2 text-sm">
                      <Checkbox /> Unchecked
                    </label>
                    <label className="text-ink-dim flex items-center gap-2 text-sm">
                      <Checkbox disabled /> Disabled
                    </label>
                  </div>

                  <Select defaultValue="15m">
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="15m">Last 15 minutes</SelectItem>
                      <SelectItem value="1h">Last hour</SelectItem>
                      <SelectItem value="24h">Last 24 hours</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </Module>
            </ModuleGrid>

            <Module label="Overlays" title="portalled — see note at top of file">
              <div className="flex flex-wrap gap-2">
                <Dialog>
                  <DialogTrigger asChild>
                    <Button variant="outline">Open dialog</Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Export detections</DialogTitle>
                      <DialogDescription>
                        Writes the current filter selection to CSV. Nothing leaves the sensor.
                      </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                      <Button variant="ghost">Cancel</Button>
                      <Button>Export</Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>

                <Sheet>
                  <SheetTrigger asChild>
                    <Button variant="outline">Open sheet</Button>
                  </SheetTrigger>
                  <SheetContent>
                    <SheetHeader>
                      <SheetTitle>Detection d-1041</SheetTitle>
                      <SheetDescription>Evil Twin · A4:2B:8C:11:04:9F · channel 6</SheetDescription>
                    </SheetHeader>
                    <div className="flex flex-col gap-2 p-4">
                      <TerminalLine stamp="14:02:11" tone="muted">first seen</TerminalLine>
                      <TerminalLine stamp="14:02:44" tone="muted">last seen</TerminalLine>
                    </div>
                  </SheetContent>
                </Sheet>

                <Popover>
                  <PopoverTrigger asChild>
                    <Button variant="outline">Open popover</Button>
                  </PopoverTrigger>
                  <PopoverContent>
                    <span className="hs-label">Confidence</span>
                    <p className="text-ink-dim mt-2 text-sm">
                      Model output, not a probability of harm. Calibrated on the held-out capture.
                    </p>
                  </PopoverContent>
                </Popover>
              </div>
            </Module>

            <Module label="Toast" title="confirmation only — detections use the arrival wash">
              {/* Radix portals every Toast into its Viewport, so pinning the
                  viewport in-flow is enough to preview toasts inside the themed
                  wrapper instead of fixed to the corner of the window. */}
              <ToastProvider duration={86400000}>
                <Toast open>
                  <div className="grid gap-1">
                    <ToastTitle>Report generated</ToastTitle>
                    <ToastDescription>4 detections written to report-1041.pdf</ToastDescription>
                  </div>
                </Toast>
                <Toast open variant="destructive">
                  <div className="grid gap-1">
                    <ToastTitle>Sensor unreachable</ToastTitle>
                    <ToastDescription>No response from wlan1mon for 30s</ToastDescription>
                  </div>
                </Toast>
                <ToastViewport className="static! flex w-full max-w-none flex-col gap-2 p-0" />
              </ToastProvider>
            </Module>
          </Section>

          {/* ---- brand --------------------------------------------------- */}
          <Section label="08 — Brand" title="Mark and wordmark">
            <ModuleGrid className="lg:grid-cols-2">
              <Module label="Mark — flat, no glow">
                <div className="flex flex-wrap items-end gap-6 py-2">
                  {[96, 48, 32, 20].map((size) => (
                    <div key={size} className="flex flex-col items-center gap-2">
                      <Logo size={size} />
                      <span className="hs-num text-ink-faint text-[0.6875rem]">{size}px</span>
                    </div>
                  ))}
                </div>
              </Module>
              <Module label="Wordmark">
                <div className="flex flex-col gap-4 py-2">
                  <Wordmark size="lg" split />
                  <Wordmark size="md" />
                  <div className="flex items-center gap-3">
                    <Logo size={28} decorative />
                    <Wordmark size="sm" split />
                  </div>
                </div>
              </Module>
            </ModuleGrid>
          </Section>

          <footer className="border-hairline text-ink-faint border-t pt-4 text-xs">
            <p>
              Dev-only reference. Anti-patterns permanently out of the system: gradient text,
              glassmorphism, rounded cards with a coloured left border, emoji icons, neon glow on
              the mark, and GitHub-dark cosplay.
            </p>
          </footer>
        </main>
      </div>
    </div>
  )
}
