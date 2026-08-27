"use client"

import * as React from "react"
import { Download, Filter, RefreshCw } from "lucide-react"

import { Logo, Wordmark } from "@/components/brand/logo"
import { useLocale } from "@/components/providers/locale-provider"
import { useTheme } from "@/components/providers/theme-provider"
import { AccentWord } from "@/components/hs/accent-word"
import { CommandBar } from "@/components/hs/command-bar"
import {
  DataCard,
  DataCardBar,
  DataCardNote,
  DataCardRow,
  DataCardRows,
  DataCardTotal,
} from "@/components/hs/data-card"
import { DataTable, type DataTableColumn, type DataTableSort } from "@/components/hs/data-table"
import { Eyebrow } from "@/components/hs/eyebrow"
import { Hairline } from "@/components/hs/hairline"
import { Marquee } from "@/components/hs/marquee"
import { Metric } from "@/components/hs/metric"
import { NavPill } from "@/components/hs/nav-pill"
import { Panel, PanelGrid } from "@/components/hs/panel"
import { Radar } from "@/components/hs/radar"
import { SectionHead } from "@/components/hs/section-head"
import { Sparkline } from "@/components/hs/sparkline"
import { StatementFooter } from "@/components/hs/statement-footer"
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
import { attackColorVar, attackLabels, attackTypes, severityOf, type AttackType } from "@/lib/colors"
import { cn } from "@/lib/utils"

/**
 * FALCON PAPER — the design system, rendered as one page.
 *
 * A dev-only surface, and the reference every other engineer on this project
 * builds against. If a primitive is not on this page it does not exist yet.
 *
 * Copy is hardcoded here on purpose. This is not a shipped screen; it is the
 * one place in the repo where literal strings in a component are correct, and
 * the Arabic block below is set as literal Arabic so the script can be judged
 * without the dictionary in the way.
 *
 * The theme and locale controls at the top drive the REAL providers
 * (`useTheme()`, `useLocale()`), not local state — so what you see here is
 * exactly what the app does, including how the Radix portals (Dialog, Sheet,
 * Select, Popover) resolve, since those mount on `document.body`.
 *
 * NOTHING ON THIS PAGE IS SENSOR DATA. Every figure is a placeholder chosen to
 * exercise a layout, and every block that carries one says so. HawkShield does
 * not invent detections, and neither does its style sheet.
 */

/* -------------------------------------------------------------------------- */
/* Scaffolding — local to this page, not part of the system                    */
/* -------------------------------------------------------------------------- */

function Section({
  id,
  label,
  title,
  body,
  children,
}: {
  id: string
  label: string
  title: React.ReactNode
  body?: string
  children: React.ReactNode
}) {
  return (
    <section id={id} className="flex scroll-mt-28 flex-col gap-8 pt-16">
      <SectionHead eyebrow={label} title={title} body={body} />
      {children}
    </section>
  )
}

function Row({ caption, children }: { caption: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-3">
      <span className="hs-label">{caption}</span>
      <div className="flex flex-wrap items-center gap-3">{children}</div>
    </div>
  )
}

/** A token swatch. The name IS the label — that is the point of the page. */
function Swatch({
  token,
  note,
  className,
  ring = false,
}: {
  token: string
  note: string
  className: string
  ring?: boolean
}) {
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <div
        className={cn(
          "h-16 rounded-md",
          ring ? "border-rule-soft border" : "border-rule border",
          className
        )}
        aria-hidden="true"
      />
      <span className="hs-num text-ink-0 truncate text-xs">{token}</span>
      <span className="text-ink-2 text-xs leading-snug">{note}</span>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Placeholder fixtures — labelled everywhere they are used                    */
/* -------------------------------------------------------------------------- */

type SampleRow = {
  time: string
  bssid: string
  cls: AttackType
  channel: number
  rssi: number
}

/** Shape-only fixtures. Nothing here was measured; see the banner at the top. */
const SAMPLE_ROWS: readonly SampleRow[] = [
  { time: "14:02:11", bssid: "A4:2B:B0:11:9C:3E", cls: "evil_twin", channel: 6, rssi: -42 },
  { time: "14:02:09", bssid: "3C:71:BF:08:12:04", cls: "deauth", channel: 11, rssi: -67 },
  { time: "14:01:58", bssid: "3C:71:BF:08:12:04", cls: "deauth", channel: 11, rssi: -66 },
  { time: "14:01:47", bssid: "D8:47:32:AA:01:7B", cls: "krack", channel: 1, rssi: -55 },
  { time: "14:01:30", bssid: "E0:CB:BC:44:2D:19", cls: "ssdp", channel: 6, rssi: -71 },
]

const SAMPLE_SPARK = [4, 6, 5, 9, 7, 12, 10, 14, 11, 18, 16, 21]

const TYPE_STEPS = [
  { token: "--text-display", cls: "text-display", note: "hero headline only" },
  { token: "--text-5xl", cls: "text-5xl", note: "page title" },
  { token: "--text-4xl", cls: "text-4xl", note: "footer statement, h1" },
  { token: "--text-3xl", cls: "text-3xl", note: "section head, h2" },
  { token: "--text-2xl", cls: "text-2xl", note: "big figure on a data card" },
  { token: "--text-xl", cls: "text-xl", note: "panel title, h3" },
  { token: "--text-lg", cls: "text-lg", note: "lede, h4" },
  { token: "--text-md", cls: "text-md", note: "section body column" },
  { token: "--text-base", cls: "text-base", note: "body" },
  { token: "--text-sm", cls: "text-sm", note: "table cell, secondary" },
  { token: "--text-xs", cls: "text-xs", note: "caption" },
]

/* -------------------------------------------------------------------------- */
/* Page                                                                       */
/* -------------------------------------------------------------------------- */

export default function DesignPage() {
  const { resolved, setTheme } = useTheme()
  const { locale, setLocale } = useLocale()
  const dark = resolved === "dark"

  const [sort, setSort] = React.useState<DataTableSort>({ columnId: "time", direction: "desc" })
  const [checked, setChecked] = React.useState(true)
  const [live, setLive] = React.useState(true)

  const columns: readonly DataTableColumn<SampleRow>[] = React.useMemo(
    () => [
      {
        id: "time",
        header: "Time",
        sortable: true,
        cell: (r) => <span className="hs-num text-ink-1 text-sm">{r.time}</span>,
      },
      {
        id: "class",
        header: "Class",
        cell: (r) => (
          <span className="flex items-center gap-2">
            <span
              aria-hidden="true"
              className="size-2 shrink-0 rounded-full"
              style={{ background: attackColorVar(r.cls) }}
            />
            <span className="text-ink-0 text-sm">{attackLabels[r.cls]}</span>
          </span>
        ),
      },
      {
        id: "bssid",
        header: "BSSID",
        hideBelow: "md",
        cell: (r) => <span className="hs-num text-ink-1 text-sm">{r.bssid}</span>,
      },
      { id: "channel", header: "Ch", numeric: true, cell: (r) => r.channel },
      { id: "rssi", header: "RSSI", numeric: true, hideBelow: "sm", cell: (r) => `${r.rssi} dBm` },
      {
        id: "severity",
        header: "Severity",
        align: "end",
        cell: (r) => <StatusPill tone={severityOf(r.cls)}>{severityOf(r.cls)}</StatusPill>,
      },
    ],
    []
  )

  const navLinks = [
    { href: "#foundations", label: "Colour" },
    { href: "#type", label: "Type" },
    { href: "#primitives", label: "Primitives" },
    { href: "#arabic", label: "العربية" },
  ]

  return (
    <div className="min-w-0">
      {/* ── N5 · Floating pill ─────────────────────────────────────────── */}
      <NavPill
        label="Design system"
        brand={
          <>
            <Logo size={22} decorative />
            {/* Stands down below 400px so the pill stays content-sized on a
                320px phone rather than stretching to the viewport. */}
            <Wordmark size="sm" split className="hidden min-[400px]:inline-block" />
          </>
        }
        links={navLinks}
        actions={<CommandBar />}
      />

      {/* ── Hero · Marquee ─────────────────────────────────────────────── */}
      {/* Bottom padding is 1.4x the top, so the hero settles into the page
          rather than floating above it. */}
      <header className="mx-auto w-full max-w-[1240px] px-6 pt-28 pb-40 sm:px-8">
        <Eyebrow variant="pill" tone="accent" live={live}>
          Falcon Paper · v3 · style sheet
        </Eyebrow>

        <div className="mt-8 grid items-center gap-12 lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]">
          <div className="min-w-0">
            <h1 className="font-display text-ink-0 text-display max-w-[13ch] min-w-0 font-bold [overflow-wrap:anywhere]">
              A sensor that <AccentWord>explains</AccentWord> itself.
            </h1>

            <p className="text-ink-1 text-md mt-6 max-w-[52ch]">
              HawkShield watches 802.11 frames from a Raspberry Pi, classifies what it
              sees into eight attack types, and reports it. It does not block, and it
              never claims a network is clean — this system is built to say exactly that
              much and no more.
            </p>

            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Button>Primary action</Button>
              <Button variant="outline">Secondary</Button>
              <Button variant="ghost">Tertiary</Button>
            </div>

            <div className="text-ink-2 mt-6 flex flex-wrap items-center gap-x-5 gap-y-2">
              <span className="hs-label">2 families</span>
              <span className="hs-label">2 rule weights</span>
              <span className="hs-label">1 accent</span>
              <span className="hs-label">light + dark authored</span>
            </div>
          </div>

          {/* The hero object. Values are placeholders — the card says so. */}
          <DataCard
            label="wlan1mon"
            title="Capture window · placeholder values"
            status={<StatusPill tone="info" live={live}>{live ? "live" : "paused"}</StatusPill>}
          >
            <DataCardRows>
              <DataCardRow label="Frames seen" value="—" />
              <DataCardRow label="Classified" value="—" />
              <DataCardRow label="Evil Twin" value="—" tone="critical" />
              <DataCardRow label="KRACK" value="—" tone="companion" />
            </DataCardRows>
            <DataCardTotal label="Detections in window" value="—" unit="events" />
            <DataCardBar
              label="Severity split — layout placeholder, not a measurement"
              segments={[
                { label: "critical", value: 3, color: attackColorVar("evil_twin") },
                { label: "high", value: 5, color: attackColorVar("deauth") },
                { label: "info", value: 9, color: attackColorVar("ssdp") },
              ]}
            />
            <DataCardNote>
              Figures withheld · this card is a layout specimen, not a reading
            </DataCardNote>
          </DataCard>
        </div>

        <Marquee
          className="mt-20"
          items={[
            "DETECT",
            "CLASSIFY",
            "REPORT",
            "802.11 MONITOR MODE",
            "LIGHTGBM · 8 CLASSES",
            "SAQR · صقر",
          ]}
        />
      </header>

      <main className="mx-auto flex w-full max-w-[1240px] min-w-0 flex-col gap-8 px-6 pb-24 sm:px-8">
        {/* ── The one thing to read first ─────────────────────────────── */}
        <Panel
          label="Read this first"
          className="border-[color-mix(in_oklch,var(--sev-critical)_30%,transparent)]"
        >
          <p className="text-ink-1 max-w-[68ch] text-sm">
            Every number, address and timestamp on this page is a placeholder chosen to
            exercise a layout. None of it came from the sensor, the database or the model.
            When a figure would imply a measurement that has not been taken, it is set as
            an em dash rather than filled in.
          </p>
        </Panel>

        {/* ── Foundations ─────────────────────────────────────────────── */}
        <Section
          id="foundations"
          label="foundations"
          title={
            <>
              Colour is <AccentWord>semantic</AccentWord>, never decorative.
            </>
          }
          body="Four paper steps, four ink steps, one accent taken off the Wi-Fi arcs in the mark, one amber companion used sparingly, one critical red. Dark is authored as its own warm-cool graphite, not flipped."
        >
          <Panel label="Paper" title="Surfaces" surface="sunken">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Swatch token="--color-paper-0" note="the page" className="bg-paper-0" ring />
              <Swatch token="--color-paper-1" note="card" className="bg-paper-1" ring />
              <Swatch token="--color-paper-2" note="elevated / hover" className="bg-paper-2" />
              <Swatch token="--color-paper-3" note="hairline as fill" className="bg-paper-3" />
            </div>
          </Panel>

          <Panel label="Ink" title="Type colours" surface="sunken">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Swatch token="--color-ink-0" note="primary · 17.8:1" className="bg-ink-0" />
              <Swatch token="--color-ink-1" note="body · 10.4:1" className="bg-ink-1" />
              <Swatch token="--color-ink-2" note="secondary · 5.8:1" className="bg-ink-2" />
              <Swatch
                token="--color-ink-3"
                note="mute · 3.7:1 — placeholders only, never prose"
                className="bg-ink-3"
              />
            </div>
          </Panel>

          <Panel label="Accent + semantics" title="The five that mean something" surface="sunken">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
              <Swatch token="--color-accent" note="identity azure · 3:1, large only" className="bg-accent" />
              <Swatch token="--color-accent-cta" note="text-safe azure · 5.8:1" className="bg-accent-cta" />
              <Swatch token="--color-navy" note="the hawk's head · CTA fill in light" className="bg-navy" />
              <Swatch token="--color-companion" note="amber · fills and dots" className="bg-companion" />
              <Swatch token="--color-companion-ink" note="amber, text-safe" className="bg-companion-ink" />
              <Swatch token="--color-critical" note="the one red" className="bg-critical" />
            </div>
            <p className="text-ink-2 mt-5 max-w-[68ch] text-sm">
              <span className="hs-num">--color-focus</span> is deliberately not the accent: a
              ring drawn in the same hue as the control it surrounds vanishes the moment that
              control is itself accent-filled. Tab through this page to see it.
            </p>
          </Panel>

          <Panel label="Threat classes" title="Nine identities, one ordinal ramp" surface="sunken">
            <div className="flex flex-col gap-3">
              {attackTypes.map((type) => (
                <div key={type} className="flex items-center gap-4">
                  <span
                    aria-hidden="true"
                    className="border-rule h-8 w-16 shrink-0 rounded-sm border"
                    style={{ background: attackColorVar(type) }}
                  />
                  <span className="text-ink-0 min-w-0 flex-1 truncate text-sm">
                    {attackLabels[type]}
                  </span>
                  <span className="hs-num text-ink-2 hidden text-xs sm:inline">
                    --cls-{type.replace(/_/g, "-")}
                  </span>
                  <StatusPill tone={severityOf(type)}>{severityOf(type)}</StatusPill>
                </div>
              ))}
            </div>
            <p className="text-ink-2 mt-5 max-w-[68ch] text-sm">
              Two anchors and a six-step azure-to-slate ramp. Lightness is banded so one
              value clears 3:1 on both papers — these are consumed as literal hex by
              recharts and cannot be theme-split.
            </p>
          </Panel>

          <PanelGrid className="sm:grid-cols-[repeat(2,minmax(0,1fr))]">
            <Panel label="Rules" title="Two weights, no third">
              <div className="flex flex-col gap-6">
                <div className="flex flex-col gap-2">
                  <span className="hs-label">--rule-hair · 8%</span>
                  <Hairline />
                </div>
                <div className="flex flex-col gap-2">
                  <span className="hs-label">--rule-soft · 14%</span>
                  <Hairline strong />
                </div>
                <Hairline label="labelled rule" />
              </div>
            </Panel>

            <Panel label="Radius + elevation" title="6 / 12 / 20 / 28 / pill">
              <div className="flex flex-wrap items-end gap-3">
                {(
                  [
                    ["rounded-sm", "6"],
                    ["rounded-md", "12"],
                    ["rounded-lg", "20"],
                    ["rounded-xl", "28"],
                    ["rounded-full", "pill"],
                  ] as const
                ).map(([cls, label]) => (
                  <div key={cls} className="flex flex-col items-center gap-2">
                    <span
                      aria-hidden="true"
                      className={cn("bg-paper-0 border-rule-soft hs-elev size-16 border", cls)}
                    />
                    <span className="hs-label">{label}</span>
                  </div>
                ))}
              </div>
              <p className="text-ink-2 mt-5 max-w-[68ch] text-sm">
                One card elevation and one floating elevation. In dark the card step resolves
                to nothing — a shadow on graphite is a smudge — and the hairline does the work.
              </p>
            </Panel>
          </PanelGrid>
        </Section>

        {/* ── Type ────────────────────────────────────────────────────── */}
        <Section
          id="type"
          label="type"
          title={
            <>
              Two families, <AccentWord>both scripts</AccentWord>.
            </>
          }
          body="Thmanyah Sans carries display and body in Latin and Arabic alike, which is what collapsed the previous four-family stack to two. IBM Plex Mono carries figures, MACs, SQL and timestamps — and nothing else, because it has no Arabic at all."
        >
          <Panel label="Scale" title="Every step, with its token" flush>
            <div className="flex flex-col">
              {TYPE_STEPS.map((step) => (
                <div
                  key={step.token}
                  className="border-rule flex flex-col gap-2 border-b px-4 py-5 last:border-b-0 sm:flex-row sm:items-baseline sm:gap-6"
                >
                  <span className="hs-num text-ink-2 w-40 shrink-0 text-xs">{step.token}</span>
                  <span
                    className={cn(
                      "font-display text-ink-0 min-w-0 flex-1 font-bold [overflow-wrap:anywhere]",
                      step.cls
                    )}
                  >
                    Every packet matters
                  </span>
                  <span className="hs-label shrink-0">{step.note}</span>
                </div>
              ))}
            </div>
          </Panel>

          <PanelGrid className="lg:grid-cols-[repeat(2,minmax(0,1fr))]">
            <Panel label="Weights" title="Thmanyah Sans">
              <div className="flex flex-col gap-3">
                {(
                  [
                    ["font-light", "300 Light"],
                    ["font-normal", "400 Regular"],
                    ["font-medium", "500 Medium"],
                    ["font-bold", "700 Bold"],
                    ["font-black", "900 Black — the accent word"],
                  ] as const
                ).map(([cls, label]) => (
                  <div key={cls} className="flex items-baseline justify-between gap-4">
                    <span className={cn("font-display text-ink-0 text-xl", cls)}>
                      HawkShield · صقر
                    </span>
                    <span className="hs-label shrink-0">{label}</span>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel label="Emphasis" title="No italics, anywhere">
              <p className="text-ink-1 max-w-[68ch] text-sm">
                The reference this system is cut from sets its emphasis word in an italic
                serif. We cannot: Thmanyah has no italic, Arabic script has no italics at
                all, and an italicised word inside an upright heading is one of the most
                reliable generated-looking tells there is. Weight and colour carry it
                instead — one primitive, used everywhere.
              </p>
              <p className="font-display text-ink-0 mt-6 text-2xl font-bold">
                It <AccentWord>detects</AccentWord>. It never blocks.
              </p>
              <p className="font-display text-ink-0 mt-3 text-2xl font-bold" lang="ar" dir="rtl">
                يكتشف ولا <AccentWord>يمنع</AccentWord>.
              </p>
            </Panel>
          </PanelGrid>

          <Panel label="Mono" title="Where the machine speaks">
            <div className="flex flex-col gap-3">
              <span className="hs-num text-ink-0 text-sm">A4:2B:B0:11:9C:3E</span>
              <span className="hs-num text-ink-0 text-sm">2026-08-28T14:02:11Z · ch 6 · −42 dBm</span>
              <span className="hs-ltr text-ink-0 font-mono text-sm">
                select class, count(*) from detections group by 1
              </span>
              <span className="hs-label">uppercase mono eyebrow · 11px · 0.1em</span>
            </div>
            <p className="text-ink-2 mt-5 max-w-[68ch] text-sm">
              Figures are pinned LTR. Inside an Arabic paragraph a string opening with a
              neutral character takes the paragraph direction, and{" "}
              <span className="hs-num">−42 dBm</span> renders backwards. The DOM would be
              right and the screen wrong.
            </p>
          </Panel>
        </Section>

        {/* ── Primitives ──────────────────────────────────────────────── */}
        <Section
          id="primitives"
          label="primitives"
          title={
            <>
              Every state, <AccentWord>in code</AccentWord>.
            </>
          }
          body="Default, hover, focus-visible, active, disabled, loading, error, empty. A component that only ever renders its happy path is the reason a dashboard shows a blank rectangle the first time the API is slow."
        >
          <Panel label="Buttons" title="Pills, in seven variants">
            <div className="flex flex-col gap-6">
              <Row caption="Variants">
                <Button>Default · CTA</Button>
                <Button variant="accent">Accent</Button>
                <Button variant="outline">Outline</Button>
                <Button variant="secondary">Secondary</Button>
                <Button variant="ghost">Ghost</Button>
                <Button variant="destructive">Destructive</Button>
                <Button variant="link">Link</Button>
              </Row>
              <Row caption="Sizes">
                <Button size="sm">Small</Button>
                <Button>Default</Button>
                <Button size="lg">Large</Button>
                <Button size="icon" aria-label="Refresh">
                  <RefreshCw aria-hidden />
                </Button>
              </Row>
              <Row caption="States — hover and focus are live; tab into them">
                <Button disabled>Disabled</Button>
                <Button aria-busy="true">Loading</Button>
                <Button aria-invalid="true" variant="outline">
                  Error
                </Button>
              </Row>
            </div>
          </Panel>

          <PanelGrid className="lg:grid-cols-[repeat(2,minmax(0,1fr))]">
            <Panel label="Eyebrows + pills" title="The mono micro-label">
              <div className="flex flex-col gap-6">
                <Row caption="Eyebrow">
                  <Eyebrow>bare</Eyebrow>
                  <Eyebrow variant="pill">pill</Eyebrow>
                  <Eyebrow variant="pill" tone="accent" live>
                    live
                  </Eyebrow>
                </Row>
                <Row caption="Status pill · quiet">
                  <StatusPill tone="critical">critical</StatusPill>
                  <StatusPill tone="high">high</StatusPill>
                  <StatusPill tone="info">info</StatusPill>
                  <StatusPill tone="neutral">neutral</StatusPill>
                </Row>
                <Row caption="Status pill · solid">
                  <StatusPill tone="critical" variant="solid">
                    critical
                  </StatusPill>
                  <StatusPill tone="high" variant="solid">
                    high
                  </StatusPill>
                  <StatusPill tone="info" variant="solid" dot>
                    info
                  </StatusPill>
                </Row>
                <Row caption="Badge — names a thing, does not grade it">
                  <Badge>wlan1mon</Badge>
                  <Badge variant="secondary">lightgbm</Badge>
                  <Badge variant="outline">ch 6</Badge>
                  <Badge variant="destructive">quarantined</Badge>
                </Row>
                <Row caption="Radar — the listening indicator">
                  <span className="flex items-center gap-2">
                    <Radar label="Sensor listening" active={live} />
                    <span className="text-ink-1 text-sm">
                      {live ? "listening" : "stopped"}
                    </span>
                  </span>
                  <Button size="sm" variant="outline" onClick={() => setLive((v) => !v)}>
                    Toggle
                  </Button>
                </Row>
              </div>
            </Panel>

            <Panel label="Fields" title="Paper slips on the card">
              <div className="flex flex-col gap-5">
                <Input placeholder="Filter by BSSID" aria-label="Filter by BSSID" />
                <Input defaultValue="A4:2B:B0:11:9C:3E" aria-label="BSSID" className="hs-num" />
                <Input
                  aria-invalid="true"
                  defaultValue="not-a-mac"
                  aria-label="Invalid BSSID"
                />
                <Input disabled placeholder="Disabled" aria-label="Disabled field" />
                <Select defaultValue="all">
                  <SelectTrigger aria-label="Class filter">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All classes</SelectItem>
                    {attackTypes.map((t) => (
                      <SelectItem key={t} value={t}>
                        {attackLabels[t]}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <label className="text-ink-1 flex items-center gap-3 text-sm">
                  <Checkbox
                    checked={checked}
                    onCheckedChange={(v) => setChecked(v === true)}
                  />
                  Only show critical
                </label>
              </div>
            </Panel>
          </PanelGrid>

          <Panel
            label="Table"
            title="Detections · placeholder rows"
            actions={
              <>
                <Button size="sm" variant="ghost" aria-label="Filter">
                  <Filter aria-hidden />
                </Button>
                <Button size="sm" variant="ghost" aria-label="Export">
                  <Download aria-hidden />
                </Button>
              </>
            }
            flush
          >
            <DataTable
              columns={columns}
              rows={SAMPLE_ROWS}
              rowKey={(r) => `${r.time}-${r.bssid}`}
              sort={sort}
              onSortChange={setSort}
              emptyLabel="No detections in this window"
              isArriving={(_, i) => i === 0}
              tintOf={(r) => attackColorVar(r.cls)}
            />
          </Panel>

          <PanelGrid className="lg:grid-cols-[repeat(3,minmax(0,1fr))]">
            <Panel label="Table · loading" flush>
              <DataTable
                columns={columns.slice(0, 3)}
                rows={[]}
                rowKey={() => "x"}
                state="loading"
                emptyLabel="—"
                loadingLabel="Reading"
              />
            </Panel>
            <Panel label="Table · empty" flush>
              <DataTable
                columns={columns.slice(0, 3)}
                rows={[]}
                rowKey={() => "x"}
                emptyLabel="No detections in this window"
              />
            </Panel>
            <Panel label="Table · error" flush>
              <DataTable
                columns={columns.slice(0, 3)}
                rows={[]}
                rowKey={() => "x"}
                state="error"
                emptyLabel="—"
                errorLabel="Sensor unreachable"
              />
            </Panel>
          </PanelGrid>

          <PanelGrid className="sm:grid-cols-[repeat(2,minmax(0,1fr))] lg:grid-cols-[repeat(4,minmax(0,1fr))]">
            <Panel label="Metric">
              <Metric
                label="Frames / sec"
                value={1240}
                animate={false}
                footer={<Sparkline values={SAMPLE_SPARK} area label="Placeholder trend" />}
              />
            </Panel>
            <Panel label="Metric · delta">
              <Metric label="Detections" value={87} delta={12} deltaLabel="vs. last hour" animate={false} />
            </Panel>
            <Panel label="Metric · critical">
              <Metric label="Evil Twin" value={3} tone="critical" animate={false} />
            </Panel>
            <Panel label="Metric · withheld">
              <Metric
                label="Model precision"
                value={0}
                format={() => "—"}
                animate={false}
                footer={<span className="hs-label">measurement pending</span>}
              />
            </Panel>
          </PanelGrid>

          <PanelGrid className="lg:grid-cols-[repeat(2,minmax(0,1fr))]">
            <Panel label="Trace" title="Saqr tool calls · placeholder transcript">
              <div className="flex flex-col gap-1.5">
                <TerminalLine stamp="14:02:11" tone="muted">
                  question received
                </TerminalLine>
                <TerminalLine stamp="14:02:11" tone="accent" depth={1}>
                  query_detections(window=&quot;15m&quot;)
                </TerminalLine>
                <TerminalLine stamp="14:02:12" depth={1}>
                  returned 5 rows
                </TerminalLine>
                <TerminalLine stamp="14:02:12" tone="critical" depth={1}>
                  1 row graded critical
                </TerminalLine>
                <TerminalLine pending depth={0} tone="muted">
                  composing answer
                </TerminalLine>
              </div>
            </Panel>

            <Panel label="Overlays" title="Portals resolve against the page theme">
              <div className="flex flex-wrap gap-3">
                <Dialog>
                  <DialogTrigger asChild>
                    <Button variant="outline">Dialog</Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Export this window</DialogTitle>
                      <DialogDescription>
                        Writes every row currently in view. Nothing is sent anywhere.
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
                    <Button variant="outline">Sheet</Button>
                  </SheetTrigger>
                  <SheetContent side={locale === "ar" ? "left" : "right"}>
                    <SheetHeader>
                      <SheetTitle>Detection detail</SheetTitle>
                      <SheetDescription>
                        The drawer enters from the inline-end edge in both directions.
                      </SheetDescription>
                    </SheetHeader>
                  </SheetContent>
                </Sheet>

                <Popover>
                  <PopoverTrigger asChild>
                    <Button variant="outline">Popover</Button>
                  </PopoverTrigger>
                  <PopoverContent>
                    <p className="text-ink-1 text-sm">
                      Same paper, same hairline, one elevation step up.
                    </p>
                  </PopoverContent>
                </Popover>
              </div>

              <p className="text-ink-2 mt-6 max-w-[68ch] text-sm">
                Radix portals mount on <span className="hs-num">document.body</span>, so they
                follow the class on <span className="hs-num">&lt;html&gt;</span>. The controls
                in the nav pill drive the real theme provider, which is why they resolve
                correctly here.
              </p>
            </Panel>
          </PanelGrid>

          <Panel label="Motion" title="Four loops, all of them load-bearing">
            <ul className="text-ink-1 flex max-w-[68ch] flex-col gap-3 text-sm">
              <li className="flex flex-wrap items-center gap-3">
                <StatusPill tone="info" live>
                  live dot
                </StatusPill>
                <span>answers &ldquo;is the sensor still listening?&rdquo; — nothing else.</span>
              </li>
              <li className="flex flex-wrap items-center gap-3">
                <Eyebrow variant="pill">arrival wash</Eyebrow>
                <span>a new row tints itself with its class colour, then decays. No toast.</span>
              </li>
              <li className="flex flex-wrap items-center gap-3">
                <Eyebrow variant="pill">scan</Eyebrow>
                <span>replaces the spinner: a line down the panel that is filling in.</span>
              </li>
              <li className="flex flex-wrap items-center gap-3">
                <Eyebrow variant="pill">marquee</Eyebrow>
                <span>one strip, hero only, removed from the accessibility tree.</span>
              </li>
            </ul>
            <p className="text-ink-2 mt-6 max-w-[68ch] text-sm">
              Under <span className="hs-num">prefers-reduced-motion: reduce</span> every one
              of them stops and resolves to a complete still frame. That is the test a motion
              has to pass to be allowed here at all.
            </p>
          </Panel>
        </Section>

        {/* ── Arabic ──────────────────────────────────────────────────── */}
        <Section
          id="arabic"
          label="العربية"
          title={
            <>
              Arabic is a <AccentWord>first-class page</AccentWord>.
            </>
          }
          body="Not a translation layer over Latin metrics. Thmanyah covers both scripts, so an Arabic page is set in the same face at the same weights — and the mono eyebrow swaps family and drops its tracking, because tracking shatters the joins of a cursive script."
        >
          <div lang="ar" dir="rtl" className="flex min-w-0 flex-col gap-4">
            <Panel label="لوحة" title="نموذج تخطيط · قيم غير حقيقية">
              <p className="text-ink-1 text-base">
                يراقب HawkShield إطارات 802.11 من حسّاس Raspberry Pi، ويصنّف ما يرصده إلى
                ثمانية أنواع من الهجمات، ثم يبلّغ عنها. لا يحجب ولا يمنع، ولا يزعم أبدًا أن
                الشبكة نظيفة.
              </p>
              <div className="mt-6 flex flex-wrap items-center gap-3">
                <StatusPill tone="critical">حرِج</StatusPill>
                <StatusPill tone="high">مرتفع</StatusPill>
                <StatusPill tone="info">معلومة</StatusPill>
                <Eyebrow variant="pill" tone="accent" live>
                  مباشر
                </Eyebrow>
              </div>
              <div className="mt-6 flex flex-wrap items-center gap-3">
                <Button>إجراء رئيسي</Button>
                <Button variant="outline">ثانوي</Button>
              </div>
              <p className="text-ink-2 mt-6 max-w-[68ch] text-sm">
                العنوان الفيزيائي <span className="hs-num">A4:2B:B0:11:9C:3E</span> وقوة
                الإشارة <span className="hs-num">−42 dBm</span> — كلاهما مثبّت باتجاه
                يسار-يمين داخل فقرة عربية.
              </p>
            </Panel>

            <DataCard
              label="wlan1mon"
              title="نافذة الالتقاط · قيم نموذجية"
              status={<StatusPill tone="info">نموذج</StatusPill>}
            >
              <DataCardRows>
                <DataCardRow label="الإطارات المرصودة" value="—" />
                <DataCardRow label="المصنّفة" value="—" />
                <DataCardRow label="التوأم الخبيث" value="—" tone="critical" />
              </DataCardRows>
              <DataCardTotal label="إجمالي النافذة" value="—" unit="حدث" />
              <DataCardNote>القيم محجوبة · هذه بطاقة تخطيط لا قراءة</DataCardNote>
            </DataCard>
          </div>
        </Section>

        {/* ── Theme proof ─────────────────────────────────────────────── */}
        <Section
          id="themes"
          label="themes"
          title={
            <>
              Dark is <AccentWord>authored</AccentWord>, not flipped.
            </>
          }
          body="A token inversion of a paper design looks broken: the shadows go the wrong way and the hairlines turn to smoke. Dark re-derives every value by lift. Both are shown here at once by locally theming a subtree."
        >
          <PanelGrid className="lg:grid-cols-[repeat(2,minmax(0,1fr))]">
            {/* The whole theme lives in custom properties, so putting `.dark`
                on any element re-themes that subtree — which is exactly how
                both themes can appear on one screen. */}
            <div className="bg-paper-0 border-rule-soft min-w-0 rounded-xl border p-5">
              <Eyebrow className="mb-4">current theme · {dark ? "dark" : "light"}</Eyebrow>
              <ThemeSpecimen />
            </div>
            <div
              className={cn(
                dark ? "" : "dark",
                "bg-paper-0 border-rule-soft min-w-0 rounded-xl border p-5"
              )}
            >
              <Eyebrow className="mb-4">the other one · {dark ? "light" : "dark"}</Eyebrow>
              <ThemeSpecimen />
            </div>
          </PanelGrid>

          <Panel label="Switches" title="Both drive the real providers">
            <div className="flex flex-wrap items-center gap-3">
              <Button variant={dark ? "outline" : "default"} onClick={() => setTheme("light")}>
                Light
              </Button>
              <Button variant={dark ? "default" : "outline"} onClick={() => setTheme("dark")}>
                Dark
              </Button>
              <Button variant="ghost" onClick={() => setTheme("system")}>
                Follow system
              </Button>
              <span className="border-rule-soft mx-2 h-8 border-e" aria-hidden="true" />
              <Button
                variant={locale === "en" ? "default" : "outline"}
                onClick={() => setLocale("en")}
              >
                English
              </Button>
              <Button
                variant={locale === "ar" ? "default" : "outline"}
                onClick={() => setLocale("ar")}
                lang="ar"
              >
                العربية
              </Button>
            </div>
          </Panel>
        </Section>
      </main>

      {/* ── Ft5 · Statement ────────────────────────────────────────────── */}
      <div className="mx-auto w-full max-w-[1240px] px-6 sm:px-8">
        <StatementFooter
          statement={
            <>
              It watches, it <AccentWord>names</AccentWord> what it saw, and it stops there.
            </>
          }
          brand={
            <>
              <Logo size={24} decorative />
              <Wordmark size="sm" split />
            </>
          }
          linksLabel="Style sheet sections"
          links={
            <>
              <a href="#foundations" className="text-ink-1 hover:text-ink-0 transition-colors">
                Colour
              </a>
              <a href="#type" className="text-ink-1 hover:text-ink-0 transition-colors">
                Type
              </a>
              <a href="#primitives" className="text-ink-1 hover:text-ink-0 transition-colors">
                Primitives
              </a>
              <a href="#arabic" className="text-ink-1 hover:text-ink-0 transition-colors" lang="ar">
                العربية
              </a>
            </>
          }
          meta="Falcon Paper · dev surface · no sensor data on this page"
        />
      </div>
    </div>
  )
}

/**
 * A small cross-section of the system, rendered twice — once in the page theme
 * and once in the other one — so both can be judged side by side.
 */
function ThemeSpecimen() {
  return (
    <div className="flex flex-col gap-5">
      <p className="font-display text-ink-0 text-xl font-bold">
        Detected, <AccentWord>classified</AccentWord>, reported.
      </p>
      <p className="text-ink-1 text-sm">
        Body copy at <span className="hs-num">--color-ink-1</span>, secondary at{" "}
        <span className="text-ink-2">--color-ink-2</span>.
      </p>
      <div className="flex flex-wrap gap-2">
        <StatusPill tone="critical">critical</StatusPill>
        <StatusPill tone="high">high</StatusPill>
        <StatusPill tone="info">info</StatusPill>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button size="sm">CTA</Button>
        <Button size="sm" variant="outline">
          Outline
        </Button>
      </div>
      <div className="bg-paper-1 border-rule-soft hs-elev rounded-lg border p-4">
        <span className="hs-label">panel on paper-1</span>
        <p className="text-ink-1 mt-2 text-sm">One hairline, one elevation step.</p>
      </div>
      <Hairline label="rule" />
    </div>
  )
}
