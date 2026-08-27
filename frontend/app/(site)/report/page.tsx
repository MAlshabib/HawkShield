"use client"

/**
 * The detection report, as a document.
 *
 * WHY THIS EXISTS RATHER THAN A BETTER SERVER PDF
 *
 * `POST /reports/export` renders with ReportLab, and ReportLab cannot be made
 * to produce this page. The brand face ships as `thmanyahsans-*.otf` with
 * PostScript/CFF outlines, which `TTFont` rejects outright
 * (`TTFError: postscript outlines are not supported`), and woff2 is not a
 * format it recognises at all. The Pi carries DejaVu and Noto Sans Mono and no
 * Arabic TTF whatsoever. On top of that ReportLab performs neither Arabic
 * shaping nor the bidi algorithm, so an Arabic page would additionally need
 * `arabic-reshaper` and `python-bidi` — two dependencies, to arrive at a
 * document still set in the wrong face.
 *
 * The browser already has every one of those things: the real fonts, correct
 * shaping, a conforming bidi implementation, and the whole Falcon Paper token
 * system. "Save as PDF" is native. So the good report is a print view, and the
 * server PDF stays what it always was — the headless fallback.
 *
 * It lives in the `(site)` group deliberately: a report is a document, not an
 * application screen, and the app navbar has no business on a printed page.
 * The window comes off the query string (`?days=30`) so the page can be opened
 * cold, bookmarked, and re-printed without going through the dialog again.
 */
import * as React from "react"
import Link from "next/link"
import { ArrowLeft, Printer } from "lucide-react"

import { Logo, Wordmark } from "@/components/brand/logo"
import { AccentWord } from "@/components/hs/accent-word"
import { Eyebrow } from "@/components/hs/eyebrow"
import { Panel } from "@/components/hs/panel"
import { StatusPill } from "@/components/hs/status-pill"
import { Quantity } from "@/components/quantity"
import { Button } from "@/components/ui/button"
import type { HealthPayload } from "@/hooks/use-health"
import { apiFetchJson } from "@/lib/api"
import { attackColorVar, attackTypes, attackLabels, severityOf, type AttackType } from "@/lib/colors"
import { apiTimeMs, freqToChannel, toAttackType } from "@/lib/detections"
import { Ltr, Mac, toISO, useFormatters, type DateLike } from "@/lib/format"
import { useT, type TranslationKey } from "@/lib/i18n"
import { cn } from "@/lib/utils"

/* -------------------------------------------------------------------------- */
/* Wire shapes                                                                */
/* -------------------------------------------------------------------------- */

type SummaryPayload = {
  period?: string | null
  totals?: Record<string, unknown> | null
  summary?: {
    totalAttacks?: unknown
    mostFrequentType?: unknown
    peakHour?: unknown
    uniqueSources?: unknown
  } | null
}

type OffenderRow = { wlan_sa?: string | null; count?: unknown }
type ChannelRow = { channel_freq?: unknown; count?: unknown }
type CountPayload = { count?: unknown }
type AnalysisPayload = Record<string, unknown>

/**
 * One endpoint's outcome. `failed` is not `data === null`: an endpoint that
 * answered with an empty list told us something true, and an endpoint that did
 * not answer told us nothing. The two must not render the same way — printing a
 * zero for a question nobody answered is the single failure this report exists
 * to avoid.
 */
type Source<T> = { data: T | null; failed: boolean }

const PENDING: Source<never> = { data: null, failed: false }

async function read<T>(path: string): Promise<Source<T>> {
  try {
    return { data: await apiFetchJson<T>(path, { cache: "no-store" }), failed: false }
  } catch {
    return { data: null, failed: true }
  }
}

/**
 * `Number(null)` is `0`, and `Number("")` is `0` — neither is NaN, so a bare
 * cast turns "the sensor said nothing" into "the sensor said none". Null-ish
 * input is rejected before the cast, and anything that is not a finite number
 * afterwards comes back as `null` for the caller to render as an em dash.
 */
function count(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null
  const n = Number(value)
  return Number.isFinite(n) ? n : null
}

/* -------------------------------------------------------------------------- */
/* Window                                                                     */
/* -------------------------------------------------------------------------- */

/** Matches `MAX_DAYS` in `backend/app/routers/reports.py`. */
const MAX_DAYS = 3650
const DEFAULT_DAYS = 30
const TOP_LIMIT = 10

const WINDOW_KEY: Record<number, TranslationKey> = {
  1: "time.range.hours24",
  7: "time.range.days7",
  30: "time.range.days30",
}

/** `?days=N`, clamped to what the API will accept. Anything else is ignored. */
function daysFromQuery(): number {
  try {
    const raw = new URLSearchParams(window.location.search).get("days")
    const n = count(raw)
    if (n === null) return DEFAULT_DAYS
    return Math.min(MAX_DAYS, Math.max(1, Math.round(n)))
  } catch {
    return DEFAULT_DAYS
  }
}

/* -------------------------------------------------------------------------- */
/* Print stylesheet                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Scoped to this route rather than added to `globals.css`, because it is the
 * only page in the product that has a printed form.
 *
 * The three things it has to get right:
 *
 * 1. **A4, with real margins.** `@page` is the only place a browser will accept
 *    a paper size. The page-number rule is kept in a *separate* `@page` block:
 *    Chrome does not implement margin at-rules, and a parser that discards the
 *    unknown `@bottom-center` must not be able to take `size` and `margin` with
 *    it. Where the engine does support it (Prince, Paged.js, and eventually
 *    Chrome) the numbering appears; where it does not, Chrome's own print
 *    footer still offers it.
 * 2. **Light paper, always.** The screen honours the operator's theme; paper
 *    does not get a vote. A dark-paper PDF is a solid block of toner that reads
 *    badly and photocopies worse. `:root.dark` — specificity (0,2,0) — outranks
 *    the `.dark` class the theme provider puts on `<html>`, so every token is
 *    pulled back to its authored light value for print and nothing else in the
 *    system has to know.
 * 3. **The accents survive.** Browsers drop backgrounds and fills when printing
 *    unless `print-color-adjust: exact` says otherwise, which would take the
 *    class ramp, the severity pills and every share bar with it — the parts
 *    that carry meaning rather than decoration.
 */
const PRINT_CSS = `
@page { size: A4; margin: 16mm 15mm 18mm; }

@page {
  @bottom-center {
    content: counter(page) " / " counter(pages);
    font-family: "IBM Plex Mono", ui-monospace, monospace;
    font-size: 8pt;
    color: var(--color-ink-2);
  }
}

@media print {
  /* ── 1 · the light palette, forced ─────────────────────────────────── */
  :root.dark {
    --color-paper-0: oklch(98.6% 0.004 250);
    --color-paper-1: oklch(96.4% 0.008 250);
    --color-paper-2: oklch(93.4% 0.012 250);
    --color-paper-3: oklch(89.5% 0.016 250);
    --color-ink-0: oklch(19% 0.03 258);
    --color-ink-1: oklch(36% 0.026 258);
    --color-ink-2: oklch(50% 0.022 258);
    --color-ink-3: oklch(60.5% 0.017 258);
    --color-accent: oklch(60% 0.15 250);
    --color-accent-cta: oklch(50% 0.148 252);
    --color-accent-soft: oklch(74% 0.1 250);
    --color-accent-tint: oklch(94.5% 0.022 250);
    --color-companion: oklch(78% 0.15 70);
    --color-companion-ink: oklch(55% 0.113 62);
    --color-critical: oklch(58% 0.2 25);
    --color-focus: oklch(42% 0.19 262);
    --color-cta: var(--color-navy);
    --color-cta-ink: var(--color-paper-0);
    --color-cta-hover: var(--color-accent-cta);
    --color-on-accent: var(--color-paper-0);
    --color-on-companion: var(--color-ink-0);
    --color-on-critical: var(--color-paper-0);
    --color-rule: color-mix(in oklch, var(--color-ink-0) 8%, transparent);
    --color-rule-soft: color-mix(in oklch, var(--color-ink-0) 14%, transparent);
    --color-shadow: var(--color-navy);
    --hs-azure: var(--color-accent-cta);
    --surface-sunken: var(--color-paper-1);
    --sev-high: var(--color-companion-ink);
    --sev-info: var(--color-accent-cta);
    --on-critical: var(--color-paper-0);
    --on-high: var(--color-paper-0);
    --on-info: var(--color-paper-0);
    --on-neutral: var(--color-paper-0);
    --primary: var(--color-accent-cta);
    --primary-foreground: var(--color-paper-0);
    --destructive-foreground: var(--color-paper-0);
    --sidebar-primary-foreground: var(--color-paper-0);
    color-scheme: light;
  }

  /* ── 2 · keep the fills, drop the lift ─────────────────────────────── */
  .hs-report,
  .hs-report *,
  .hs-report *::before,
  .hs-report *::after {
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
    box-shadow: none !important;
    text-shadow: none !important;
  }

  html,
  body {
    background: var(--color-paper-0) !important;
    color: var(--color-ink-0);
  }

  body {
    /* Print reads in points. 10pt body, which is a report, not a UI. */
    font-size: 10pt;
    line-height: 1.45;
  }

  /* ── 3 · what paper does not carry ─────────────────────────────────── */
  .hs-no-print { display: none !important; }

  /* ── 4 · the sheet fills the page box; @page owns the margin ───────── */
  .hs-sheet {
    max-inline-size: none !important;
    margin: 0 !important;
    padding-inline: 0 !important;
    padding-block: 0 !important;
  }

  /* The mark ships as two rasters — the dark one is selected by the .dark
     class rather than by a token, so forcing the light palette does not move
     it, and the dark artwork's near-white head would vanish on paper. Paper
     always gets the light copy, which is the first of the two. */
  .hs-report [data-slot="logo"] img { display: none !important; }
  .hs-report [data-slot="logo"] img:first-of-type { display: block !important; }

  /* A card sits on the page rather than floating above it. */
  .hs-report [data-slot="panel"] {
    border-radius: 0;
    border-inline: 0;
    border-block-start: 0;
  }

  /* ── 5 · pagination ────────────────────────────────────────────────── */
  .hs-report h1,
  .hs-report h2,
  .hs-report h3,
  .hs-report h4,
  .hs-report [data-slot="panel-header"] {
    break-after: avoid;
    page-break-after: avoid;
  }

  /* Cards are atomic. A metric tile or a note split across a fold reads as a
     printing fault rather than as a page turn. */
  .hs-report [data-slot="panel"],
  .hs-report [data-print="keep"] {
    break-inside: avoid;
    page-break-inside: avoid;
  }

  /* Except the three tables, which are allowed to run on. A table that cannot
     break pushes itself whole onto the next sheet and leaves the rest of the
     current one blank -- measured at four pages that way against three this
     way, for the same content. Their heads repeat, which is what makes the
     continuation readable. */
  .hs-report [data-print="flow"],
  .hs-report [data-print="flow"] [data-slot="panel-body"] {
    break-inside: auto;
    page-break-inside: auto;
  }

  /* A head repeats on every page its table reaches, which is what makes the
     continuation readable. A FOOT deliberately does not: table-footer-group
     would repeat the "Total" row at the bottom of every fragment, under six of
     nine rows, where it reads as the total OF those six. A wrong figure set in
     the right place is worse than no figure. */
  .hs-report thead { display: table-header-group; }

  .hs-report tr,
  .hs-report li {
    break-inside: avoid;
    page-break-inside: avoid;
  }

  .hs-report p {
    orphans: 3;
    widows: 3;
  }

  /* Nothing scrolls on paper. */
  .hs-report [data-print="scroller"] {
    overflow: visible !important;
  }

  /* Pinned rather than left to a breakpoint. A print box resolves media
     queries against the page width, so the four-up glance row would silently
     become two-up or stay four-up depending on the paper -- and at four-up on
     A4 every label wraps to two lines and the figures stop sharing a baseline.
     Two-by-two is roomy at 180mm and it is the same on every sheet size. */
  .hs-report [data-print="glance"] {
    grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
  }

  /* ── 6 · the closing line ──────────────────────────────────────────── */
  /* It prints, and it prints once, at the end.
   *
   * A position: fixed running footer was built first and then measured out
   * of the design. Chrome does repeat a fixed box on every sheet -- the
   * print-to-PDF content stream for this page carries the same
   * 0 0 680 32 re fill on all three -- but it anchors it INSIDE the page
   * area, not in the @page margin, and CSS gives no way to shorten the flow to
   * reserve that band. On the first page the class table runs to the fold, so
   * the "running" footer landed on top of its last row. Page furniture that
   * eats a row of data is not furniture, it is damage.
   *
   * Page numbers therefore come from the @bottom-center margin box above on
   * engines that implement it, and from the browser's own print footer
   * everywhere else. */
  .hs-report [data-print="closing"] {
    display: flex !important;
    break-inside: avoid;
    page-break-inside: avoid;
    margin-block-start: 8mm;
  }
}
`

/* -------------------------------------------------------------------------- */
/* Page                                                                       */
/* -------------------------------------------------------------------------- */

const EMPTY = "—"

export default function ReportPage() {
  const t = useT()
  const f = useFormatters()

  // `null` until the URL has been read on the client. A lazy initialiser would
  // touch `window` during the static export's build-time render, and seeding it
  // with the default would fire one throwaway request for the wrong window.
  const [days, setDays] = React.useState<number | null>(null)
  const [compiledAt, setCompiledAt] = React.useState<number | null>(null)

  const [summary, setSummary] = React.useState<Source<SummaryPayload>>(PENDING)
  const [analysis, setAnalysis] = React.useState<Source<AnalysisPayload>>(PENDING)
  const [offenders, setOffenders] = React.useState<Source<OffenderRow[]>>(PENDING)
  const [channels, setChannels] = React.useState<Source<ChannelRow[]>>(PENDING)
  const [stored, setStored] = React.useState<Source<CountPayload>>(PENDING)
  const [health, setHealth] = React.useState<Source<HealthPayload>>(PENDING)

  React.useEffect(() => {
    setDays(daysFromQuery())
  }, [])

  React.useEffect(() => {
    if (days === null) return
    let alive = true

    void (async () => {
      const [s, a, o, c, p, h] = await Promise.all([
        read<SummaryPayload>(`/reports/summary?days=${days}`),
        read<AnalysisPayload>("/attacks/analysis"),
        read<OffenderRow[]>(`/top-offenders?days=${days}&limit=${TOP_LIMIT}`),
        read<ChannelRow[]>(`/channel-usage?days=${days}`),
        read<CountPayload>("/packets/count"),
        read<HealthPayload>("/health"),
      ])
      if (!alive) return
      setSummary(s)
      setAnalysis(a)
      setOffenders(o)
      setChannels(c)
      setStored(p)
      setHealth(h)
      // The document is a snapshot: one instant for the whole page, stamped
      // when the reads settled rather than when React happened to render.
      setCompiledAt(Date.now())
    })()

    return () => {
      alive = false
    }
  }, [days])

  /* ── derived ────────────────────────────────────────────────────────── */

  const head = summary.data?.summary ?? null
  const totalDetections = count(head?.totalAttacks)
  const uniqueSources = count(head?.uniqueSources)
  const peakHour = count(head?.peakHour)
  const mostFrequent = head?.mostFrequentType ? toAttackType(String(head.mostFrequentType)) : null
  const storedAllTime = count(stored.data?.count)

  const allTime = React.useMemo(() => {
    const rows = analysis.data
    if (!rows) return null
    const out = new Map<AttackType, number>()
    for (const [label, value] of Object.entries(rows)) {
      const n = count(value)
      if (n === null) continue
      const type = toAttackType(label)
      out.set(type, (out.get(type) ?? 0) + n)
    }
    return out
  }, [analysis.data])

  const classRows = React.useMemo(() => {
    const totals = summary.data?.totals
    if (!totals) return []
    return attackTypes
      .map((type) => ({ type, value: count(totals[type]) }))
      .filter((row): row is { type: AttackType; value: number } => row.value !== null && row.value > 0)
      .sort((a, b) => b.value - a.value)
  }, [summary.data])

  const classTotal = classRows.reduce((sum, row) => sum + row.value, 0)

  const sourceRows = React.useMemo(() => {
    const rows = offenders.data
    if (!rows) return []
    return rows
      .map((row) => ({ mac: row.wlan_sa ?? null, value: count(row.count) }))
      .filter((row): row is { mac: string; value: number } => Boolean(row.mac) && row.value !== null)
  }, [offenders.data])

  const sourceTotal = sourceRows.reduce((sum, row) => sum + row.value, 0)

  const channelRows = React.useMemo(() => {
    const rows = channels.data
    if (!rows) return []
    return rows
      .map((row) => ({ freq: count(row.channel_freq), value: count(row.count) }))
      .filter((row): row is { freq: number; value: number } => row.freq !== null && row.value !== null)
  }, [channels.data])

  const channelTotal = channelRows.reduce((sum, row) => sum + row.value, 0)

  const capture = health.data?.capture ?? null
  const configOnly = capture?.source === "config"
  const latestPacketMs = apiTimeMs(health.data?.latest_packet_ts ?? null)

  const windowLabel =
    days === null
      ? EMPTY
      : WINDOW_KEY[days]
        ? t(WINDOW_KEY[days])
        : t("report.doc.windowDays", { n: f.number(days) })

  const settled = compiledAt !== null
  // Every read failed: say so once, at the top, instead of six times down the
  // page. A sensor that is not answering is one fact, not six.
  const allFailed =
    settled &&
    summary.failed &&
    analysis.failed &&
    offenders.failed &&
    channels.failed &&
    stored.failed &&
    health.failed

  /* ── render ─────────────────────────────────────────────────────────── */

  return (
    <div className="hs-report min-w-0">
      {/* The only raw CSS in the product, and it is here rather than in
          globals.css because this is the only route with a printed form. */}
      <style dangerouslySetInnerHTML={{ __html: PRINT_CSS }} />

      {/* ── Toolbar · screen only ────────────────────────────────────── */}
      <div className="hs-no-print border-rule-soft bg-paper-0/85 sticky top-0 z-10 border-b backdrop-blur">
        <div className="mx-auto flex w-full max-w-[920px] flex-wrap items-center gap-3 px-6 py-3 sm:px-8">
          <Link
            href="/threats"
            className="text-ink-1 hover:text-ink-0 inline-flex items-center gap-2 text-sm transition-colors"
          >
            {/* The glyph points along the reading axis, so it mirrors with it. */}
            <ArrowLeft className="size-4 rtl:-scale-x-100" aria-hidden="true" />
            {t("report.doc.back")}
          </Link>

          <Button className="ms-auto" onClick={() => window.print()}>
            <Printer aria-hidden="true" />
            {t("report.doc.print")}
          </Button>
        </div>
      </div>

      {/* ── The document ─────────────────────────────────────────────── */}
      <article className="hs-sheet mx-auto flex w-full max-w-[920px] min-w-0 flex-col gap-6 px-6 pt-10 pb-16 sm:px-8">
        {/* ── Masthead ───────────────────────────────────────────────── */}
        <header data-print="keep" className="flex flex-col gap-5">
          <div className="flex flex-wrap items-start gap-x-6 gap-y-4">
            <div className="flex items-center gap-3">
              <Logo size={38} decorative />
              <Wordmark size="md" split />
            </div>

            <dl className="ms-auto grid gap-x-6 gap-y-1.5 text-sm sm:grid-cols-[auto_auto]">
              <MetaPair label={t("report.doc.window")}>{windowLabel}</MetaPair>
              <MetaPair label={t("report.doc.generated")}>
                {compiledAt === null ? (
                  <span className="text-ink-2">{EMPTY}</span>
                ) : (
                  <Stamp value={compiledAt} className="text-xs" />
                )}
              </MetaPair>
            </dl>
          </div>

          <div className="bg-rule-soft h-px w-full" role="separator" />

          <div className="flex flex-col gap-4">
            <Eyebrow>{t("report.doc.eyebrow")}</Eyebrow>
            <h1 className="font-display text-ink-0 text-3xl max-w-[20ch] min-w-0 font-bold [overflow-wrap:anywhere] [text-wrap:balance]">
              {t("report.doc.headLead")}
              <AccentWord>{t("report.doc.headAccent")}</AccentWord>
              {t("report.doc.headTail")}
            </h1>
            <p className="text-ink-1 text-md max-w-[68ch]">{t("report.doc.lede")}</p>
          </div>
        </header>

        {allFailed && (
          <p className="text-critical hs-label" data-print="keep">
            {t("report.doc.unreachable")}
          </p>
        )}

        {!settled && (
          <p className="hs-label" data-print="keep">
            {t("report.doc.loading")}
          </p>
        )}

        {/* ── 1 · The window at a glance ─────────────────────────────── */}
        <Panel label={t("report.doc.totals")} loading={!settled}>
          {summary.failed ? (
            <Failed>{t("report.doc.sectionFailed")}</Failed>
          ) : (
            <div
              data-print="glance"
              className="grid gap-6 sm:grid-cols-[repeat(2,minmax(0,1fr))] lg:grid-cols-[repeat(4,minmax(0,1fr))]"
            >
              <Figure label={t("report.doc.totalDetections")} value={f.number(totalDetections)} />
              <Figure label={t("report.doc.uniqueSources")} value={f.number(uniqueSources)} />
              <Figure
                label={t("report.doc.peakHour")}
                // A clock reading is a technical string: `07:00` inside an
                // Arabic paragraph must not be allowed to reorder.
                value={peakHour === null ? EMPTY : `${String(peakHour).padStart(2, "0")}:00`}
                note={peakHour === null ? undefined : t("report.doc.peakHourNote")}
              />
              <Figure
                label={t("report.doc.storedAllTime")}
                value={f.number(storedAllTime)}
                note={stored.failed ? t("report.doc.sectionFailed") : undefined}
              />
            </div>
          )}

          {!summary.failed && (
            <div className="border-rule mt-6 flex flex-wrap items-baseline gap-x-3 gap-y-2 border-t pt-4">
              <span className="hs-label">{t("report.doc.mostFrequent")}</span>
              {mostFrequent === null || classTotal === 0 ? (
                <span className="text-ink-2 text-sm">{t("report.notReported")}</span>
              ) : (
                <span className="inline-flex items-center gap-2">
                  <ClassDot type={mostFrequent} />
                  <Ltr className="text-ink-0 text-sm font-medium">{attackLabels[mostFrequent]}</Ltr>
                  <StatusPill tone={severityOf(mostFrequent)}>
                    {t(`severity.${severityOf(mostFrequent)}`)}
                  </StatusPill>
                </span>
              )}
            </div>
          )}
        </Panel>

        {/* ── 2 · By class ───────────────────────────────────────────── */}
        {/* Allowed to run past a fold. A long table that cannot break pushes
            itself whole onto the next sheet and leaves half a page of paper
            blank; splitting one with its head repeated is what a printed table
            has always done. */}
        <Panel data-print="flow" label={t("report.doc.byClass")} flush loading={!settled}>
          {/* The note sits in the body, not in the panel's `title` slot: that
              slot truncates to one line by design, and a sentence that explains
              what a column means must not be allowed to disappear into an
              ellipsis. */}
          <Note>{t("report.doc.byClassNote")}</Note>

          {summary.failed ? (
            <div className="p-4">
              <Failed>{t("report.doc.sectionFailed")}</Failed>
            </div>
          ) : classRows.length === 0 ? (
            <p className="hs-label p-4">{settled ? t("report.doc.empty") : EMPTY}</p>
          ) : (
            <div data-print="scroller" className="overflow-x-auto">
              <table className="w-full min-w-[34rem] border-collapse text-sm">
                <thead>
                  <tr className="border-rule border-b">
                    <Th>{t("report.doc.colClass")}</Th>
                    <Th>{t("report.doc.colSeverity")}</Th>
                    <Th numeric>{t("report.doc.colWindow")}</Th>
                    <Th numeric>{t("report.doc.colShare")}</Th>
                    <Th numeric>{t("report.doc.colAllTime")}</Th>
                  </tr>
                </thead>
                <tbody>
                  {classRows.map((row) => (
                    <tr key={row.type} className="border-rule border-b">
                      <Td>
                        <span className="flex min-w-0 items-center gap-2.5">
                          <ClassDot type={row.type} />
                          <Ltr className="text-ink-0 truncate font-medium">
                            {attackLabels[row.type]}
                          </Ltr>
                        </span>
                      </Td>
                      <Td>
                        <StatusPill tone={severityOf(row.type)}>
                          {t(`severity.${severityOf(row.type)}`)}
                        </StatusPill>
                      </Td>
                      <Td numeric>
                        <span className="hs-num">{f.number(row.value)}</span>
                      </Td>
                      <Td numeric>
                        <span className="flex items-center justify-end gap-2">
                          <ShareBar
                            fraction={classTotal > 0 ? row.value / classTotal : null}
                            color={attackColorVar(row.type)}
                          />
                          <span className="hs-num text-ink-1 w-14 text-end">
                            {classTotal > 0 ? f.percent(row.value / classTotal, 1) : EMPTY}
                          </span>
                        </span>
                      </Td>
                      <Td numeric>
                        <span className="hs-num text-ink-1">
                          {analysis.failed ? EMPTY : f.number(allTime?.get(row.type) ?? null)}
                        </span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
                <tfoot>
                  <tr>
                    <Td>
                      <span className="hs-label">{t("common.total")}</span>
                    </Td>
                    <Td />
                    <Td numeric>
                      <span className="hs-num text-ink-0 font-medium">{f.number(classTotal)}</span>
                    </Td>
                    <Td />
                    <Td numeric>
                      <span className="hs-num text-ink-1">
                        {analysis.failed || allTime === null
                          ? EMPTY
                          : f.number([...allTime.values()].reduce((s, n) => s + n, 0))}
                      </span>
                    </Td>
                  </tr>
                </tfoot>
              </table>
            </div>
          )}
        </Panel>

        {/* ── 3 · Busiest source addresses ───────────────────────────── */}
        <Panel data-print="flow" label={t("report.doc.topSources")} flush loading={!settled}>
          <Note>{t("report.doc.topSourcesNote", { n: f.number(TOP_LIMIT) })}</Note>

          {offenders.failed ? (
            <div className="p-4">
              <Failed>{t("report.doc.sectionFailed")}</Failed>
            </div>
          ) : sourceRows.length === 0 ? (
            <p className="hs-label p-4">{settled ? t("report.doc.noSources") : EMPTY}</p>
          ) : (
            <div data-print="scroller" className="overflow-x-auto">
              <table className="w-full min-w-[30rem] border-collapse text-sm">
                <thead>
                  <tr className="border-rule border-b">
                    <Th>{t("common.rank")}</Th>
                    <Th>{t("report.doc.colSource")}</Th>
                    <Th numeric>{t("report.doc.colCount")}</Th>
                    <Th numeric>{t("report.doc.colShare")}</Th>
                  </tr>
                </thead>
                <tbody>
                  {sourceRows.map((row, i) => (
                    <tr key={row.mac} className="border-rule border-b">
                      <Td>
                        <span className="hs-num text-ink-2">{f.number(i + 1)}</span>
                      </Td>
                      <Td>
                        <Mac value={row.mac} className="text-ink-0 text-xs" />
                      </Td>
                      <Td numeric>
                        <span className="hs-num">{f.number(row.value)}</span>
                      </Td>
                      <Td numeric>
                        <span className="flex items-center justify-end gap-2">
                          <ShareBar
                            fraction={sourceTotal > 0 ? row.value / sourceTotal : null}
                            color="var(--color-accent-soft)"
                          />
                          <span className="hs-num text-ink-1 w-14 text-end">
                            {sourceTotal > 0 ? f.percent(row.value / sourceTotal, 1) : EMPTY}
                          </span>
                        </span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* ── 4 · Channel occupancy ──────────────────────────────────── */}
        {/* Unbounded: one row per frequency the sensor stored. This is the one
            table allowed to run past a fold, with its head repeating. */}
        <Panel data-print="flow" label={t("report.doc.channels")} flush loading={!settled}>
          <Note>{t("report.doc.channelsNote")}</Note>

          {channels.failed ? (
            <div className="p-4">
              <Failed>{t("report.doc.sectionFailed")}</Failed>
            </div>
          ) : channelRows.length === 0 ? (
            <p className="hs-label p-4">{settled ? t("report.doc.noChannels") : EMPTY}</p>
          ) : (
            <div data-print="scroller" className="overflow-x-auto">
              <table className="w-full min-w-[30rem] border-collapse text-sm">
                <thead>
                  <tr className="border-rule border-b">
                    <Th>{t("report.doc.colFrequency")}</Th>
                    <Th>{t("report.doc.colChannel")}</Th>
                    <Th numeric>{t("report.doc.colCount")}</Th>
                    <Th numeric>{t("report.doc.colShare")}</Th>
                  </tr>
                </thead>
                <tbody>
                  {channelRows.map((row) => {
                    const channel = freqToChannel(row.freq)
                    return (
                      <tr key={row.freq} className="border-rule border-b">
                        <Td>
                          <Quantity value={f.number(row.freq)} unit={t("units.mhz")} />
                        </Td>
                        <Td>
                          {channel === null ? (
                            <span className="text-ink-2">{t("report.notReported")}</span>
                          ) : (
                            <span className="hs-num">{f.number(channel)}</span>
                          )}
                        </Td>
                        <Td numeric>
                          <span className="hs-num">{f.number(row.value)}</span>
                        </Td>
                        <Td numeric>
                          <span className="flex items-center justify-end gap-2">
                            <ShareBar
                              fraction={channelTotal > 0 ? row.value / channelTotal : null}
                              color="var(--color-accent-soft)"
                            />
                            <span className="hs-num text-ink-1 w-14 text-end">
                              {channelTotal > 0 ? f.percent(row.value / channelTotal, 1) : EMPTY}
                            </span>
                          </span>
                        </Td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* ── 5 · Provenance ─────────────────────────────────────────── */}
        <Panel label={t("report.doc.provenance")} loading={!settled}>
          {health.failed ? (
            <Failed>{t("report.doc.sectionFailed")}</Failed>
          ) : (
            <>
              <dl className="grid gap-x-8 gap-y-0 sm:grid-cols-[repeat(2,minmax(0,1fr))]">
                <Row label={t("report.doc.iface")}>
                  {capture?.iface ? (
                    <Ltr className="font-mono text-xs">{capture.iface}</Ltr>
                  ) : (
                    <Unreported label={t("report.notReported")} />
                  )}
                </Row>
                <Row label={t("report.doc.configuredChannel")}>
                  {count(capture?.channel) === null ? (
                    <Unreported label={t("report.notReported")} />
                  ) : (
                    <span className="hs-num">{f.number(count(capture?.channel))}</span>
                  )}
                </Row>
                <Row label={t("report.doc.observedFreq")}>
                  {count(capture?.observed_channel_freq) === null ? (
                    <Unreported label={t("report.notReported")} />
                  ) : (
                    <Quantity
                      value={f.number(count(capture?.observed_channel_freq))}
                      unit={t("units.mhz")}
                    />
                  )}
                </Row>
                <Row label={t("report.doc.latestPacket")}>
                  {latestPacketMs === null ? (
                    <Unreported label={t("report.notReported")} />
                  ) : (
                    <Stamp value={latestPacketMs} className="text-xs" />
                  )}
                </Row>
                <Row label={t("report.doc.model")}>
                  {health.data?.model_version && health.data.model_version !== "none" ? (
                    <Ltr className="font-mono text-xs">{health.data.model_version}</Ltr>
                  ) : (
                    <Unreported label={t("report.notReported")} />
                  )}
                </Row>
                <Row label={t("report.doc.spec")}>
                  {health.data?.spec_version ? (
                    <span className="hs-num">{health.data.spec_version}</span>
                  ) : (
                    <Unreported label={t("report.notReported")} />
                  )}
                </Row>
                <Row label={t("report.doc.backend")}>
                  {health.data?.version ? (
                    <span className="hs-num">{health.data.version}</span>
                  ) : (
                    <Unreported label={t("report.notReported")} />
                  )}
                </Row>
                <Row label={t("report.doc.source")}>{t("report.doc.sourceValue")}</Row>
              </dl>

              {configOnly && (
                <p className="text-ink-2 mt-4 max-w-[68ch] text-xs">{t("report.doc.configOnly")}</p>
              )}
            </>
          )}
        </Panel>

        {/* ── 6 · Reading this report ────────────────────────────────── */}
        <Panel label={t("report.doc.reading")}>
          <div className="text-ink-1 flex max-w-[70ch] flex-col gap-3 text-sm">
            <p>{t("report.doc.reading1")}</p>
            <p>{t("report.doc.reading2")}</p>
            <p className="text-ink-0 font-medium">{t("report.doc.reading3")}</p>
          </div>
        </Panel>

        {/* ── Closing line ───────────────────────────────────────────── */}
        <footer
          data-print="closing"
          className="border-rule flex flex-wrap items-baseline gap-x-4 gap-y-2 border-t pt-5"
        >
          <Wordmark size="sm" split />
          <span className="hs-label">{t("brand.tagline")}</span>
          <span className="hs-label ms-auto">{t("report.doc.footerNote")}</span>
        </footer>
      </article>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Document furniture                                                         */
/* -------------------------------------------------------------------------- */

/**
 * A timestamp in the reader's own locale.
 *
 * NOT `<Timestamp>` from `lib/format`, and the difference is measured rather
 * than assumed. That component pins its run to `direction: ltr`, which is
 * exactly right for an ISO string, a MAC or a hex literal — and exactly wrong
 * for a *localised* date, because a localised Arabic date contains an Arabic
 * word. Inside an LTR isolate, `28 أغسطس 2026، 02:19:30` renders in the visual
 * order `28  02:19:30  ،  2026  أغسطس`: bidi rule W2 retypes every European
 * number following an Arabic letter as an Arabic number, so the month, the
 * year and the clock collapse into one right-to-left run and swap ends. The
 * DOM is right and the sheet is wrong — the failure this project names as the
 * worst kind.
 *
 * `<bdi>` isolates the run without pinning it. Its direction is inferred from
 * the first strong character — Latin in English, Arabic in Arabic — so each
 * language gets its own reading order and neither is imposed on the other.
 *
 * The mono face is deliberately absent too: IBM Plex Mono carries no Arabic at
 * all, so setting the month name in it would drop the word to a system
 * fallback and shatter its joins. `tabular-nums` on the body face gives the
 * column alignment without the coverage gap.
 */
function Stamp({ value, className }: { value: DateLike; className?: string }) {
  const f = useFormatters()
  return (
    <time
      dateTime={toISO(value)}
      // Honest, not lazy: the export is prerendered in the default locale and
      // the reader's is only known once the client has read localStorage.
      suppressHydrationWarning
      className={cn("tabular-nums", className)}
    >
      <bdi>{f.dateTime(value)}</bdi>
    </time>
  )
}

function MetaPair({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="hs-label">{label}</dt>
      <dd className="text-ink-0 text-sm">{children}</dd>
    </div>
  )
}

/**
 * A headline figure. The display face, not the mono: at 30px the mono's fixed
 * advance widths read as a spreadsheet, and `tabular-nums` alone already gives
 * the column alignment. `Ltr` rather than `hs-num` for exactly that reason — it
 * isolates the run without dragging the mono family in with it.
 */
function Figure({
  label,
  value,
  note,
}: {
  label: React.ReactNode
  value: string
  note?: React.ReactNode
}) {
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <span className="hs-label">{label}</span>
      <Ltr className="font-display text-ink-0 text-3xl leading-none font-bold tabular-nums">
        {value}
      </Ltr>
      {note && <span className="text-ink-2 text-xs">{note}</span>}
    </div>
  )
}

function Row({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="border-rule flex items-baseline justify-between gap-4 border-b py-2.5">
      <dt className="hs-label shrink-0">{label}</dt>
      <dd className="text-ink-0 min-w-0 text-end text-sm">{children}</dd>
    </div>
  )
}

function Unreported({ label }: { label: string }) {
  return <span className="text-ink-2 text-xs">{label}</span>
}

/** The sentence that says what a table's columns actually count. */
function Note({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-ink-1 border-rule max-w-[78ch] border-b px-4 py-3 text-sm">{children}</p>
  )
}

function Failed({ children }: { children: React.ReactNode }) {
  return <p className="text-critical max-w-[68ch] text-sm">{children}</p>
}

function ClassDot({ type }: { type: AttackType }) {
  return (
    <span
      aria-hidden="true"
      className="size-2 shrink-0 rounded-full"
      style={{ background: attackColorVar(type) }}
    />
  )
}

/**
 * The share of a total, drawn once. `inline-size` rather than `width` so the
 * bar grows from the reader's start edge in both directions.
 */
function ShareBar({ fraction, color }: { fraction: number | null; color: string }) {
  if (fraction === null) return null
  const pct = Math.max(0, Math.min(1, fraction)) * 100
  return (
    <span aria-hidden="true" className="bg-paper-3 hidden h-1.5 w-16 rounded-full sm:inline-block">
      <span
        className="block h-full rounded-full"
        style={{ inlineSize: `${pct}%`, background: color }}
      />
    </span>
  )
}

function Th({ children, numeric = false }: { children?: React.ReactNode; numeric?: boolean }) {
  return (
    <th
      scope="col"
      className={`hs-label px-4 py-2.5 align-bottom ${numeric ? "text-end" : "text-start"}`}
    >
      {children}
    </th>
  )
}

function Td({ children, numeric = false }: { children?: React.ReactNode; numeric?: boolean }) {
  return (
    <td className={`px-4 py-2.5 align-middle ${numeric ? "text-end" : "text-start"}`}>{children}</td>
  )
}
