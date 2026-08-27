"use client"

/**
 * The landing page, served at `/`. The showpiece.
 *
 * WHY IT LIVES IN ITS OWN ROUTE GROUP
 *
 * `(app)` mounts `components/navbar.tsx` — a full-width sticky bar — around
 * every page inside it. Falcon Paper's macrostructure is *Marquee Hero* with
 * an **N5 floating pill** nav (`brand-spec.md` §Structure), and the two cannot
 * both be on screen: a pill floating under a sticky bar reads as a rendering
 * bug. So `/` moved to `(site)`, which inherits the root layout and nothing
 * else, and carries its own `NavPill`. The console routes keep their bar.
 *
 * WHAT IS ALLOWED ON THIS PAGE
 *
 * Only figures the sensor actually reported. There are no fixtures here, no
 * customer logos, no testimonials and no placeholder counts — the reference
 * this system is cut from puts a customer-logo wall in the third band, and we
 * do not have customers, so that band is the eight real classes with their
 * real counts instead.
 *
 * Two failure modes are distinguished everywhere, because collapsing them is
 * the single most misleading thing this page could do:
 *
 *   · **Unknown** — the endpoint did not answer. Rendered as `—` plus words.
 *   · **Zero** — the endpoint answered and the count is nought. Rendered as 0,
 *     which for a class means *looked for, not seen* and is a real result.
 *
 * `Number(null)` is `0`, not `NaN`, and this project has shipped that bug three
 * times — a null RSSI printed as `0` reads as full signal. Every numeric cast
 * below goes through `num()`, which rejects `null`/`undefined`/non-finite
 * first and returns `null` rather than a plausible-looking zero.
 *
 * Endpoints, by band:
 *   hero          — `/health` (capture block, packets, model, spec) + `/attacks/analysis`
 *   marquee       — none; the eight class identifiers are `lib/colors.ts`
 *   coverage      — `/attacks/analysis`
 *   how it works  — none; prose, plus `spec_version` from `/health`
 *   live numbers  — `/packets/count`, `/attacks/analysis`, `/reports/summary`, `/attacks/series`
 *   saqr, footer  — none
 */
import * as React from "react"
import Link from "next/link"
import { ArrowLeft, ArrowRight } from "lucide-react"

import { Logo, Wordmark } from "@/components/brand/logo"
import { AccentWord } from "@/components/hs/accent-word"
import { CommandBar } from "@/components/hs/command-bar"
import {
  DataCard,
  DataCardBar,
  DataCardNote,
  DataCardRow,
  DataCardRows,
  DataCardTotal,
  type DataCardRowTone,
} from "@/components/hs/data-card"
import { Eyebrow } from "@/components/hs/eyebrow"
import { Marquee } from "@/components/hs/marquee"
import { Metric } from "@/components/hs/metric"
import { NavPill, type NavPillLink } from "@/components/hs/nav-pill"
import { Panel, PanelGrid } from "@/components/hs/panel"
import { SectionHead } from "@/components/hs/section-head"
import { Sparkline } from "@/components/hs/sparkline"
import { StatementFooter } from "@/components/hs/statement-footer"
import { StatusPill } from "@/components/hs/status-pill"
import { Button } from "@/components/ui/button"
import { useHealth, type ConnectionState } from "@/hooks/use-health"
import { apiFetchJson } from "@/lib/api"
import {
  attackColorVar,
  attackLabels,
  attackTypes,
  severityOf,
  type AttackType,
  type Severity,
} from "@/lib/colors"
import { freqToChannel, toAttackType } from "@/lib/detections"
import { Ltr, TIMEZONE, useFormatters } from "@/lib/format"
import { useLocale, useT } from "@/lib/i18n"
import type { TranslationKey } from "@/lib/i18n"

/** Withheld, not zero. Same glyph the formatters and `/design` use. */
const EMPTY = "—"

/** The eight classes the spec defines. `other` is the catch-all, not a ninth. */
const SPEC_CLASSES: readonly AttackType[] = attackTypes.filter((t) => t !== "other")

/** The reporting window for every "last N days" figure on this page. */
const WINDOW_DAYS = 7

/* -------------------------------------------------------------------------- */
/* Reading the sensor                                                         */
/* -------------------------------------------------------------------------- */

/**
 * The only numeric cast on this page.
 *
 * `Number(null)` is `0` and `Number(undefined)` is `NaN`; neither may reach a
 * formatter, because both would print as a measurement nobody took. Anything
 * that is not a finite number comes back as `null`, which every call site
 * below renders as `—` and words.
 */
function num(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null
  const n = typeof value === "number" ? value : Number(value)
  return Number.isFinite(n) ? n : null
}

/** A non-empty trimmed string, or `null`. `"none"` is the API's own "unset". */
function str(value: unknown): string | null {
  if (typeof value !== "string") return null
  const s = value.trim()
  return s === "" || s === "none" ? null : s
}

type AnalysisPayload = Record<string, unknown>

type SummaryPayload = {
  summary?: { totalAttacks?: unknown; mostFrequentType?: unknown; uniqueSources?: unknown } | null
}

type SeriesPayload = {
  total?: unknown
  points?: ReadonlyArray<{ t?: unknown; count?: unknown }> | null
}

type Feed = {
  /** False until the first pass has settled — distinct from "answered nothing". */
  ready: boolean
  /** Total rows in `packets`, all time. `/packets/count`. */
  packets: number | null
  /** Per-class counts, zero-filled by the API across the whole spec. */
  counts: Record<AttackType, number> | null
  /** Distinct source MACs in the window. `/reports/summary`. */
  sources: number | null
  /** Class the window saw most of, already narrowed to our vocabulary. */
  busiest: AttackType | null
  /** Per-day detection counts in the window. `/attacks/series`. */
  series: number[] | null
}

const EMPTY_FEED: Feed = {
  ready: false,
  packets: null,
  counts: null,
  sources: null,
  busiest: null,
  series: null,
}

/** Never throws: a dead endpoint yields `null`, which renders as "not reported". */
async function read<T>(path: string): Promise<T | null> {
  try {
    return await apiFetchJson<T>(path)
  } catch {
    return null
  }
}

/**
 * Narrow `/attacks/analysis` into our vocabulary.
 *
 * The model emits `(Re)Assoc`, `Evil_Twin`, `RogueAP`; `lib/colors.ts` is keyed
 * `reassoc`, `evil_twin`, `rogueap`. `toAttackType` is the one place that
 * mapping lives. The API zero-fills every class in the spec, so a `0` here is a
 * genuine "looked for, not seen" and must survive to the screen as a `0`.
 */
function toCounts(raw: AnalysisPayload | null): Record<AttackType, number> | null {
  if (!raw || typeof raw !== "object") return null
  const out = Object.fromEntries(attackTypes.map((t) => [t, 0])) as Record<AttackType, number>
  let sawOne = false
  for (const [label, value] of Object.entries(raw)) {
    const n = num(value)
    if (n === null) continue
    out[toAttackType(label)] += n
    sawOne = true
  }
  return sawOne ? out : null
}

/**
 * One pass on mount, then a slow refresh. The landing page is an argument, not
 * an instrument: it has to be *true*, not live to the second, and the console
 * behind the CTA is where a second-by-second view belongs.
 *
 * The four reads are independent. A backend that can answer `/packets/count`
 * but not `/reports/summary` shows the count and says "not reported" for the
 * rest, rather than blanking the page on one rejection.
 */
function useSensorFeed(): Feed {
  const [feed, setFeed] = React.useState<Feed>(EMPTY_FEED)

  React.useEffect(() => {
    let cancelled = false

    const pass = async () => {
      const series = `/attacks/series?days=${WINDOW_DAYS}&bucket=day&tz=${encodeURIComponent(TIMEZONE)}`
      const [count, analysis, summary, points] = await Promise.all([
        read<{ count?: unknown }>("/packets/count"),
        read<AnalysisPayload>("/attacks/analysis"),
        read<SummaryPayload>(`/reports/summary?days=${WINDOW_DAYS}`),
        read<SeriesPayload>(series),
      ])
      if (cancelled) return

      const s = summary?.summary ?? null
      const mostFrequent = str(s?.mostFrequentType)
      const buckets = Array.isArray(points?.points) ? points.points : null

      setFeed({
        ready: true,
        packets: num(count?.count),
        counts: toCounts(analysis),
        sources: num(s?.uniqueSources),
        busiest: mostFrequent ? toAttackType(mostFrequent) : null,
        // A bucket whose count is missing is dropped, not read as 0 — an absent
        // bucket and an empty one are different facts here too.
        series: buckets ? buckets.map((p) => num(p?.count)).filter((n): n is number => n !== null) : null,
      })
    }

    void pass()
    const timer = setInterval(() => void pass(), 30_000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])

  return feed
}

/* -------------------------------------------------------------------------- */
/* Small shared pieces                                                        */
/* -------------------------------------------------------------------------- */

const STATE_KEY: Record<ConnectionState, TranslationKey> = {
  unknown: "landing.sensor.unknown",
  online: "landing.sensor.online",
  degraded: "landing.sensor.degraded",
  offline: "landing.sensor.offline",
}

const STATE_TONE = {
  unknown: "neutral",
  online: "info",
  degraded: "high",
  offline: "critical",
} as const

/** Severity -> the row tint a `DataCard` understands. `info` stays plain ink. */
const ROW_TONE: Record<Severity, DataCardRowTone> = {
  critical: "critical",
  high: "companion",
  info: "default",
}

const SEVERITY_KEY: Record<Severity, TranslationKey> = {
  critical: "severity.critical",
  high: "severity.high",
  info: "severity.info",
}

/**
 * A `key: value` pair for the mono fineprint under the hero.
 *
 * The label and the figure are siblings rather than one interpolated string.
 * A version like `2.1.0` inside a translated Arabic sentence is a bidi hazard —
 * it opens on a neutral character and would take the paragraph's direction —
 * and `hs-num` cannot be applied to half of a `t()` result.
 */
function Fineprint({ label, value }: { label: string; value: string | null }) {
  return (
    <span className="flex min-w-0 items-baseline gap-2">
      <span className="hs-label shrink-0">{label}</span>
      <span className="hs-num text-ink-1 truncate text-xs">{value ?? EMPTY}</span>
    </span>
  )
}

/* -------------------------------------------------------------------------- */
/* Page                                                                       */
/* -------------------------------------------------------------------------- */

export default function LandingPage() {
  const t = useT()
  const f = useFormatters()
  const { isRTL } = useLocale()
  const { state, health } = useHealth()
  const feed = useSensorFeed()

  // Direction, not language: the glyph is swapped rather than mirrored with a
  // transform, so the arrowhead keeps its drawn weight.
  const Arrow = isRTL ? ArrowLeft : ArrowRight

  const offline = state === "offline"
  const capture = health?.capture ?? null

  /* -- what the capture block actually reported ----------------------------- */
  // `observed_*` is measured from the newest stored packet; `iface`/`channel`
  // are what the sensor was *configured* to. Prefer the measurement, fall back
  // to the configuration, and say which one is on screen in the card note.
  const observedIface = str(capture?.observed_iface)
  const configuredIface = str(capture?.iface)
  const iface = observedIface ?? configuredIface
  const observedChannel = freqToChannel(num(capture?.observed_channel_freq))
  const channel = observedChannel ?? num(capture?.channel)
  const measured = str(capture?.source)?.includes("sysfs") === true
  const frames = num(health?.packets)
  const model = str(health?.model_version)
  const spec = str(health?.spec_version)

  /* -- class counts --------------------------------------------------------- */
  const counts = feed.counts
  const classified = counts ? SPEC_CLASSES.reduce((sum, c) => sum + counts[c], 0) : null
  const classesSeen = counts ? SPEC_CLASSES.filter((c) => counts[c] > 0).length : null

  const ranked = React.useMemo(
    () =>
      counts
        ? [...SPEC_CLASSES].sort((a, b) => counts[b] - counts[a] || SPEC_CLASSES.indexOf(a) - SPEC_CLASSES.indexOf(b))
        : null,
    [counts]
  )
  const top = ranked ? ranked.filter((c) => counts![c] > 0).slice(0, 3) : []

  const severityTotals = React.useMemo(() => {
    if (!counts) return null
    const out: Record<Severity, number> = { critical: 0, high: 0, info: 0 }
    for (const c of SPEC_CLASSES) out[severityOf(c)] += counts[c]
    return out
  }, [counts])

  const busiestCount = feed.busiest && counts ? counts[feed.busiest] : null

  /* -- nav ------------------------------------------------------------------ */
  const navLinks: readonly NavPillLink[] = [
    { href: "/dashboard", label: t("nav.dashboard") },
    { href: "/threats", label: t("nav.threats") },
    { href: "/map", label: t("nav.map") },
    { href: "/saqr", label: t("nav.saqr") },
  ]

  return (
    <div className="min-w-0">
      {/* Off-screen until focused. `start-4`, never `left-4`: it has to appear
          on the reading edge in Arabic too. */}
      <a
        href="#main"
        className="border-rule-soft bg-paper-1 text-ink-0 sr-only rounded-md px-3 py-2 text-sm focus:not-sr-only focus:absolute focus:top-4 focus:start-4 focus:z-[60] focus:border"
      >
        {t("nav.skipToContent")}
      </a>

      {/* ── N5 · floating pill ─────────────────────────────────────────── */}
      <NavPill
        label={t("nav.primary")}
        brand={
          <Link href="/" className="flex items-center gap-2 leading-none" aria-label={t("brand.name")}>
            <Logo size={22} decorative />
            {/* Stands down below 400px so the pill stays content-sized on a
                320px phone instead of stretching to the viewport. */}
            <Wordmark size="sm" split className="hidden min-[400px]:inline-block" />
          </Link>
        }
        links={navLinks}
        renderLink={(link, cls) => (
          <Link href={link.href} className={cls}>
            {link.label}
          </Link>
        )}
        actions={<CommandBar />}
      />

      {/* ── 1 · Hero ───────────────────────────────────────────────────── */}
      {/* Bottom padding is ~1.4x the top so the hero settles into the page
          rather than floating above it. */}
      <header className="mx-auto w-full max-w-[1240px] px-6 pt-28 pb-24 sm:px-8 sm:pb-32">
        {/* Live only when the sensor is genuinely answering: a pulsing dot over
            a dead endpoint is the UI lying once a second, forever. */}
        <Eyebrow
          variant="pill"
          tone={state === "online" ? "accent" : "default"}
          live={state === "online"}
          dot={state !== "online"}
        >
          {t(STATE_KEY[state])}
        </Eyebrow>

        <div className="mt-8 grid items-center gap-12 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
          <div className="min-w-0">
            {/* `overflow-wrap: anywhere` is mandatory: at 320px the display
                step is ~48px and one long word would otherwise push the page
                sideways.

                The headline is FIVE keys, not three, because `Wi-Fi` carries a
                hyphen and a written hyphen is a line-break opportunity no CSS
                can suppress from the outside (`word-break: keep-all` is
                CJK-only; `hyphens` governs *inserted* hyphens). At 375px in
                Arabic and at 1440px in English the headline broke as `Wi-` /
                `Fi`. Giving the identifier its own span lets it take
                `white-space: nowrap` and wrap as one unit — and it wants
                `<Ltr>` regardless, being a Latin identifier inside a sentence
                that is Arabic half the time. `lead` is empty in English: the
                Arabic sentence opens with a word before the term and the
                English one does not. */}
            <h1 className="font-display text-ink-0 text-display max-w-[16ch] min-w-0 font-bold [overflow-wrap:anywhere] [text-wrap:balance]">
              {t("landing.hero.lead")}
              <Ltr className="whitespace-nowrap">{t("landing.hero.term")}</Ltr>
              {t("landing.hero.mid")}
              <AccentWord>{t("landing.hero.accent")}</AccentWord>
              {t("landing.hero.tail")}
            </h1>

            <p className="text-ink-1 text-md mt-6 max-w-[52ch]">{t("landing.hero.lede")}</p>

            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Button asChild size="lg">
                <Link href="/dashboard" className="inline-flex items-center gap-2">
                  {t("app.hero.primaryCta")}
                  <Arrow className="size-4 shrink-0" aria-hidden="true" />
                </Link>
              </Button>
              <Button asChild variant="outline" size="lg">
                <Link href="/threats">{t("app.hero.secondaryCta")}</Link>
              </Button>
            </div>

            <div className="mt-8 flex flex-wrap items-baseline gap-x-6 gap-y-3">
              <Fineprint label={t("landing.fineprint.model")} value={model} />
              <Fineprint label={t("landing.fineprint.spec")} value={spec} />
              <Fineprint label={t("landing.fineprint.timezone")} value={TIMEZONE} />
            </div>
          </div>

          {/* The hero object. Every figure below came off the sensor in this
              session; nothing here has a fallback value. */}
          <DataCard
            label={iface ?? EMPTY}
            title={t("landing.capture.title")}
            status={
              <StatusPill tone={STATE_TONE[state]} live={state === "online"} dot={state !== "online"}>
                {t(STATE_KEY[state])}
              </StatusPill>
            }
          >
            <DataCardRows>
              <DataCardRow label={t("landing.capture.iface")} value={iface ?? EMPTY} />
              <DataCardRow
                label={t("landing.capture.channel")}
                value={channel === null ? EMPTY : f.number(channel)}
              />
              <DataCardRow
                label={t("landing.capture.frames")}
                value={frames === null ? EMPTY : f.number(frames)}
              />

              {top.length > 0
                ? top.map((c) => (
                    <DataCardRow
                      key={c}
                      // The class identifier stays Latin in both locales and is
                      // isolated, or an Arabic row reorders "Evil Twin".
                      label={<Ltr>{attackLabels[c]}</Ltr>}
                      value={f.number(counts![c])}
                      tone={ROW_TONE[severityOf(c)]}
                    />
                  ))
                : // Not a spacer: it names why the rows are absent.
                  <DataCardRow
                    label={t("landing.capture.classes")}
                    value={counts ? f.number(0) : EMPTY}
                  />}
            </DataCardRows>

            <DataCardTotal
              label={t("landing.capture.total")}
              value={classified === null ? EMPTY : f.number(classified)}
              unit={t("landing.capture.unit")}
            />

            {severityTotals && classified !== null && classified > 0 && (
              <DataCardBar
                label={t("landing.capture.severity")}
                segments={[
                  {
                    label: t("severity.critical"),
                    value: severityTotals.critical,
                    color: "var(--sev-critical)",
                  },
                  { label: t("severity.high"), value: severityTotals.high, color: "var(--sev-high)" },
                  { label: t("severity.info"), value: severityTotals.info, color: "var(--sev-info)" },
                ]}
              />
            )}

            {/* Three notes, three different claims. Before `/health` has
                answered we know nothing about the radio, so claiming it could
                not be measured would be as wrong as claiming it could. */}
            <DataCardNote>
              {offline
                ? t("landing.unreachable")
                : !health
                  ? t("landing.reading")
                  : measured
                    ? t("landing.capture.noteMeasured")
                    : t("landing.capture.noteConfigured")}
            </DataCardNote>
          </DataCard>
        </div>

        {/* ── 2 · Marquee ──────────────────────────────────────────────── */}
        {/* The eight class identifiers. Latin in both locales — a class name is
            a technical identifier, not prose — and `aria-hidden`, because the
            same eight are real content in the coverage strip below. */}
        <Marquee
          className="mt-16 sm:mt-20"
          items={SPEC_CLASSES.map((c) => attackLabels[c])}
        />
      </header>

      <main id="main" className="mx-auto flex w-full max-w-[1240px] min-w-0 flex-col gap-24 px-6 pb-24 sm:px-8 sm:gap-28">
        {/* ── 3 · Coverage strip ─────────────────────────────────────────── */}
        {/* Where the reference puts a wall of customer logos. We have no
            customers, and inventing eight of them is the exact anti-pattern
            this system bans, so the band is the eight classes and what the
            sensor has actually counted for each. */}
        <section className="flex min-w-0 flex-col gap-6">
          <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
            <Eyebrow>{t("landing.coverage.eyebrow")}</Eyebrow>
            <span className="text-ink-2 text-sm">
              {classesSeen === null
                ? feed.ready
                  ? t("landing.notReported")
                  : t("landing.reading")
                : t("landing.coverage.seen", {
                    seen: f.number(classesSeen),
                    total: f.number(SPEC_CLASSES.length),
                  })}
            </span>
          </div>

          {/* No internal rules and no per-cell card. Eight bordered boxes read
              as eight competing objects; one hairline above and below reads as
              one band, which is what this is. */}
          <ul className="border-rule grid min-w-0 grid-cols-2 gap-x-6 gap-y-8 border-y py-8 sm:grid-cols-4 sm:gap-x-8">
            {SPEC_CLASSES.map((c) => {
              const n = counts ? counts[c] : null
              // Share of everything classified. Guarded against a zero total, and
              // against a total that is itself unknown.
              const share = n !== null && classified !== null && classified > 0 ? n / classified : null
              return (
                <li key={c} className="flex min-w-0 flex-col gap-2">
                  <span className="flex min-w-0 items-center gap-2">
                    <span
                      aria-hidden="true"
                      className="size-2.5 shrink-0 rounded-full"
                      style={{ background: attackColorVar(c) }}
                    />
                    <Ltr className="text-ink-0 min-w-0 truncate text-sm font-medium">
                      {attackLabels[c]}
                    </Ltr>
                  </span>

                  <span className="font-display text-ink-0 text-xl leading-none font-bold tabular-nums">
                    {n === null ? EMPTY : f.number(n)}
                  </span>

                  {/* The track is drawn even at 0%: the bar is the scale, and a
                      class with nothing against it still has to show its slot. */}
                  <span className="bg-paper-2 mt-0.5 block h-1 w-full overflow-hidden rounded-full">
                    {share !== null && share > 0 && (
                      <span
                        aria-hidden="true"
                        className="block h-full rounded-full"
                        style={{ inlineSize: `${share * 100}%`, background: attackColorVar(c) }}
                      />
                    )}
                  </span>

                  <span className="flex min-w-0 items-baseline justify-between gap-2">
                    <span className="hs-label min-w-0 truncate">
                      {n === null
                        ? t("landing.notReported")
                        : n === 0
                          ? t("landing.coverage.notSeen")
                          : t(SEVERITY_KEY[severityOf(c)])}
                    </span>
                    {/* Isolated: in an Arabic paragraph `12.8%` opens on a
                        digit run and would otherwise take the paragraph's
                        direction along with the sign. */}
                    {share !== null && share > 0 && (
                      <span className="hs-num text-ink-2 shrink-0 text-xs">{f.percent(share, 1)}</span>
                    )}
                  </span>
                </li>
              )
            })}
          </ul>

          {offline && <p className="text-ink-2 text-sm">{t("landing.unreachable")}</p>}
        </section>

        {/* ── 4 · How it works ───────────────────────────────────────────── */}
        <section className="flex min-w-0 flex-col gap-8">
          <SectionHead
            eyebrow={t("landing.how.eyebrow")}
            title={
              <>
                {t("landing.how.lead")}
                <AccentWord>{t("landing.how.accent")}</AccentWord>
                {t("landing.how.tail")}
              </>
            }
            body={t("landing.how.body")}
          />

          {/* Four panels, not a diagram. A drawn pipeline here would be a
              picture of the code rather than the code, and it would be the
              first thing to go stale. */}
          <PanelGrid className="sm:grid-cols-[repeat(2,minmax(0,1fr))] lg:grid-cols-[repeat(4,minmax(0,1fr))]">
            <Panel label={t("landing.how.step1")} title={t("landing.how.step1.title")}>
              <p className="text-ink-1 text-sm">{t("landing.how.step1.body")}</p>
            </Panel>
            <Panel label={t("landing.how.step2")} title={t("landing.how.step2.title")}>
              <p className="text-ink-1 text-sm">{t("landing.how.step2.body")}</p>
            </Panel>
            <Panel label={t("landing.how.step3")} title={t("landing.how.step3.title")}>
              <p className="text-ink-1 text-sm">{t("landing.how.step3.body")}</p>
            </Panel>
            <Panel label={t("landing.how.step4")} title={t("landing.how.step4.title")}>
              <p className="text-ink-1 text-sm">{t("landing.how.step4.body")}</p>
            </Panel>
          </PanelGrid>

          <p className="text-ink-2 max-w-[68ch] text-sm">{t("landing.how.note")}</p>
        </section>

        {/* ── 5 · Live numbers ───────────────────────────────────────────── */}
        <section className="flex min-w-0 flex-col gap-8">
          <SectionHead
            eyebrow={t("landing.numbers.eyebrow")}
            title={
              <>
                {t("landing.numbers.lead")}
                <AccentWord>{t("landing.numbers.accent")}</AccentWord>
                {t("landing.numbers.tail")}
              </>
            }
            body={t("landing.numbers.body")}
          />

          {offline ? (
            <Panel label={t("landing.figures")}>
              <p className="text-ink-1 text-sm">{t("landing.unreachable")}</p>
            </Panel>
          ) : !feed.ready ? (
            <Panel label={t("landing.figures")} loading>
              <p className="text-ink-2 text-sm">{t("landing.reading")}</p>
            </Panel>
          ) : (
            /* The panels carry no header: `Metric` already sets its own mono
               label, and a second one above it says the same thing twice. */
            <PanelGrid className="sm:grid-cols-[repeat(2,minmax(0,1fr))] lg:grid-cols-[repeat(4,minmax(0,1fr))]">
              <Panel>
                <Readout
                  label={t("landing.stat.packets")}
                  value={feed.packets}
                  format={f.number}
                  notReported={t("landing.notReported")}
                  footer={
                    feed.series && feed.series.length > 1 ? (
                      <span className="flex min-w-0 flex-col gap-1.5">
                        {/* No `label`: the caption directly beneath already
                            carries it, and two names for one line is a stutter
                            in a screen reader. */}
                        <Sparkline values={feed.series} area />
                        <span className="hs-label">{t("landing.stat.trend", { days: f.number(WINDOW_DAYS) })}</span>
                      </span>
                    ) : undefined
                  }
                />
              </Panel>

              <Panel>
                <Readout
                  label={t("landing.stat.classes")}
                  value={classesSeen}
                  format={f.number}
                  notReported={t("landing.notReported")}
                  unit={t("landing.stat.classesOf", { total: f.number(SPEC_CLASSES.length) })}
                />
              </Panel>

              <Panel>
                <Readout
                  label={t("landing.stat.sources")}
                  value={feed.sources}
                  format={f.number}
                  notReported={t("landing.notReported")}
                  footer={<span className="hs-label">{t("landing.stat.window", { days: f.number(WINDOW_DAYS) })}</span>}
                />
              </Panel>

              <Panel>
                <Readout
                  label={t("landing.stat.busiest")}
                  value={busiestCount}
                  format={f.number}
                  notReported={t("landing.notReported")}
                  tone={feed.busiest ? severityOf(feed.busiest) : "neutral"}
                  footer={
                    feed.busiest ? (
                      <Ltr className="hs-label">{attackLabels[feed.busiest]}</Ltr>
                    ) : (
                      <span className="hs-label">{t("landing.stat.window", { days: f.number(WINDOW_DAYS) })}</span>
                    )
                  }
                />
              </Panel>
            </PanelGrid>
          )}
        </section>

        {/* ── 6 · Saqr ───────────────────────────────────────────────────── */}
        <section className="flex min-w-0 flex-col gap-8">
          <SectionHead
            eyebrow={t("landing.saqr.eyebrow")}
            title={
              <>
                {t("landing.saqr.lead")}
                <AccentWord>{t("landing.saqr.accent")}</AccentWord>
                {t("landing.saqr.tail")}
              </>
            }
            body={t("landing.saqr.body")}
            actions={
              <Button asChild>
                <Link href="/saqr" className="inline-flex items-center gap-2">
                  {t("landing.saqr.cta")}
                  <Arrow className="size-4 shrink-0" aria-hidden="true" />
                </Link>
              </Button>
            }
          />

          <PanelGrid className="sm:grid-cols-[repeat(3,minmax(0,1fr))]">
            <Panel label={t("landing.saqr.p1")}>
              <p className="text-ink-1 text-sm">{t("landing.saqr.p1.body")}</p>
            </Panel>
            <Panel label={t("landing.saqr.p2")}>
              <p className="text-ink-1 text-sm">{t("landing.saqr.p2.body")}</p>
            </Panel>
            <Panel label={t("landing.saqr.p3")}>
              <p className="text-ink-1 text-sm">{t("landing.saqr.p3.body")}</p>
            </Panel>
          </PanelGrid>
        </section>
      </main>

      {/* ── 7 · Ft5 · Statement footer ─────────────────────────────────── */}
      <div className="mx-auto w-full max-w-[1240px] px-6 sm:px-8">
        <StatementFooter
          statement={
            <>
              {t("landing.footer.lead")}
              <AccentWord>{t("landing.footer.accent")}</AccentWord>
              {t("landing.footer.tail")}
            </>
          }
          brand={
            <>
              <Logo size={24} decorative />
              <Wordmark size="sm" split />
            </>
          }
          linksLabel={t("landing.footer.linksLabel")}
          links={
            <>
              {navLinks.map((link) => (
                <Link
                  key={link.href}
                  href={link.href}
                  className="text-ink-1 hover:text-ink-0 transition-colors"
                >
                  {link.label}
                </Link>
              ))}
            </>
          }
          meta={t("landing.footer.meta")}
        />
      </div>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Readout                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * `Metric`, but for a figure that may not exist.
 *
 * `Metric` takes `value: number`, so a caller with `null` has to invent one —
 * and inventing `0` is precisely the failure this page exists to avoid. Passing
 * `0` with a formatter that returns `—` keeps the layout, the count-up and the
 * label rhythm identical while printing nothing the sensor did not report, and
 * the footer says so in words underneath.
 */
function Readout({
  label,
  value,
  format,
  notReported,
  unit,
  tone = "neutral",
  footer,
}: {
  label: React.ReactNode
  value: number | null
  format: (n: number) => string
  notReported: string
  unit?: React.ReactNode
  tone?: "neutral" | "critical" | "high" | "info"
  footer?: React.ReactNode
}) {
  const known = value !== null

  return (
    <Metric
      label={label}
      value={known ? value : 0}
      format={known ? format : () => EMPTY}
      animate={known}
      unit={known ? unit : undefined}
      tone={known ? tone : "neutral"}
      footer={known ? footer : <span className="hs-label">{notReported}</span>}
    />
  )
}
