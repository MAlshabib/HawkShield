"use client"

/**
 * The landing page, served at `/`.
 *
 * It replaces two things at once. The old `/` was a client-side redirect stub
 * that flashed an untranslated "Loading HawkShield..." before bouncing to
 * `/home`; the old `/home` was a marketing hero that fired a *fabricated*
 * attack toast every 15-30 seconds and claimed the product "blocks" attacks.
 * Both are gone. Nothing on this page is invented: every figure below is a
 * value the sensor reported in this session, and when it reports nothing the
 * strip says so in words rather than printing zeros — a zero and an unknown are
 * different facts and a judge will read them differently.
 *
 * Endpoints: `/health` (state, model in service), `/packets/count` (total
 * observed) and `/attacks/analysis` (how many of the eight classes have
 * actually been seen).
 */
import * as React from "react"
import Link from "next/link"
import { ArrowLeft, ArrowRight } from "lucide-react"

import { Logo, Wordmark } from "@/components/brand/logo"
import { Hairline } from "@/components/hs/hairline"
import { Metric } from "@/components/hs/metric"
import { Module } from "@/components/hs/module"
import { Radar } from "@/components/hs/radar"
import { StatusPill } from "@/components/hs/status-pill"
import { Button } from "@/components/ui/button"
import { useHealth, type ConnectionState } from "@/hooks/use-health"
import { apiFetchJson } from "@/lib/api"
import { attackTypes } from "@/lib/colors"
import { useFormatters } from "@/lib/format"
import { useLocale, useT } from "@/lib/i18n"
import type { TranslationKey } from "@/lib/i18n"

/** Classes the spec defines. `other` is the catch-all bucket, not a ninth class. */
const REAL_CLASS_COUNT = attackTypes.filter((t) => t !== "other").length

type Strip = {
  /** `null` until the sensor has answered — never coerced to 0. */
  packets: number | null
  classesSeen: number | null
}

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

/** One non-numeric cell of the strip. Mirrors `Metric`'s label/value rhythm. */
function Readout({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="hs-label">{label}</span>
      <span className="flex min-w-0 items-baseline">{children}</span>
    </div>
  )
}

export default function LandingPage() {
  const t = useT()
  const f = useFormatters()
  const { isRTL } = useLocale()
  const Arrow = isRTL ? ArrowLeft : ArrowRight
  const { state, health } = useHealth()
  const [strip, setStrip] = React.useState<Strip>({ packets: null, classesSeen: null })

  // One pass on mount, then a slow refresh. The landing page is not an
  // instrument; it only has to be true, not live to the second.
  React.useEffect(() => {
    let cancelled = false

    const read = async () => {
      try {
        const [count, analysis] = await Promise.all([
          apiFetchJson<{ count?: number }>("/packets/count"),
          apiFetchJson<Record<string, number>>("/attacks/analysis"),
        ])
        if (cancelled) return
        const seen = Object.values(analysis ?? {}).filter((n) => Number(n) > 0).length
        setStrip({
          packets: typeof count?.count === "number" ? count.count : null,
          classesSeen: analysis ? seen : null,
        })
      } catch {
        // Leave the previous values alone. `state` from useHealth is what tells
        // the reader the sensor is away; blanking the figures would say it twice.
        if (!cancelled) setStrip((prev) => prev)
      }
    }

    void read()
    const timer = setInterval(read, 30_000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])

  const unreachable = state === "offline"
  const waiting = state === "unknown" && strip.packets === null
  const model = health?.model_version && health.model_version !== "none" ? health.model_version : null

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-10 px-4 py-14 sm:py-20 lg:px-8">
      {/* ---- mark, wordmark, thesis --------------------------------------- */}
      <div className="flex flex-col gap-6">
        <div className="flex items-center gap-4">
          <Logo size={64} decorative />
          <Wordmark size="lg" split />
        </div>

        <span className="hs-label">{t("landing.eyebrow")}</span>

        <h1 className="text-ink font-display max-w-[18ch] text-4xl leading-[1.05] font-medium sm:text-5xl">
          {t("app.hero.headline")}
        </h1>

        <p className="text-ink-dim max-w-prose text-base leading-relaxed">{t("app.hero.body")}</p>

        <div className="flex flex-wrap items-center gap-4">
          <Button asChild size="lg">
            <Link href="/dashboard" className="inline-flex items-center gap-2">
              {t("app.hero.primaryCta")}
              {/* Direction, not language: the glyph is swapped rather than
                  mirrored with a transform, so the arrowhead keeps its weight. */}
              <Arrow className="size-4" aria-hidden="true" />
            </Link>
          </Button>
          <span className="text-ink-faint text-sm">{t("brand.tagline")}</span>
        </div>
      </div>

      <Hairline />

      {/* ---- live stat strip --------------------------------------------- */}
      <Module
        label={t("landing.figures")}
        actions={
          <>
            {/* The sweep is only mounted over a sensor that is genuinely
                answering. Anything else gets the frozen ring. */}
            <Radar
              size={11}
              active={state === "online"}
              label={t(STATE_KEY[state])}
            />
            <StatusPill tone={STATE_TONE[state]} dot>
              {t(STATE_KEY[state])}
            </StatusPill>
          </>
        }
      >
        {unreachable ? (
          <p className="text-ink-dim py-2 text-sm">{t("landing.unreachable")}</p>
        ) : waiting ? (
          <p className="text-ink-dim py-2 text-sm">{t("landing.reading")}</p>
        ) : (
          <div className="grid grid-cols-2 gap-6 py-1 lg:grid-cols-4">
            {strip.packets === null ? (
              <Readout label={t("landing.stat.packets")}>
                <span className="text-ink-dim text-sm">{t("landing.notReported")}</span>
              </Readout>
            ) : (
              <Metric label={t("landing.stat.packets")} value={strip.packets} format={f.number} />
            )}

            {strip.classesSeen === null ? (
              <Readout label={t("landing.stat.classes")}>
                <span className="text-ink-dim text-sm">{t("landing.notReported")}</span>
              </Readout>
            ) : (
              <Metric
                label={t("landing.stat.classes")}
                value={strip.classesSeen}
                format={f.number}
                unit={t("landing.stat.classesOf", { total: f.number(REAL_CLASS_COUNT) })}
              />
            )}

            <Readout label={t("landing.stat.model")}>
              {model ? (
                // A model identifier is Latin in both locales and must not be
                // reordered by the bidi run, hence `hs-num`.
                <span className="hs-num text-ink text-lg leading-none font-medium">{model}</span>
              ) : (
                <span className="text-ink-dim text-sm">{t("landing.notReported")}</span>
              )}
            </Readout>

            <Readout label={t("landing.stat.sensor")}>
              <span className="text-ink text-lg leading-none font-medium">{t(STATE_KEY[state])}</span>
            </Readout>
          </div>
        )}
      </Module>
    </div>
  )
}
