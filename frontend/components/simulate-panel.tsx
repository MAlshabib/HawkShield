"use client"

/**
 * Operator control for `POST /simulate` — the demo's plan B.
 *
 * The backend crafts or replays traffic, runs it through the REAL detection
 * model, and persists whatever the model predicted, tagged as simulated. So the
 * summary below is not a mock: it is ground truth about what the model did, and
 * nothing here assumes which classes will come back. The rows are built from
 * whatever keys the response carried.
 *
 * It only needs the API, so it stays usable while the rest of the console is in
 * its reconnecting state.
 *
 * The status→outcome mapping in `lib/simulate.ts` is unchanged; what changed is
 * that it now hands back dictionary keys instead of English prose, so this panel
 * speaks Arabic like every other surface. The server's own `detail` string is
 * the one thing still rendered verbatim — see the note where it is shown.
 */
import * as React from "react"
import { Loader2, Zap } from "lucide-react"

import { Panel } from "@/components/hs/panel"
import { StatusPill } from "@/components/hs/status-pill"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { useToast } from "@/hooks/use-toast"
import { attackColorVar, attackLabels } from "@/lib/colors"
import { useFormatters } from "@/lib/format"
import { useT } from "@/lib/i18n"
import {
  SIMULATABLE_ATTACKS,
  SIMULATE_COUNT_PRESETS,
  SIMULATE_MAX_COUNT,
  SIMULATE_MIN_COUNT,
  runSimulation,
  summaryRows,
  totalPersisted,
  type SimulatableAttack,
  type SimulateIntensity,
  type SimulateMessage,
  type SimulateSummary,
} from "@/lib/simulate"
import { cn } from "@/lib/utils"

type Result =
  | { kind: "ok"; summary: SimulateSummary; note: SimulateMessage | null }
  | { kind: "error"; title: SimulateMessage; message: SimulateMessage; detail: string | null }

export function SimulatePanel({
  onSimulated,
  className,
}: {
  /** Called after a successful run so the host page can pull the new figures. */
  onSimulated?: () => void
  className?: string
}) {
  const t = useT()
  const f = useFormatters()
  const { toast } = useToast()

  const [selected, setSelected] = React.useState<SimulatableAttack[]>(["deauth", "disas"])
  const [all, setAll] = React.useState(false)
  const [count, setCount] = React.useState(50)
  const [intensity, setIntensity] = React.useState<SimulateIntensity>("burst")
  const [running, setRunning] = React.useState(false)
  const [result, setResult] = React.useState<Result | null>(null)

  const rows = React.useMemo(
    () => (result?.kind === "ok" ? summaryRows(result.summary) : []),
    [result]
  )
  const canRun = !running && (all || selected.length > 0)

  const toggle = (cls: SimulatableAttack) =>
    setSelected((prev) => (prev.includes(cls) ? prev.filter((c) => c !== cls) : [...prev, cls]))

  const clamp = (n: number) =>
    Math.max(
      SIMULATE_MIN_COUNT,
      Math.min(SIMULATE_MAX_COUNT, Number.isFinite(n) ? Math.round(n) : SIMULATE_MIN_COUNT)
    )

  const run = async () => {
    if (!canRun) return
    setRunning(true)
    const outcome = await runSimulation({ attacks: all ? "all" : selected, count, intensity })
    setRunning(false)

    if (outcome.ok) {
      const persisted = totalPersisted(outcome.summary)
      setResult({ kind: "ok", summary: outcome.summary, note: outcome.note })
      toast({
        title: t("admin.simulate.done"),
        description:
          persisted > 0
            ? t("admin.simulate.storedDetail", { n: f.number(persisted) })
            : t("admin.simulate.storedNothing"),
      })
      onSimulated?.()
    } else {
      setResult({
        kind: "error",
        title: outcome.title,
        message: outcome.message,
        detail: outcome.detail,
      })
      toast({
        variant: "destructive",
        title: t(outcome.title.key, outcome.title.vars),
        description: t(outcome.message.key, outcome.message.vars),
      })
    }
  }

  // Phrased as `Classes: 2 · Frames: 25 · Burst` rather than `2 classes`, so no
  // word has to agree in number with a figure the operator can set to 1.
  const selectionLabel = t("admin.simulate.selection", {
    classes: all ? t("common.all") : f.number(selected.length),
    count: f.number(count),
    intensity: t(intensity === "burst" ? "admin.simulate.burst" : "admin.simulate.trickle"),
  })

  return (
    <Panel
      label={t("admin.simulate.title")}
      title={t("admin.simulate.subtitle")}
      aria-label={t("admin.simulate.aria")}
      className={className}
    >
      <div className="flex flex-col gap-4">
        {/* ---- classes ---------------------------------------------------- */}
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between gap-3">
            <span className="hs-label">{t("admin.simulate.classes")}</span>
            <label className="text-ink-0 flex cursor-pointer items-center gap-2 text-sm">
              <Checkbox checked={all} onCheckedChange={(v) => setAll(v === true)} />
              {t("admin.simulate.allClasses")}
              <span className="text-ink-2 text-xs">({t("admin.simulate.backendPicks")})</span>
            </label>
          </div>

          <div
            className={cn(
              // One column on a phone. At two columns a 320px viewport left
              // about 70px for the label and `Disassociation` truncated to
              // `Disassocia…`, which is the one word on this panel an operator
              // has to be able to tell apart from `Deauth`.
              "grid grid-cols-1 gap-2 transition-opacity sm:grid-cols-2 lg:grid-cols-3",
              all && "pointer-events-none opacity-40"
            )}
            aria-disabled={all}
          >
            {SIMULATABLE_ATTACKS.map((cls) => {
              const active = selected.includes(cls)
              return (
                <label
                  key={cls}
                  className={cn(
                    "border-rule flex cursor-pointer items-center gap-2 rounded-md border px-2.5 py-1.5 transition-colors",
                    active ? "border-rule-soft bg-paper-2" : "hover:border-rule-soft"
                  )}
                >
                  <Checkbox checked={active} disabled={all} onCheckedChange={() => toggle(cls)} />
                  <span
                    aria-hidden="true"
                    className="size-2 shrink-0 rounded-full"
                    style={{ background: attackColorVar(cls) }}
                  />
                  {/* Class identifiers are Latin in both locales. */}
                  <span className="text-ink-0 hs-ltr truncate text-sm">{attackLabels[cls]}</span>
                </label>
              )
            })}
          </div>

          {all && <p className="text-ink-2 max-w-[68ch] text-xs">{t("admin.simulate.allNote")}</p>}
        </div>

        {/* ---- count + intensity ------------------------------------------ */}
        <div className="grid gap-4 md:grid-cols-2">
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between gap-3">
              <label htmlFor="sim-count" className="hs-label">
                {t("admin.simulate.count")}
              </label>
              <Input
                id="sim-count"
                type="number"
                min={SIMULATE_MIN_COUNT}
                max={SIMULATE_MAX_COUNT}
                value={count}
                onChange={(e) => setCount(clamp(Number(e.target.value)))}
                className="hs-num h-7 w-20 text-end"
              />
            </div>
            <input
              type="range"
              aria-label={t("admin.simulate.count")}
              min={SIMULATE_MIN_COUNT}
              max={SIMULATE_MAX_COUNT}
              step={1}
              value={count}
              onChange={(e) => setCount(clamp(Number(e.target.value)))}
              // Direction is inherited, not pinned. A range input is chrome
              // rather than a spatial artefact, and every engine already mirrors
              // it under RTL so the minimum sits on the reading-start edge. That
              // keeps it agreeing with the preset row beneath, which ascends
              // 25 → 500 in reading order; pinning the track LTR left the two
              // controls counting in opposite directions on the same Arabic page.
              className="accent-accent w-full"
            />
            <div className="flex flex-wrap items-center gap-1.5">
              {SIMULATE_COUNT_PRESETS.map((p) => (
                <Button
                  key={p}
                  size="sm"
                  variant={count === p ? "outline" : "ghost"}
                  onClick={() => setCount(p)}
                  className="hs-num"
                >
                  {f.number(p)}
                </Button>
              ))}
              <span className="hs-label ms-auto">
                {t("admin.simulate.max", { n: f.number(SIMULATE_MAX_COUNT) })}
              </span>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <span className="hs-label">{t("admin.simulate.intensity")}</span>
            <div className="grid grid-cols-2 gap-2">
              {(["burst", "trickle"] as const).map((mode) => (
                <Button
                  key={mode}
                  variant={intensity === mode ? "outline" : "ghost"}
                  onClick={() => setIntensity(mode)}
                >
                  {t(mode === "burst" ? "admin.simulate.burst" : "admin.simulate.trickle")}
                </Button>
              ))}
            </div>
            <p className="text-ink-2 text-xs">
              {t(intensity === "burst" ? "admin.simulate.burstHint" : "admin.simulate.trickleHint")}
            </p>
          </div>
        </div>

        {/* ---- action ------------------------------------------------------ */}
        <div className="flex flex-wrap items-center gap-3">
          <Button onClick={run} disabled={!canRun}>
            {running ? (
              <Loader2 className="animate-spin" aria-hidden="true" />
            ) : (
              <Zap aria-hidden="true" />
            )}
            {running ? t("admin.simulate.running") : t("admin.simulate.run")}
          </Button>
          <span className="hs-label">{selectionLabel}</span>
        </div>

        {/* ---- result ------------------------------------------------------ */}
        {result?.kind === "error" && (
          <div className="border-rule-soft bg-paper-2 flex flex-col gap-1 rounded-md border p-3">
            <span className="text-sev-high text-sm font-medium">
              {t(result.title.key, result.title.vars)}
            </span>
            <span className="text-ink-1 text-xs">{t(result.message.key, result.message.vars)}</span>
            {/* FastAPI's own `detail`, verbatim. It is the server describing what
                it rejected; translating a message we did not write would be
                inventing words for it. Pinned LTR since it is machine prose. */}
            {result.detail && (
              <span className="hs-ltr text-ink-2 font-mono text-xs">{result.detail}</span>
            )}
          </div>
        )}

        {result?.kind === "ok" && (
          <div className="border-rule-soft flex flex-col gap-2 rounded-md border p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="hs-label">{t("admin.simulate.output")}</span>
              {result.summary.model_version && (
                <span className="hs-ltr text-ink-2 font-mono text-xs">
                  {String(result.summary.model_version)}
                </span>
              )}
            </div>

            {result.note && (
              <p className="text-sev-high text-xs">{t(result.note.key, result.note.vars)}</p>
            )}

            {rows.length === 0 ? (
              <p className="text-ink-1 text-xs">{t("admin.simulate.storedNothing")}</p>
            ) : (
              <div className="flex flex-col">
                <div className="border-rule grid grid-cols-[minmax(0,1fr)_4.25rem_4.25rem] gap-3 border-b pb-2">
                  <span className="hs-label">{t("admin.simulate.column.class")}</span>
                  <span className="hs-label text-end">{t("admin.simulate.column.detected")}</span>
                  <span className="hs-label text-end">{t("admin.simulate.column.stored")}</span>
                </div>
                {rows.map((r) => (
                  <div
                    key={r.key}
                    className="border-rule grid grid-cols-[minmax(0,1fr)_4.25rem_4.25rem] items-center gap-3 border-b py-2 last:border-0"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span
                        aria-hidden="true"
                        className="size-2 shrink-0 rounded-full"
                        style={{ background: r.color }}
                      />
                      <span className="text-ink-0 hs-ltr truncate text-sm">{r.label}</span>
                      {/* The model may return a different label than requested;
                          when it does, say so rather than quietly relabelling. */}
                      {r.topLabel !== r.label && (
                        <StatusPill tone="neutral" className="hs-ltr">
                          {r.topLabel}
                        </StatusPill>
                      )}
                    </span>
                    <span className="hs-num text-ink-2 text-end text-sm">{f.number(r.detected)}</span>
                    <span className="hs-num text-ink-0 text-end text-sm">{f.number(r.persisted)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </Panel>
  )
}

export default SimulatePanel
