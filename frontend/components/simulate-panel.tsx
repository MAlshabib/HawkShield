"use client"

/**
 * Operator control for `POST /simulate`.
 *
 * This is the demo's plan B: when the capture source (the Pi) is not feeding
 * the database, the operator pushes crafted traffic through the *real* model
 * from here and the dashboard repopulates with genuine model output. It only
 * needs the API — so it stays enabled even while the rest of the page is in its
 * reconnecting state.
 */
import { useMemo, useState } from "react"
import { ChevronDown, Loader2, Zap } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { useToast } from "@/hooks/use-toast"
import { cn } from "@/lib/utils"
import { attackColors, attackLabels } from "@/lib/colors"
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
  type SimulateSummary,
} from "@/lib/simulate"

type Result =
  | { kind: "ok"; summary: SimulateSummary; note: string | null; at: number }
  | { kind: "error"; title: string; message: string; at: number }

export function SimulatePanel({
  onSimulated,
  className,
  defaultOpen = true,
}: {
  /** Called after a successful run so the host page can pull the new rows. */
  onSimulated?: () => void
  className?: string
  defaultOpen?: boolean
}) {
  const { toast } = useToast()
  const [open, setOpen] = useState(defaultOpen)
  const [selected, setSelected] = useState<SimulatableAttack[]>(["deauth", "disas"])
  const [all, setAll] = useState(false)
  const [count, setCount] = useState(50)
  const [intensity, setIntensity] = useState<SimulateIntensity>("burst")
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<Result | null>(null)

  const rows = useMemo(() => (result?.kind === "ok" ? summaryRows(result.summary) : []), [result])
  const canRun = !running && (all || selected.length > 0)

  const toggle = (cls: SimulatableAttack) =>
    setSelected((prev) => (prev.includes(cls) ? prev.filter((c) => c !== cls) : [...prev, cls]))

  const clampCount = (n: number) =>
    Math.max(
      SIMULATE_MIN_COUNT,
      Math.min(SIMULATE_MAX_COUNT, Number.isFinite(n) ? Math.round(n) : SIMULATE_MIN_COUNT),
    )

  const run = async () => {
    if (!canRun) return
    setRunning(true)
    const outcome = await runSimulation({
      attacks: all ? "all" : selected,
      count,
      intensity,
    })
    setRunning(false)

    if (outcome.ok) {
      const persisted = totalPersisted(outcome.summary)
      const classes = summaryRows(outcome.summary).length
      setResult({ kind: "ok", summary: outcome.summary, note: outcome.note, at: Date.now() })
      toast({
        title: "Simulation complete",
        description:
          (persisted > 0
            ? `${persisted} detection${persisted === 1 ? "" : "s"} stored across ${classes} class${
                classes === 1 ? "" : "es"
              }.`
            : "The model ran but stored nothing — see the breakdown below.") +
          (outcome.note ? ` ${outcome.note}` : ""),
        className: "border border-cyan-500/40 bg-[#040A14]/90",
      })
      onSimulated?.()
    } else {
      setResult({ kind: "error", title: outcome.title, message: outcome.message, at: Date.now() })
      toast({
        title: outcome.title,
        description: outcome.message,
        className: "border border-amber-500/40 bg-[#040A14]/90",
      })
    }
  }

  return (
    <section
      className={cn("rounded-2xl bg-[#0F1629] border border-white/5 overflow-hidden", className)}
      aria-label="Attack simulation"
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 p-4 text-left hover:bg-white/[0.02] transition-colors"
      >
        <span className="flex items-center gap-2">
          <Zap className="h-4 w-4 text-cyan-400" aria-hidden />
          <span className="text-white font-semibold">Simulate Attacks</span>
          <span className="hidden sm:inline text-xs text-gray-500">
            crafted traffic through the live detection model
          </span>
        </span>
        <ChevronDown className={cn("h-4 w-4 text-gray-400 transition-transform", open && "rotate-180")} />
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-4 border-t border-white/5 pt-4">
          {/* Classes */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-400">Attack classes</span>
              <label className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                <Checkbox
                  checked={all}
                  onCheckedChange={(v) => setAll(v === true)}
                  className="border-cyan-500/40 data-[state=checked]:bg-cyan-500 data-[state=checked]:border-cyan-500"
                />
                All
                <span className="text-xs text-gray-500">(backend picks)</span>
              </label>
            </div>

            <div
              className={cn(
                "grid grid-cols-2 sm:grid-cols-3 gap-2 transition-opacity",
                all && "opacity-40 pointer-events-none",
              )}
              aria-disabled={all}
            >
              {SIMULATABLE_ATTACKS.map((cls) => {
                const active = selected.includes(cls)
                return (
                  <label
                    key={cls}
                    className={cn(
                      "flex items-center gap-2 rounded-xl border px-3 py-2 cursor-pointer transition-colors",
                      active ? "border-cyan-500/30 bg-cyan-400/5" : "border-white/5 hover:border-white/10",
                    )}
                  >
                    <Checkbox
                      checked={active}
                      disabled={all}
                      onCheckedChange={() => toggle(cls)}
                      className="border-white/20 data-[state=checked]:bg-cyan-500 data-[state=checked]:border-cyan-500"
                    />
                    <span
                      className="h-2.5 w-2.5 rounded-full shrink-0"
                      style={{ background: attackColors[cls] }}
                      aria-hidden
                    />
                    <span className="text-sm text-white/90 truncate">{attackLabels[cls]}</span>
                  </label>
                )
              })}
            </div>
            {all && (
              <p className="text-xs text-gray-500">
                &quot;All&quot; lets the backend decide which classes it can actually produce — the result summary
                below is the source of truth.
              </p>
            )}
          </div>

          {/* Count + intensity */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label htmlFor="sim-count" className="text-sm text-gray-400">
                  Packets
                </label>
                <input
                  id="sim-count-number"
                  type="number"
                  min={SIMULATE_MIN_COUNT}
                  max={SIMULATE_MAX_COUNT}
                  value={count}
                  onChange={(e) => setCount(clampCount(Number(e.target.value)))}
                  className="w-20 rounded-md border border-white/10 bg-[#0B1120] px-2 py-1 text-right text-sm text-white outline-none focus:border-cyan-500/40"
                />
              </div>
              <input
                id="sim-count"
                type="range"
                min={SIMULATE_MIN_COUNT}
                max={SIMULATE_MAX_COUNT}
                step={1}
                value={count}
                onChange={(e) => setCount(clampCount(Number(e.target.value)))}
                className="w-full accent-cyan-400"
              />
              <div className="flex flex-wrap gap-1.5">
                {SIMULATE_COUNT_PRESETS.map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setCount(p)}
                    className={cn(
                      "rounded-md border px-2 py-0.5 text-xs transition-colors",
                      count === p
                        ? "border-cyan-500/40 text-cyan-300 bg-cyan-400/10"
                        : "border-white/10 text-gray-400 hover:text-cyan-300",
                    )}
                  >
                    {p}
                  </button>
                ))}
                <span className="ml-auto text-xs text-gray-600">max {SIMULATE_MAX_COUNT}</span>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-sm text-gray-400">Intensity</span>
              <div className="grid grid-cols-2 gap-2">
                {(["burst", "trickle"] as const).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setIntensity(mode)}
                    className={cn(
                      "rounded-xl border px-3 py-2 text-sm capitalize transition-colors",
                      intensity === mode
                        ? "border-cyan-500/30 bg-cyan-400/5 text-cyan-300"
                        : "border-white/5 text-gray-400 hover:border-white/10",
                    )}
                  >
                    {mode}
                  </button>
                ))}
              </div>
              <p className="text-xs text-gray-500">
                {intensity === "burst"
                  ? "All packets injected at once — fastest way to repopulate the view."
                  : "Spread over time — looks like live traffic arriving."}
              </p>
            </div>
          </div>

          {/* Action */}
          <div className="flex items-center gap-3">
            <Button
              onClick={run}
              disabled={!canRun}
              className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold"
            >
              {running ? (
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              ) : (
                <Zap className="h-4 w-4" aria-hidden />
              )}
              {running ? "Simulating…" : "Simulate"}
            </Button>
            <span className="text-xs text-gray-500">
              {all ? "All classes" : `${selected.length} class${selected.length === 1 ? "" : "es"}`} · {count} packets ·{" "}
              {intensity}
            </span>
          </div>

          {/* Result */}
          {result?.kind === "error" && (
            <div className="rounded-xl border border-amber-500/20 bg-amber-400/5 px-4 py-3">
              <div className="text-sm font-medium text-amber-200">{result.title}</div>
              <div className="text-xs text-amber-200/70 mt-1">{result.message}</div>
            </div>
          )}

          {result?.kind === "ok" && (
            <div className="rounded-xl border border-white/5 bg-[#0B1120] px-4 py-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-white/90">Model output</span>
                <span className="text-xs text-gray-500">
                  {typeof result.summary.count === "number" ? `${result.summary.count} packets · ` : ""}
                  {new Date(result.at).toLocaleTimeString()}
                </span>
              </div>
              {result.note && <div className="text-xs text-amber-300/80">{result.note}</div>}
              {rows.length === 0 ? (
                <div className="text-xs text-gray-400">
                  The run completed but the model stored no detections for this selection.
                </div>
              ) : (
                <div className="space-y-1">
                  <div className="grid grid-cols-[1fr_auto_auto] gap-3 text-[11px] uppercase tracking-wide text-gray-500">
                    <span>Class</span>
                    <span className="w-16 text-right">Detected</span>
                    <span className="w-16 text-right">Stored</span>
                  </div>
                  {rows.map((r) => (
                    <div
                      key={r.key}
                      className="grid grid-cols-[1fr_auto_auto] gap-3 items-center text-sm text-white/90"
                    >
                      <span className="flex items-center gap-2 min-w-0">
                        <span
                          className="h-2.5 w-2.5 rounded-full shrink-0"
                          style={{ background: r.color }}
                          aria-hidden
                        />
                        <span className="truncate">{r.label}</span>
                      </span>
                      <span className="w-16 text-right tabular-nums">{r.detected}</span>
                      <span className="w-16 text-right tabular-nums text-cyan-300">{r.persisted}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  )
}

export default SimulatePanel
