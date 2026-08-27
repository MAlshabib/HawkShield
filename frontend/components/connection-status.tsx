"use client"

/**
 * The quiet half of the failover story: a small chip that says what the link is
 * doing without shouting about it. It never blanks the page and never invents
 * numbers — when the backend is away the dashboard keeps the last good data and
 * this chip explains why it stopped moving.
 */
import { Loader2, RefreshCw, Wifi } from "lucide-react"
import { cn } from "@/lib/utils"
import type { ConnectionState } from "@/hooks/use-health"

function agoLabel(at: number | null): string {
  if (!at) return "no data yet"
  const secs = Math.max(0, Math.round((Date.now() - at) / 1000))
  if (secs < 60) return `${secs}s ago`
  const mins = Math.round(secs / 60)
  if (mins < 60) return `${mins}m ago`
  return `${Math.round(mins / 60)}h ago`
}

export function ConnectionStatus({
  state,
  lastOkAt,
  onRetry,
  className,
}: {
  state: ConnectionState
  lastOkAt: number | null
  onRetry?: () => void
  className?: string
}) {
  const healthy = state === "online"
  const unknown = state === "unknown"

  const tone = healthy
    ? "border-cyan-500/30 text-cyan-300 bg-cyan-400/5"
    : unknown
      ? "border-white/10 text-gray-400 bg-white/5"
      : "border-amber-500/30 text-amber-300 bg-amber-400/5"

  const text = healthy
    ? "Live"
    : unknown
      ? "Connecting…"
      : state === "degraded"
        ? "Reconnecting to storage…"
        : "Reconnecting…"

  const detail = healthy
    ? null
    : state === "degraded"
      ? "API is up, its database is not answering. Showing the last good data."
      : state === "offline"
        ? `Backend not answering. Showing the last good data (${agoLabel(lastOkAt)}).`
        : null

  return (
    <div className={cn("flex items-center gap-2", className)}>
      <span
        title={detail ?? "Backend healthy"}
        className={cn(
          "inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition-colors",
          tone,
        )}
      >
        {healthy ? (
          <Wifi className="h-3.5 w-3.5" />
        ) : (
          <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
        )}
        {text}
      </span>
      {!healthy && !unknown && onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-1 rounded-full border border-white/10 px-2.5 py-1 text-xs text-gray-400 hover:text-cyan-300 hover:border-cyan-500/30 transition-colors"
        >
          <RefreshCw className="h-3 w-3" />
          Retry
        </button>
      )}
    </div>
  )
}

/** One-line banner for the degraded state. Calm on purpose. */
export function ConnectionBanner({ state, lastOkAt }: { state: ConnectionState; lastOkAt: number | null }) {
  if (state === "online" || state === "unknown") return null
  return (
    <div className="rounded-2xl border border-amber-500/20 bg-amber-400/5 px-4 py-3 text-sm text-amber-200/90 flex items-center gap-3">
      <Loader2 className="h-4 w-4 animate-spin shrink-0" aria-hidden />
      <span>
        {state === "degraded"
          ? "Storage is not answering — the view below is the last data we received and will refresh by itself."
          : `Waiting for the backend — the view below is the last data we received (${agoLabel(lastOkAt)}) and will refresh by itself.`}{" "}
        <span className="text-amber-200/70">Simulation still works if the API is reachable.</span>
      </span>
    </div>
  )
}
