"use client"

/**
 * Hidden operator console at /admin. Deliberately unlinked from the navbar and
 * every page — reachable only by typing the URL. Hosts the simulate lever and
 * the backend's own account of itself, kept off the public dashboard.
 */
import { useState } from "react"
import Link from "next/link"
import { ArrowRight } from "lucide-react"
import { useHealth } from "@/hooks/use-health"
import { ConnectionBanner, ConnectionStatus } from "@/components/connection-status"
import { SimulatePanel } from "@/components/simulate-panel"

function Row({ label, value, tone }: { label: string; value: string; tone?: "ok" | "warn" }) {
  return (
    <div className="flex items-center justify-between gap-4 py-2 border-b border-white/5 last:border-0">
      <span className="text-sm text-gray-400">{label}</span>
      <span
        className={
          "text-sm font-mono " +
          (tone === "ok" ? "text-cyan-300" : tone === "warn" ? "text-amber-300" : "text-white/90")
        }
      >
        {value}
      </span>
    </div>
  )
}

export default function AdminPage() {
  const { state, health, lastOkAt, refresh } = useHealth()
  const [runs, setRuns] = useState(0)

  const models = health?.models ?? null
  const modelList = models
    ? Object.entries(models)
        .filter(([, present]) => present)
        .map(([name]) => name)
        .join(", ") || "none present"
    : "—"

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white">Control</h1>
          <p className="text-gray-400 mt-1">
            Push traffic through the live detection model and watch it land on the dashboard.
          </p>
        </div>
        <ConnectionStatus state={state} lastOkAt={lastOkAt} onRetry={refresh} />
      </div>

      <ConnectionBanner state={state} lastOkAt={lastOkAt} />

      <SimulatePanel onSimulated={() => { setRuns((n) => n + 1); refresh() }} />

      <section className="rounded-2xl bg-[#0F1629] border border-white/5 p-4">
        <h3 className="text-white font-semibold mb-2">Backend</h3>
        <Row label="Status" value={health?.status ?? (state === "offline" ? "unreachable" : "—")} />
        <Row
          label="Database"
          value={health?.database === true ? "reachable" : health?.database === false ? "not answering" : "—"}
          tone={health?.database === true ? "ok" : health?.database === false ? "warn" : undefined}
        />
        <Row label="Stored packets" value={health?.packets != null ? String(health.packets) : "—"} />
        <Row label="Model in service" value={health?.model_version ?? "—"} />
        <Row label="Model artefacts" value={modelList} />
        <Row label="API version" value={health?.version ?? "—"} />
        {runs > 0 && (
          <p className="text-xs text-gray-500 mt-3">
            {runs} simulation{runs === 1 ? "" : "s"} run this session.
          </p>
        )}
        <Link
          href="/dashboard"
          className="mt-4 inline-flex items-center gap-1.5 text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
        >
          Open the dashboard
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </section>
    </div>
  )
}
