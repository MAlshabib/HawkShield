/**
 * Client contract for `POST /simulate` — the operator's "plan B" lever.
 *
 * The backend crafts / replays traffic, runs it through the REAL detection
 * model and persists whatever the model predicted, tagged as simulated. It is
 * therefore *not* a fake-data generator: the summary it returns is ground truth
 * about what the model actually did, which is why nothing here assumes which
 * classes will come back. Render the summary, never a hardcoded class list.
 */
import { attackColors, attackLabels, type AttackType } from "@/lib/colors"
import { ApiError, apiPostJson } from "@/lib/api"
import type { TranslationKey, TranslationVars } from "@/lib/i18n/types"

/**
 * Classes the backend can craft individually. `Normal` is never persisted, and
 * SSDP / Kr00k are only reachable through the "all" preset (the backend decides
 * what it can actually produce) — so they are deliberately absent here.
 */
export const SIMULATABLE_ATTACKS = [
  "deauth",
  "disas",
  "reassoc",
  "rogueap",
  "krack",
  "evil_twin",
] as const satisfies readonly AttackType[]

export type SimulatableAttack = (typeof SIMULATABLE_ATTACKS)[number]

/** Mirrors the backend's own ceiling; the server is still the authority. */
export const SIMULATE_MAX_COUNT = 500
export const SIMULATE_MIN_COUNT = 1
export const SIMULATE_COUNT_PRESETS = [25, 50, 100, 250, SIMULATE_MAX_COUNT]

export type SimulateIntensity = "burst" | "trickle"

export type SimulateRequest = {
  /** Explicit class list, or the string "all" to let the backend choose. */
  attacks: SimulatableAttack[] | "all"
  count: number
  intensity: SimulateIntensity
}

/** One class's outcome, as `/simulate` reports it under `per_class`. */
export type SimulatePerClass = {
  requested?: number
  frames_pushed?: number
  detected?: number
  persisted?: number
  top_label?: string
  labels?: Record<string, number>
}

export type SimulateSummary = {
  sim_batch?: string
  model_version?: string
  intensity?: string
  classes?: string[]
  /** Frames requested per class; the server clamps this to its own ceiling. */
  count_per_class?: number
  /** Rows actually written to the DB across all classes. */
  total_persisted?: number
  /** Per requested class: what the model detected and what was persisted. */
  per_class?: Record<string, SimulatePerClass>
  [k: string]: unknown
}

/** A class row for rendering a summary, with a swatch when we know the class. */
export type SummaryRow = { key: string; label: string; color: string; detected: number; persisted: number; topLabel: string }

const KNOWN_COLORS = attackColors as Record<string, string>
const KNOWN_LABELS = attackLabels as Record<string, string>

/** Normalise a label the backend returned into our colour/label vocabulary. */
export function classKey(raw: string): string {
  return String(raw).trim().toLowerCase().replace(/[\s-]+/g, "_")
}

export function classColor(raw: string): string {
  return KNOWN_COLORS[classKey(raw)] ?? KNOWN_COLORS.other
}

export function classLabel(raw: string): string {
  return KNOWN_LABELS[classKey(raw)] ?? String(raw)
}

/**
 * Fold `detected` + `persisted` into one sorted table. Driven entirely by the
 * keys the response carried, so a class we have never heard of still renders.
 */
export function summaryRows(summary: SimulateSummary | null): SummaryRow[] {
  if (!summary) return []
  // The response is keyed by the requested class under `per_class`; each entry
  // carries its own detected/persisted counts. A model may return a different
  // label than requested (e.g. RogueAP -> a couple of Disas), so the row key is
  // the requested class and `topLabel` records what the model actually called it.
  const per = (summary.per_class ?? {}) as Record<string, SimulatePerClass>
  return Object.entries(per)
    .map(([k, v]) => ({
      key: classKey(k),
      label: classLabel(k),
      color: classColor(k),
      detected: Number(v?.detected ?? 0),
      persisted: Number(v?.persisted ?? 0),
      topLabel: v?.top_label ? classLabel(v.top_label) : classLabel(k),
    }))
    .filter((r) => r.detected > 0 || r.persisted > 0)
    .sort((a, b) => b.detected - a.detected || a.label.localeCompare(b.label))
}

export function totalPersisted(summary: SimulateSummary | null): number {
  if (summary && typeof summary.total_persisted === "number") return summary.total_persisted
  return summaryRows(summary).reduce((n, r) => n + r.persisted, 0)
}

/**
 * A localisable message: a key from the dictionary plus whatever it interpolates.
 *
 * The status -> outcome mapping below is the part worth keeping, and it is
 * unchanged. What used to travel with it was English prose, which meant the
 * simulate panel was the one surface in the product that could not speak Arabic.
 * Outcomes now carry keys, and the page calls `useT()` on them like everything
 * else. `detail` stays a raw string on purpose: it is FastAPI's own words about
 * what it rejected, and inventing an Arabic translation of a server message we
 * did not write would be fabrication.
 */
export type SimulateMessage = { key: TranslationKey; vars?: TranslationVars }

export type SimulateOutcome =
  | { ok: true; summary: SimulateSummary; note: SimulateMessage | null }
  | {
      ok: false
      title: SimulateMessage
      message: SimulateMessage
      /** Verbatim `detail` from the server, when it sent one. Never translated. */
      detail: string | null
      retryable: boolean
    }

/**
 * Pull FastAPI's `{"detail": ...}` out of an error body without throwing.
 * `detail` is a string for HTTPException and a list of `{loc, msg}` objects for
 * a 422 — flatten the latter into something an operator can read at a glance.
 */
function detailOf(body: string): string {
  if (!body) return ""
  try {
    const parsed = JSON.parse(body) as { detail?: unknown }
    const d = parsed?.detail
    if (typeof d === "string") return d
    if (Array.isArray(d)) {
      const parts = d
        .map((item) => {
          const e = item as { loc?: unknown[]; msg?: unknown }
          const field = Array.isArray(e?.loc) ? e.loc.filter((x) => x !== "body").join(".") : ""
          const msg = typeof e?.msg === "string" ? e.msg : ""
          return field && msg ? `${field}: ${msg}` : msg || field
        })
        .filter(Boolean)
      if (parts.length) return parts.join("; ")
    }
    if (d != null) return JSON.stringify(d)
  } catch {
    /* not JSON — fall through to the raw text */
  }
  return body.slice(0, 200)
}

/**
 * Fire a simulation and translate every failure mode into a calm, operator
 * readable message. Never throws.
 */
export async function runSimulation(req: SimulateRequest): Promise<SimulateOutcome> {
  const count = Math.max(SIMULATE_MIN_COUNT, Math.min(SIMULATE_MAX_COUNT, Math.round(req.count)))
  try {
    const summary = await apiPostJson<SimulateSummary>("/simulate", { ...req, count })
    const served = Number(summary?.count_per_class)
    const note: SimulateMessage | null =
      Number.isFinite(served) && served > 0 && served < count
        ? { key: "admin.simulate.capped", vars: { served, requested: count } }
        : null
    return { ok: true, summary: summary ?? {}, note }
  } catch (e) {
    if (e instanceof ApiError) {
      const detail = detailOf(e.body) || null
      if (e.status === 503) {
        return {
          ok: false,
          title: { key: "admin.simulate.error.noModel.title" },
          message: { key: "admin.simulate.error.noModel.body" },
          detail,
          retryable: true,
        }
      }
      if (e.status === 403 || e.status === 404) {
        return {
          ok: false,
          title: { key: "admin.simulate.error.disabled.title" },
          message: { key: "admin.simulate.error.disabled.body" },
          detail,
          retryable: false,
        }
      }
      if (e.status === 400 || e.status === 422) {
        return {
          ok: false,
          title: { key: "admin.simulate.error.rejected.title" },
          message: { key: "admin.simulate.error.rejected.body", vars: { n: SIMULATE_MAX_COUNT } },
          detail,
          retryable: false,
        }
      }
      return {
        ok: false,
        title: { key: "admin.simulate.error.http.title", vars: { status: e.status } },
        message: { key: "admin.simulate.error.http.body" },
        detail: detail || e.statusText || null,
        retryable: true,
      }
    }
    return {
      ok: false,
      title: { key: "admin.simulate.error.unreachable.title" },
      message: { key: "admin.simulate.error.unreachable.body" },
      detail: null,
      retryable: true,
    }
  }
}
