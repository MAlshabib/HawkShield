/**
 * Client contract for `POST /admin/purge` — the operator's "delete all
 * detections" lever.
 *
 * The backend empties the `packets` table (or, in `simulated` scope, only the
 * rows tagged `raw.sim`), so every count on every surface returns to zero. It is
 * destructive and deliberately guarded by a fixed sentinel the operator must
 * type, so this module never fires without one and never throws on the way back:
 * every failure becomes a calm, localised message, exactly as `lib/simulate.ts`
 * models it.
 */
import { ApiError, apiPostJson } from "@/lib/api"
import type { TranslationKey, TranslationVars } from "@/lib/i18n/types"

/**
 * The exact word the operator types and the client sends. Fixed, Latin in every
 * locale, and mirrored on the server (`PURGE_SENTINEL` in
 * `backend/app/routers/admin.py`). Anything else is a 400 that deletes nothing.
 */
export const PURGE_SENTINEL = "DELETE"

/** `all` empties the table; `simulated` deletes only `raw.sim` rows. */
export type PurgeScope = "all" | "simulated"

/** The `{deleted, remaining}` the endpoint returns on success. */
export type PurgeResult = { deleted: number; remaining: number }

/** A localisable message: a dictionary key plus whatever it interpolates. */
export type PurgeMessage = { key: TranslationKey; vars?: TranslationVars }

export type PurgeOutcome =
  | { ok: true; result: PurgeResult }
  | {
      ok: false
      title: PurgeMessage
      message: PurgeMessage
      /** Verbatim `detail` from the server, when it sent one. Never translated. */
      detail: string | null
    }

/** Pull FastAPI's `{"detail": "..."}` out of an error body without throwing. */
function detailOf(body: string): string {
  if (!body) return ""
  try {
    const parsed = JSON.parse(body) as { detail?: unknown }
    const d = parsed?.detail
    if (typeof d === "string") return d
    if (d != null) return JSON.stringify(d)
  } catch {
    /* not JSON — fall through to the raw text */
  }
  return body.slice(0, 200)
}

/**
 * Fire a purge and translate every failure mode into a calm, operator-readable
 * message. Never throws.
 */
export async function runPurge(scope: PurgeScope = "all"): Promise<PurgeOutcome> {
  try {
    const result = await apiPostJson<PurgeResult>("/admin/purge", {
      confirm: PURGE_SENTINEL,
      scope,
    })
    return {
      ok: true,
      result: {
        deleted: Number(result?.deleted ?? 0),
        remaining: Number(result?.remaining ?? 0),
      },
    }
  } catch (e) {
    if (e instanceof ApiError) {
      const detail = detailOf(e.body) || null
      if (e.status === 403 || e.status === 404) {
        return {
          ok: false,
          title: { key: "admin.purge.error.disabled.title" },
          message: { key: "admin.purge.error.disabled.body" },
          detail,
        }
      }
      if (e.status === 400 || e.status === 422) {
        return {
          ok: false,
          title: { key: "admin.purge.error.rejected.title" },
          message: { key: "admin.purge.error.rejected.body" },
          detail,
        }
      }
      return {
        ok: false,
        title: { key: "admin.purge.error.http.title", vars: { status: e.status } },
        message: { key: "admin.purge.error.http.body" },
        detail: detail || e.statusText || null,
      }
    }
    return {
      ok: false,
      title: { key: "admin.purge.error.unreachable.title" },
      message: { key: "admin.purge.error.unreachable.body" },
      detail: null,
    }
  }
}
