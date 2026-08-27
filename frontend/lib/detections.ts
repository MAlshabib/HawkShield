/**
 * Domain helpers shared by the landing page and the ops console.
 *
 * Three pieces of knowledge live here rather than being retyped per module,
 * because each one has already been a bug once:
 *
 * 1. The label the model emits (`(Re)Assoc`, `Evil_Twin`, `RogueAP`) is not the
 *    key `lib/colors.ts` is written in. `lib/simulate.classKey` lower-cases and
 *    swaps separators, which is enough for the simulate panel's own vocabulary
 *    but turns `(Re)Assoc` into `(re)assoc` — an unknown class that silently
 *    falls to the grey `other` swatch on a dashboard.
 * 2. `packets.ts` is stored naive-UTC (`backend/app/models.py:_utcnow`) and
 *    serialised without a `Z`. `new Date("2026-08-27T18:20:11")` is parsed as
 *    *browser-local* time, so every rendered timestamp is wrong by the reader's
 *    offset. Every API timestamp must be stamped UTC before it is parsed.
 * 3. RadioTap reports a frequency; operators talk in channels.
 */
import { attackTypes, type AttackType } from "@/lib/colors"

/**
 * Labels whose alphanumeric squash does not already equal a key in
 * `attackColors`. Everything else round-trips: `(Re)Assoc` -> `reassoc`,
 * `RogueAP` -> `rogueap`, `SSDP` -> `ssdp`.
 */
const LABEL_ALIASES: Record<string, AttackType> = {
  eviltwin: "evil_twin",
  twin: "evil_twin",
  rogue: "rogueap",
  reassociation: "reassoc",
  assoc: "reassoc",
  disassoc: "disas",
  disassociation: "disas",
  deauthentication: "deauth",
}

const KNOWN = new Set<string>(attackTypes)

/**
 * Narrow whatever the API called a class into our vocabulary. Anything
 * unrecognised becomes `other` — a class the model has never emitted before
 * must not be able to take a dashboard down, and it must not be dropped either.
 */
export function toAttackType(raw: string | null | undefined): AttackType {
  if (!raw) return "other"
  const squashed = String(raw).toLowerCase().replace(/[^a-z0-9]/g, "")
  if (KNOWN.has(squashed)) return squashed as AttackType
  return LABEL_ALIASES[squashed] ?? "other"
}

/**
 * Stamp a bare backend timestamp as UTC so `toDate()` does not read it in the
 * browser's zone. Values that already carry an offset (or that are not strings)
 * are returned untouched.
 */
export function apiTime(value: string | number | null | undefined): string | number | null {
  if (value == null) return null
  if (typeof value === "number") return value
  const s = String(value).trim()
  if (!s) return null
  if (/(z|[+-]\d{2}:?\d{2})$/i.test(s)) return s
  // `YYYY-MM-DD HH:mm:ss` and the ISO form both become an explicit UTC instant.
  return `${s.replace(" ", "T")}Z`
}

/** Milliseconds since epoch for an API timestamp, or `null` if unparseable. */
export function apiTimeMs(value: string | number | null | undefined): number | null {
  const stamped = apiTime(value)
  if (stamped == null) return null
  const ms = typeof stamped === "number" ? (stamped < 1e10 ? stamped * 1000 : stamped) : Date.parse(stamped)
  return Number.isFinite(ms) ? ms : null
}

/**
 * RadioTap centre frequency (MHz) -> 802.11 channel number. Returns `null`
 * rather than 0 for anything off the plan, so a caller can say "not reported"
 * instead of printing a channel that does not exist.
 */
export function freqToChannel(freq: number | string | null | undefined): number | null {
  const f = Number(freq)
  if (!Number.isFinite(f) || f <= 0) return null
  if (f === 2484) return 14
  if (f >= 2412 && f <= 2472) return Math.round((f - 2412) / 5) + 1
  if (f >= 5000 && f <= 5925) return Math.round((f - 5000) / 5)
  if (f >= 5955 && f <= 7115) return Math.round((f - 5955) / 5) + 1 // 6 GHz
  // Some captures store the channel number itself rather than the frequency.
  if (f <= 233) return Math.round(f)
  return null
}

/** The sensor's fixed offset. Asia/Riyadh is UTC+3 year round — no DST. */
export const RIYADH_OFFSET_MS = 3 * 60 * 60 * 1000

/**
 * Shift an instant so the `getUTC*` accessors read out Asia/Riyadh wall-clock
 * fields. Bucketing a series by "hour" has to agree with the timestamps the
 * table prints, and those are always Riyadh (see `lib/format.ts`).
 */
export function riyadhParts(ms: number): { y: number; m: number; d: number; hour: number } {
  const shifted = new Date(ms + RIYADH_OFFSET_MS)
  return {
    y: shifted.getUTCFullYear(),
    m: shifted.getUTCMonth(),
    d: shifted.getUTCDate(),
    hour: shifted.getUTCHours(),
  }
}
