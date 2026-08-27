/**
 * The wire row `GET /attacks` returns, and the view row the threats page reads.
 *
 * This file deliberately contains no normalisation logic of its own. Class
 * narrowing, UTC stamping and frequency→channel all already exist in
 * `lib/detections.ts` — the V1 page reimplemented all three, slightly
 * differently, and the `(Re)Assoc` rows were mislabelled for months as a result.
 * Everything here either reads a field straight off the row or delegates.
 *
 * What is NOT here matters as much. The V1 detail drawer carried "Duration" and
 * "Packets" rows that were permanent em-dashes: the endpoint has never sent
 * either, and a field that can only ever say "—" teaches an operator that the
 * dash means "zero" rather than "not reported". They are gone rather than
 * carried forward.
 */
import { severityOf, type AttackType, type Severity } from "@/lib/colors"
import { apiTimeMs, freqToChannel, toAttackType } from "@/lib/detections"

/** One row exactly as `GET /attacks` serialises it. Every field is nullable. */
export type PacketRow = {
  id: number | string
  ts?: string | null
  iface?: string | null
  src_mac?: string | null
  dst_mac?: string | null
  bssid?: string | null
  frame_len?: number | null
  channel_freq?: number | null
  datarate?: number | null
  signal_dbm?: number | null
  wlan_retry?: number | null
  wlan_type?: number | null
  wlan_subtype?: number | null
  proba_anomaly?: number | null
  proba_attack?: number | null
  predicted_label?: string | null
  raw?: {
    sim?: boolean
    sim_batch?: string
    ssid?: string | null
    [k: string]: unknown
  } | null
}

/**
 * A detection as the table and the drawer read it. Every field is nullable in
 * the same way the wire row is: `null` means the sensor did not report it, and
 * the UI must say so rather than printing a zero.
 */
export type Detection = {
  id: string
  ms: number | null
  type: AttackType
  /** The label verbatim, for the drawer — `toAttackType` is lossy by design. */
  rawLabel: string | null
  severity: Severity
  srcMac: string | null
  dstMac: string | null
  bssid: string | null
  ssid: string | null
  iface: string | null
  channel: number | null
  freq: number | null
  rssi: number | null
  frameLen: number | null
  dataRate: number | null
  wlanType: number | null
  wlanSubtype: number | null
  retry: boolean | null
  confidence: number | null
  anomaly: number | null
  sim: boolean
}

/**
 * Finite numbers only; anything else is "not reported", never 0.
 *
 * The `value == null` guard is the whole point of this function rather than an
 * edge case. `Number(null)` is `0` and `Number("")` is `0`, both of which pass
 * `Number.isFinite` — so a bare `Number()` turns every field the sensor did not
 * report into a confident zero. `signal_dbm: null` rendered as `0 dBm`, which
 * reads as "a full-strength signal at the antenna" rather than "no reading".
 */
function num(value: unknown): number | null {
  if (value == null || value === "") return null
  const n = Number(value)
  return Number.isFinite(n) ? n : null
}

/**
 * RSSI sanity band. RadioTap occasionally reports a placeholder outside any
 * physical range, and plotting that as a signal strength is worse than
 * admitting we do not have one. -110..0 dBm covers every real reading.
 */
function rssi(value: unknown): number | null {
  const n = num(value)
  if (n === null || n < -110 || n > 0) return null
  return Math.round(n)
}

function text(value: unknown): string | null {
  if (value == null) return null
  const s = String(value).trim()
  return s ? s : null
}

/** Probabilities are fractions; anything outside 0..1 is not a confidence. */
function fraction(value: unknown): number | null {
  const n = num(value)
  if (n === null || n < 0 || n > 1) return null
  return n
}

export function toDetection(row: PacketRow): Detection {
  const type = toAttackType(row.predicted_label)
  return {
    id: String(row.id ?? ""),
    ms: apiTimeMs(row.ts),
    type,
    rawLabel: text(row.predicted_label),
    severity: severityOf(type),
    srcMac: text(row.src_mac),
    dstMac: text(row.dst_mac),
    bssid: text(row.bssid),
    ssid: text(row.raw?.ssid),
    iface: text(row.iface),
    channel: freqToChannel(row.channel_freq),
    freq: num(row.channel_freq),
    rssi: rssi(row.signal_dbm),
    frameLen: num(row.frame_len),
    dataRate: num(row.datarate),
    wlanType: num(row.wlan_type),
    wlanSubtype: num(row.wlan_subtype),
    retry: row.wlan_retry == null ? null : Number(row.wlan_retry) === 1,
    confidence: fraction(row.proba_attack),
    anomaly: fraction(row.proba_anomaly),
    sim: Boolean(row.raw?.sim),
  }
}
