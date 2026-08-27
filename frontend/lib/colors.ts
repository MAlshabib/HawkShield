/**
 * Threat-class identity colours — Falcon Paper.
 *
 * Two anchors plus a ramp. `evil_twin` takes the critical red and `krack` the
 * companion amber outright, because those two must never be missed; the
 * remaining six fall along an azure-to-slate ramp interpolated in oklch from
 * the mark's azure (250 deg) toward the navy's hue (260 deg), losing chroma as
 * they go. Salience therefore tracks severity: `evil_twin` advances, `ssdp`
 * recedes into low-chroma slate, and a legend reads as the ordinal scale these
 * classes genuinely are instead of as eight unrelated hues.
 *
 * Lightness is banded 0.527-0.615 so a single value clears 3:1 against BOTH
 * papers — `oklch(98.6% .004 250)` in light and `oklch(16.5% .018 258)` in
 * dark. That band is not a preference: these values are consumed as literal hex
 * by recharts and by inline SVG fills, which cannot ask which theme is active,
 * so unlike every other colour in the system they cannot be theme-split. The
 * same nine are mirrored as `--cls-*` in `app/globals.css` for anything that
 * can reach for a custom property instead.
 *
 * The hexes below are the sRGB rendering of the oklch values named beside them;
 * the oklch is the source of truth and the hex is what ships to a chart.
 *
 * Key order is canonical: most severe first.
 */
export const attackColors = {
  evil_twin: "#D03C3C", // oklch(57.5% 0.185 25)  — the critical anchor
  krack: "#C0640C", // oklch(60.0% 0.145 55)  — the high anchor
  kr00k: "#2B89D7", // oklch(61.5% 0.145 248) — ramp ceiling, full azure
  rogueap: "#3D83C6", // oklch(59.5% 0.125 250)
  deauth: "#497DB6", // oklch(57.8% 0.105 252.5)
  disas: "#5277A6", // oklch(56.1% 0.085 255)
  reassoc: "#587196", // oklch(54.4% 0.065 257.5)
  ssdp: "#5C6C85", // oklch(52.7% 0.045 260) — ramp floor, near-neutral slate
  other: "#727579", // oklch(56.0% 0.008 258) — unclassified: claims no hue
} as const

export type AttackType = keyof typeof attackColors

export const attackLabels: Record<AttackType, string> = {
  evil_twin: "Evil Twin",
  krack: "KRACK",
  kr00k: "Kr00k",
  rogueap: "Rogue AP",
  deauth: "Deauth",
  disas: "Disassociation",
  reassoc: "Re-Assoc",
  ssdp: "SSDP",
  other: "Other",
} as const

/** Canonical ordering for legends, filters and any other exhaustive listing. */
export const attackTypes = Object.keys(attackColors) as AttackType[]

/**
 * The three severity tiers the UI encodes. There is deliberately no "ok"/green
 * tier: colour is semantic here, and HawkShield never asserts that a network is
 * clean — it reports what it detected. Absence of a detection is absence of a
 * pill, not a green one.
 */
export type Severity = "critical" | "high" | "info"

const severityByType: Record<AttackType, Severity> = {
  // Compromise of the session key or of the AP identity itself.
  evil_twin: "critical",
  krack: "critical",
  kr00k: "critical",
  // Availability loss and impersonation groundwork — damaging, but not decryption.
  rogueap: "high",
  deauth: "high",
  disas: "high",
  // Reconnaissance and protocol noise.
  reassoc: "info",
  ssdp: "info",
  other: "info",
}

/**
 * Severity tier for a class label. Takes the raw string off the API so callers
 * need not narrow first; anything unrecognised falls back to `info` rather than
 * throwing, because a class the model has never emitted before must not be able
 * to take a dashboard down.
 */
export function severityOf(label: string): Severity {
  return severityByType[label as AttackType] ?? "info"
}

/**
 * The CSS custom property mirroring a class colour, with the literal as its
 * fallback. Preferred over `attackColors[t]` anywhere the value lands in CSS
 * (SVG `fill`, `style={{ color }}`, a `DataCardBar` segment) because the token
 * resolves through the cascade; the literal is still required where the value
 * is string-concatenated or handed to a charting library.
 */
export function attackColorVar(type: AttackType): string {
  return `var(--cls-${type.replace(/_/g, "-")}, ${attackColors[type]})`
}
