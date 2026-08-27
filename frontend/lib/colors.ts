/**
 * Threat-class identity colours.
 *
 * Derived from the two brand hues in `frontend/brand-spec.md` (navy `#0E2A55`,
 * azure `#2E8FDD`) plus the two warm severity hues. Six of the classes sit on a
 * navy -> azure ramp interpolated in oklch; the two that must never be missed
 * take the warm hues outright. V1's fuchsia `#E879F9` and indigo `#818CF8` were
 * off-brand and are gone.
 *
 * Salience tracks severity on purpose. `evil_twin` advances in red, `ssdp`
 * recedes into low-chroma slate, and everything between falls monotonically in
 * lightness and chroma — so a legend reads as an ordinal scale, which these
 * classes genuinely are, instead of as eight unrelated hues.
 *
 * Lightness is banded 0.50-0.64 so one hex clears 3:1 against BOTH substrates
 * (`#070B12` dark and `#F5F7FA` light). These values are consumed as literal
 * hex by recharts and by inline styles, so unlike the CSS tokens they cannot be
 * theme-split. The same values are mirrored as `--cls-*` in `app/globals.css`
 * for anything that can reach for a custom property instead.
 *
 * Key order is canonical: most severe first.
 */
export const attackColors = {
  evil_twin: "#DB4144", // warm hue: the critical anchor
  krack: "#BA7400", // warm hue: the high anchor
  kr00k: "#2D91E2", // oklch(0.640 0.150 247.5) — ramp ceiling, full azure
  rogueap: "#4088CD", // oklch(0.612 0.128 249.8)
  deauth: "#4A7FB8", // oklch(0.584 0.105 252.1)
  disas: "#5175A3", // oklch(0.556 0.083 254.4)
  reassoc: "#556D8E", // oklch(0.528 0.060 256.7)
  ssdp: "#566479", // oklch(0.500 0.038 259.0) — ramp floor, near-neutral slate
  other: "#787E86", // unclassified: deliberately achromatic, claims no hue
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
 * (SVG `fill`, `style={{ color }}`) since the token survives a re-themed
 * subtree; the literal is still required where the value is string-concatenated.
 */
export function attackColorVar(type: AttackType): string {
  return `var(--cls-${type.replace(/_/g, "-")}, ${attackColors[type]})`
}
