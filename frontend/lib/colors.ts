export const attackColors = {
  ssdp: "#60A5FA", // blue-400
  evil_twin: "#22D3EE", // cyan-300
  krack: "#3B82F6", // blue-500
  kr00k: "#E879F9", // fuchsia-400 - magenta, the only warm-purple hue in the set
  deauth: "#38BDF8", // cyan-400
  disas: "#FBBF24", // amber-400 - deliberately warm so it never reads as "deauth"
  reassoc: "#1D4ED8", // blue-700
  rogueap: "#0E7490", // cyan-700
  other: "#818CF8", // indigo-400
} as const

export type AttackType = keyof typeof attackColors

export const attackLabels: Record<AttackType, string> = {
  ssdp: "SSDP",
  evil_twin: "Evil Twin",
  krack: "KRACK",
  kr00k: "Kr00k",
  deauth: "Deauth",
  disas: "Disassociation",
  reassoc: "Re-Assoc",
  rogueap: "Rogue AP",
  other: "Other",
} as const

/** Canonical ordering for legends, filters and any other exhaustive listing. */
export const attackTypes = Object.keys(attackColors) as AttackType[]

// Theme colors for the cyber/neon aesthetic
export const themeColors = {
  primary: "#22D3EE", // cyan-300
  secondary: "#38BDF8", // cyan-400
  accent: "#7DD3FC", // sky-300
  background: {
    primary: "#0F172A", // slate-900
    secondary: "#1E293B", // slate-800
    card: "rgba(15, 23, 42, 0.8)", // slate-900 with opacity
  },
  glow: {
    cyan: "0 0 20px rgba(34, 211, 238, 0.3)",
    blue: "0 0 20px rgba(56, 189, 248, 0.3)",
  },
} as const
