export type AttackType = "ssdp" | "evil_twin" | "krack" | "deauth" | "reassoc" | "rogueap" | "other"
export type TimeRange = "day" | "week" | "month"

// Re-export from colors.ts for convenience
export { attackColors, attackLabels, type AttackType as AttackTypeFromColors } from "./colors"
