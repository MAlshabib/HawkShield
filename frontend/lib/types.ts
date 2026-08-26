// AttackType is derived from `attackColors` so the class list has exactly one
// source of truth; adding a key there is enough to add it everywhere.
export type { AttackType } from "./colors"
export type TimeRange = "day" | "week" | "month"

// Re-export from colors.ts for convenience
export { attackColors, attackLabels, attackTypes, type AttackType as AttackTypeFromColors } from "./colors"
