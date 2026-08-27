"use client"

/**
 * The threats filter bar: time range, class, severity, source MAC.
 *
 * Two multi-selects sit in Popovers rather than in a `<Select multiple>`,
 * because the operator's real question is "show me these three classes" and a
 * native multiple-select cannot show a colour swatch beside each option — and
 * the swatch is how the class column and this filter stay legible as one
 * system.
 *
 * Every offset is logical. The one thing that is not mirrored is the MAC input's
 * own text, which is pinned LTR by `hs-num`: a half-typed MAC reordered by the
 * bidi algorithm while you are typing it is unusable.
 */
import * as React from "react"
import { Check, Search, X } from "lucide-react"

import { StatusPill } from "@/components/hs/status-pill"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useLocale, useT, type TranslationKey } from "@/lib/i18n"
import { attackColorVar, attackLabels, attackTypes, type AttackType, type Severity } from "@/lib/colors"
import { cn } from "@/lib/utils"

/** `all` is not a duration — it is the absence of a time filter. */
export type RangeId = "all" | "1h" | "6h" | "24h" | "7d" | "30d"

export const THREAT_RANGES: readonly { id: RangeId; ms: number | null; key: TranslationKey }[] = [
  { id: "24h", ms: 24 * 3_600_000, key: "time.range.hours24" },
  { id: "1h", ms: 3_600_000, key: "time.range.hour1" },
  { id: "6h", ms: 6 * 3_600_000, key: "time.range.hours6" },
  { id: "7d", ms: 7 * 86_400_000, key: "time.range.days7" },
  { id: "30d", ms: 30 * 86_400_000, key: "time.range.days30" },
  { id: "all", ms: null, key: "time.range.all" },
]

export const SEVERITIES: readonly Severity[] = ["critical", "high", "info"]

export type ThreatFilters = {
  range: RangeId
  classes: AttackType[]
  severities: Severity[]
  search: string
}

export const EMPTY_FILTERS: ThreatFilters = {
  range: "24h",
  classes: [],
  severities: [],
  search: "",
}

export function filtersAreEmpty(f: ThreatFilters): boolean {
  return (
    f.range === EMPTY_FILTERS.range &&
    f.classes.length === 0 &&
    f.severities.length === 0 &&
    f.search.trim() === ""
  )
}

/** One row of a multi-select popover. */
function Option({
  checked,
  onToggle,
  children,
}: {
  checked: boolean
  onToggle: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      role="menuitemcheckbox"
      aria-checked={checked}
      onClick={onToggle}
      className={cn(
        "hover:bg-surface-sunken flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-start text-sm transition-colors",
        checked && "text-ink"
      )}
    >
      {/* Fixed-width gutter so the labels form a column whether or not the
          check is present — a check that shifts the label reads as a jitter. */}
      <span className="grid w-4 shrink-0 place-items-center">
        {checked && <Check className="text-hs-azure size-3.5" strokeWidth={3} aria-hidden="true" />}
      </span>
      {children}
    </button>
  )
}

function MultiSelect({
  label,
  allLabel,
  count,
  children,
}: {
  label: string
  allLabel: string
  count: number
  children: React.ReactNode
}) {
  const t = useT()
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="secondary" size="sm" className="justify-between gap-2">
          <span className="hs-label">{label}</span>
          <span className="text-ink text-xs">
            {count === 0 ? allLabel : t("threats.filter.selected", { n: count })}
          </span>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-56 p-1">
        <div role="menu" className="flex flex-col">
          {children}
        </div>
      </PopoverContent>
    </Popover>
  )
}

export function ThreatsFilters({
  filters,
  onChange,
}: {
  filters: ThreatFilters
  onChange: (next: ThreatFilters) => void
}) {
  const t = useT()
  const { dir } = useLocale()

  const toggleClass = (cls: AttackType) =>
    onChange({
      ...filters,
      classes: filters.classes.includes(cls)
        ? filters.classes.filter((c) => c !== cls)
        : [...filters.classes, cls],
    })

  const toggleSeverity = (sev: Severity) =>
    onChange({
      ...filters,
      severities: filters.severities.includes(sev)
        ? filters.severities.filter((s) => s !== sev)
        : [...filters.severities, sev],
    })

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Select
        dir={dir}
        value={filters.range}
        onValueChange={(v) => onChange({ ...filters, range: v as RangeId })}
      >
        <SelectTrigger className="w-44" aria-label={t("threats.filter.timeRange")}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {THREAT_RANGES.map((r) => (
            <SelectItem key={r.id} value={r.id}>
              {t(r.key)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <MultiSelect
        label={t("threats.filter.classes")}
        allLabel={t("threats.filter.classesAll")}
        count={filters.classes.length}
      >
        {attackTypes.map((cls) => (
          <Option
            key={cls}
            checked={filters.classes.includes(cls)}
            onToggle={() => toggleClass(cls)}
          >
            <span
              aria-hidden="true"
              className="size-2 shrink-0 rounded-full"
              style={{ background: attackColorVar(cls) }}
            />
            {/* A class identifier is Latin in both locales. */}
            <span className="hs-ltr truncate">{attackLabels[cls]}</span>
          </Option>
        ))}
      </MultiSelect>

      <MultiSelect
        label={t("severity.label")}
        allLabel={t("threats.filter.severitiesAll")}
        count={filters.severities.length}
      >
        {SEVERITIES.map((sev) => (
          <Option
            key={sev}
            checked={filters.severities.includes(sev)}
            onToggle={() => toggleSeverity(sev)}
          >
            <StatusPill tone={sev}>{t(`severity.${sev}`)}</StatusPill>
          </Option>
        ))}
      </MultiSelect>

      <div className="relative min-w-52 flex-1 sm:max-w-72">
        {/* `start-2` and `ps-8`, so the icon sits on the reading edge in both
            directions with no `[dir]` override. */}
        <Search
          className="text-ink-faint pointer-events-none absolute start-2 top-1/2 size-3.5 -translate-y-1/2"
          aria-hidden="true"
        />
        <Input
          value={filters.search}
          onChange={(e) => onChange({ ...filters, search: e.target.value })}
          placeholder={t("threats.filter.sourcePlaceholder")}
          aria-label={t("threats.filter.sourceMac")}
          // `hs-num` pins the field's own content LTR: a MAC being typed inside
          // an Arabic page must not reorder under the caret.
          className="hs-num ps-8 pe-8"
        />
        {filters.search && (
          <button
            type="button"
            onClick={() => onChange({ ...filters, search: "" })}
            aria-label={t("common.clear")}
            className="text-ink-faint hover:text-ink absolute end-2 top-1/2 -translate-y-1/2 transition-colors"
          >
            <X className="size-3.5" aria-hidden="true" />
          </button>
        )}
      </div>

      {!filtersAreEmpty(filters) && (
        <Button variant="ghost" size="sm" onClick={() => onChange(EMPTY_FILTERS)}>
          {t("common.clearAll")}
        </Button>
      )}
    </div>
  )
}
