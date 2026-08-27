"use client"

/**
 * The source-MAC picker.
 *
 * A plain `Select` was the wrong control for this list and the sensor made that
 * obvious: on the demo capture every source is `02:5A:11:10:__:__`, twenty-four
 * of them, differing only in the last two octets. Scrolling a native-feeling
 * listbox to find one of those is reading, not choosing — and Radix's own
 * typeahead does not help, because it matches from the *start* of the label and
 * every label starts identically. So the control is a combobox: type any part of
 * the address and the list narrows.
 *
 * `Popover`, not `Select`, and that is a behavioural choice rather than a
 * cosmetic one. A `Select` owns the keyboard entirely — it swallows printable
 * keys for its typeahead, so there is nowhere to put a filter field — and it
 * takes a modal scroll lock the moment it opens. A non-modal `Popover` leaves
 * both the keyboard and the page alone.
 *
 * Filtering is over the address with its separators stripped, so `10ba` and
 * `10:BA` and `10-ba` all find `02:5A:11:10:BA:51`. A query that contains no hex
 * digits at all matches nothing rather than everything — the empty state is the
 * honest answer to "zz", not the full list.
 *
 * Every option carries its packet count because the count is what makes the
 * choice informed: `/top-offenders` ranks source MACs by how many frames the
 * sensor stored for them, and picking the one with thirty frames instead of the
 * one with five hundred is the difference between a fix and an empty readout.
 */
import * as React from "react"
import { CheckIcon, ChevronDownIcon, SearchIcon } from "lucide-react"

import { Quantity } from "@/components/quantity"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { useFormatters } from "@/lib/format"
import { useT } from "@/lib/i18n"
import { cn } from "@/lib/utils"

/** One row of `/top-offenders`: a source MAC and the frames stored for it. */
export type SourceOption = { wlan_sa: string; count: number }

/**
 * A MAC reduced to the characters that carry information. Separators and case
 * are noise when someone is typing an address they half-remember, and the three
 * common ways of writing one — colons, dashes, bare — all have to reach the same
 * row.
 */
function hexOnly(value: string): string {
  return value.toLowerCase().replace(/[^0-9a-f]/g, "")
}

export function SourcePicker({
  sources,
  value,
  onChange,
  id,
  labelledBy,
}: {
  sources: readonly SourceOption[]
  /** The selected MAC, or `""` when nothing has been chosen yet. */
  value: string
  onChange: (mac: string) => void
  id?: string
  /** Id of the field's visible label, so the trigger reads as "Source MAC, <mac>". */
  labelledBy?: string
}) {
  const t = useT()
  const f = useFormatters()

  const [open, setOpen] = React.useState(false)
  const [query, setQuery] = React.useState("")
  const [active, setActive] = React.useState(0)

  const listId = React.useId()
  const optionId = (index: number) => `${listId}-option-${index}`

  const listRef = React.useRef<HTMLDivElement>(null)

  /**
   * The packet count beside an address.
   *
   * The unit word is dropped below `sm`. At 320px a seventeen-character MAC and
   * the word "packets" cannot both fit, and something has to give: it is the
   * word, because the address is the thing being chosen and an address
   * truncated to `02:5A:11:1…` tells the reader nothing — the last two octets
   * are the only part that differs between these twenty-four sources. The
   * figure itself never leaves.
   */
  const count = (n: number) => (
    <Quantity
      className="text-ink-2 shrink-0 text-xs"
      value={f.number(n)}
      // `sr-only`, not `hidden`: the word leaves the layout below `sm` but stays
      // in the accessibility tree, so a screen reader still hears "520 packets"
      // at every width rather than a bare figure.
      unit={<span className="sr-only sm:not-sr-only">{t("units.packets")}</span>}
    />
  )

  const matches = React.useMemo(() => {
    const raw = query.trim()
    if (raw === "") return sources
    const needle = hexOnly(raw)
    if (needle === "") return []
    return sources.filter((row) => hexOnly(row.wlan_sa).includes(needle))
  }, [sources, query])

  const selected = React.useMemo(
    () => sources.find((row) => row.wlan_sa === value) ?? null,
    [sources, value]
  )

  /**
   * Opening puts the cursor on whatever is already chosen, so Enter is a no-op
   * rather than a surprise. Typing puts it back on the first match, which is
   * where the eye already is.
   *
   * The list and the selection are read through a ref rather than declared as
   * dependencies, because this must fire on *opening* and on nothing else. As
   * plain deps, any re-render that handed down a new `sources` array — the
   * parent refetches whenever the source or the window changes — would clear a
   * half-typed filter out from under the reader.
   */
  const latest = React.useRef({ sources, value })
  latest.current = { sources, value }

  React.useEffect(() => {
    if (!open) return
    const { sources: rows, value: current } = latest.current
    setQuery("")
    const at = rows.findIndex((row) => row.wlan_sa === current)
    setActive(at < 0 ? 0 : at)
  }, [open])

  React.useEffect(() => {
    setActive(0)
  }, [query])

  /** Keep the cursor in view without dragging the page around it. */
  React.useEffect(() => {
    if (!open) return
    const node = listRef.current?.querySelector<HTMLElement>('[data-active="true"]')
    node?.scrollIntoView({ block: "nearest" })
  }, [open, active, matches])

  function commit(row: SourceOption | undefined) {
    if (!row) return
    onChange(row.wlan_sa)
    setOpen(false)
  }

  function onKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    // Escape and Tab are Radix's to handle — swallowing either would trap the
    // reader inside a filter field.
    const last = matches.length - 1
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault()
        setActive((i) => (matches.length === 0 ? 0 : i >= last ? 0 : i + 1))
        break
      case "ArrowUp":
        event.preventDefault()
        setActive((i) => (matches.length === 0 ? 0 : i <= 0 ? last : i - 1))
        break
      case "Home":
        event.preventDefault()
        setActive(0)
        break
      case "End":
        event.preventDefault()
        setActive(Math.max(0, last))
        break
      case "Enter":
        event.preventDefault()
        commit(matches[active])
        break
    }
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        {/* Deliberately the same field shape as `ui/select`'s trigger: this sits
            beside the window selector and the two must read as one row of
            controls, not as a select and a button that happen to be adjacent. */}
        <button
          id={id}
          type="button"
          // `PopoverTrigger` supplies `aria-haspopup`, `aria-expanded` and
          // `aria-controls` itself. The name is the label plus the button's own
          // text, so the control announces as "Source MAC, 02:5A:11:10:78:7C" —
          // an `aria-label` here would replace the chosen address rather than
          // introduce it.
          aria-labelledby={labelledBy && id ? `${labelledBy} ${id}` : undefined}
          className={cn(
            "bg-paper-0 border-rule-soft text-ink-0 hover:border-ink-3",
            "flex h-10 w-full items-center justify-between gap-2 rounded-md border",
            "px-3.5 py-2 text-sm whitespace-nowrap transition-colors"
          )}
        >
          {selected ? (
            <span className="flex min-w-0 items-center gap-2">
              <span className="hs-num truncate">{selected.wlan_sa.toUpperCase()}</span>
              {count(selected.count)}
            </span>
          ) : (
            <span className="text-ink-3 truncate">{t("map.sourcePick")}</span>
          )}
          <ChevronDownIcon className="text-ink-2 size-4 shrink-0 opacity-50" aria-hidden />
        </button>
      </PopoverTrigger>

      {/* Width is pinned to the trigger, which also makes `align` moot — there is
          no edge for the panel to align *to* when it is exactly as wide as the
          control. That is why this needs no RTL special case even though
          `Popover.Root` takes no `dir`. `avoidCollisions` flips it above the
          trigger near the bottom of the viewport instead of running off it. */}
      <PopoverContent
        align="start"
        sideOffset={4}
        avoidCollisions
        collisionPadding={12}
        // Two ceilings, and the lower always wins: 22rem so the panel stays a
        // panel on a tall screen instead of becoming a second page, and Radix's
        // own measurement so it never grows past the space it actually has. The
        // list scrolls inside whichever ceiling applies; the filter field and
        // the count line do not move.
        className="w-(--radix-popover-trigger-width) flex max-h-[min(22rem,var(--radix-popover-content-available-height))] flex-col gap-0 overflow-hidden p-0"
      >
        <div className="border-rule relative shrink-0 border-b p-2">
          {/* `start-5` = the container's own 0.5rem padding plus the field's
              `ps-9`, so the icon sits on the reading edge with no `[dir]`
              override — the same arrangement as the source filter on
              `/threats`. */}
          <SearchIcon
            className="text-ink-2 pointer-events-none absolute start-5 top-1/2 size-3.5 -translate-y-1/2"
            aria-hidden
          />
          <Input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            role="combobox"
            aria-expanded
            aria-autocomplete="list"
            aria-controls={listId}
            aria-activedescendant={matches.length > 0 ? optionId(active) : undefined}
            aria-label={t("map.sourceFilter")}
            placeholder={t("map.sourceFilter")}
            // `hs-num` pins the field's own content LTR: a MAC being typed
            // inside an Arabic page must not reorder under the caret.
            className="hs-num h-9 border-0 bg-transparent ps-9 pe-2"
          />
        </div>

        <div
          ref={listRef}
          id={listId}
          role="listbox"
          aria-label={t("map.source")}
          className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-1"
        >
          {matches.length === 0 ? (
            <p className="text-ink-2 px-2.5 py-6 text-center text-sm">{t("map.sourceNoMatch")}</p>
          ) : (
            matches.map((row, index) => {
              const isSelected = row.wlan_sa === value
              const isActive = index === active
              return (
                <div
                  key={row.wlan_sa}
                  id={optionId(index)}
                  role="option"
                  aria-selected={isSelected}
                  data-active={isActive}
                  // The cursor is a pointer affordance too: hovering a row moves
                  // it, so mouse and keyboard never disagree about where it is.
                  onMouseMove={() => setActive(index)}
                  onClick={() => commit(row)}
                  // The paddings and gaps here are tight on purpose. At 320px
                  // the row has about 196px of usable width once the scrollbar
                  // and the panel's own inset are taken out, and a full MAC at
                  // `text-sm` mono needs ~143 of it. Every extra gutter comes
                  // straight off the end of the address.
                  className={cn(
                    "text-ink-0 flex cursor-default items-center justify-between gap-2",
                    "rounded-sm px-2 py-2 text-sm select-none",
                    isActive && "bg-accent-tint"
                  )}
                >
                  <span className="flex min-w-0 items-center gap-1.5">
                    <CheckIcon
                      className={cn("size-3 shrink-0", isSelected ? "opacity-100" : "opacity-0")}
                      aria-hidden
                    />
                    {/* The address is pinned LTR by `hs-num`; the count keeps the
                        reader's own direction — see `components/quantity.tsx`. */}
                    <span className="hs-num truncate">{row.wlan_sa.toUpperCase()}</span>
                  </span>
                  {count(row.count)}
                </div>
              )
            })
          )}
        </div>

        {/* Announced on every keystroke, and worth showing: with twenty-four
            near-identical addresses, "Showing 3 of 24" is how a reader knows the
            filter did something. `common.showing` rather than a map-specific
            string, because it is the phrasing the rest of the product already
            uses — and because a counted noun in Arabic takes three different
            forms for 1, 3-10 and 11+, so the safe sentence is the one with no
            noun in it. */}
        <p aria-live="polite" className="hs-label border-rule shrink-0 border-t px-3 py-2">
          {t("common.showing", {
            shown: f.number(matches.length),
            total: f.number(sources.length),
          })}
        </p>
      </PopoverContent>
    </Popover>
  )
}
