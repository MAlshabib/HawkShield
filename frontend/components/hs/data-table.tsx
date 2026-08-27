"use client"

import * as React from "react"
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react"

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { cn } from "@/lib/utils"

/**
 * The dense operational table.
 *
 * Four states are built in rather than left to the caller, because the failure
 * mode this replaces is a table that only ever renders its happy path and shows
 * an empty rectangle the first time the API is slow. Loading paints the
 * hairline scan over the header shell so the column widths are already visible;
 * error and empty occupy the same footprint so nothing jumps as the state
 * resolves.
 *
 * All copy is a prop. This component contains no user-facing English.
 */

export type SortDirection = "asc" | "desc"

export interface DataTableSort {
  columnId: string
  direction: SortDirection
}

export interface DataTableColumn<T> {
  id: string
  /** Header content. Rendered inside the sort control when sortable. */
  header: React.ReactNode
  cell: (row: T, index: number) => React.ReactNode
  /** `end` right-aligns in LTR and left-aligns in RTL. Use for figures. */
  align?: "start" | "end"
  /** Render the cell in the mono tabular face. Implies `align: "end"`. */
  numeric?: boolean
  sortable?: boolean
  /** Any CSS length; applied to the column head so widths stay stable. */
  width?: string
  /** Hide below the given breakpoint. Dense tables have to shed columns. */
  hideBelow?: "sm" | "md" | "lg"
}

export type DataTableState = "ready" | "loading" | "error"

export interface DataTableProps<T> extends Omit<React.ComponentPropsWithoutRef<"div">, "children"> {
  columns: readonly DataTableColumn<T>[]
  rows: readonly T[]
  rowKey: (row: T, index: number) => React.Key
  /** Defaults to `ready`; `rows.length === 0` then renders the empty state. */
  state?: DataTableState
  /** Shown when `state` is `ready` and there are no rows. Required. */
  emptyLabel: React.ReactNode
  /** Shown under the scan while loading. Optional — the scan alone reads. */
  loadingLabel?: React.ReactNode
  /** Shown when `state` is `error`. Optional. */
  errorLabel?: React.ReactNode
  sort?: DataTableSort | null
  onSortChange?: (sort: DataTableSort) => void
  onRowSelect?: (row: T, index: number) => void
  /** Key of the currently selected row, matched against `rowKey`. */
  selectedKey?: React.Key | null
  /**
   * Rows for which the arrival animation should play. The tint colour comes
   * from `tintOf`; without one the wash falls back to the info hue.
   */
  isArriving?: (row: T, index: number) => boolean
  /** CSS colour for a row's arrival wash — pass the class colour token. */
  tintOf?: (row: T, index: number) => string | undefined
}

const alignClass = { start: "text-start", end: "text-end" } as const

const hideBelowClass = {
  sm: "hidden sm:table-cell",
  md: "hidden md:table-cell",
  lg: "hidden lg:table-cell",
} as const

function SortIcon({ active, direction }: { active: boolean; direction: SortDirection }) {
  if (!active) return <ChevronsUpDown className="text-ink-faint size-3" aria-hidden="true" />
  return direction === "asc" ? (
    <ArrowUp className="text-hs-azure size-3" aria-hidden="true" />
  ) : (
    <ArrowDown className="text-hs-azure size-3" aria-hidden="true" />
  )
}

function DataTable<T>({
  columns,
  rows,
  rowKey,
  state = "ready",
  emptyLabel,
  loadingLabel,
  errorLabel,
  sort = null,
  onSortChange,
  onRowSelect,
  selectedKey = null,
  isArriving,
  tintOf,
  className,
  ...props
}: DataTableProps<T>) {
  const isEmpty = state === "ready" && rows.length === 0
  const showRows = state === "ready" && rows.length > 0

  const handleSort = (column: DataTableColumn<T>) => {
    if (!column.sortable || !onSortChange) return
    // First click on a new column sorts descending: in an incident table the
    // question is always "what is worst / newest", never "what is smallest".
    const nextDirection: SortDirection =
      sort?.columnId === column.id && sort.direction === "desc" ? "asc" : "desc"
    onSortChange({ columnId: column.id, direction: nextDirection })
  }

  return (
    <div data-slot="data-table" className={cn("min-w-0", className)} {...props}>
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            {columns.map((column) => {
              const active = sort?.columnId === column.id
              const align = column.align ?? (column.numeric ? "end" : "start")

              return (
                <TableHead
                  key={column.id}
                  style={column.width ? { width: column.width } : undefined}
                  aria-sort={
                    active ? (sort.direction === "asc" ? "ascending" : "descending") : undefined
                  }
                  className={cn(
                    alignClass[align],
                    column.hideBelow && hideBelowClass[column.hideBelow]
                  )}
                >
                  {column.sortable ? (
                    <button
                      type="button"
                      onClick={() => handleSort(column)}
                      className={cn(
                        "hs-label hover:text-ink inline-flex items-center gap-1 transition-colors",
                        align === "end" && "flex-row-reverse",
                        active && "text-ink"
                      )}
                    >
                      {column.header}
                      <SortIcon active={active} direction={sort?.direction ?? "desc"} />
                    </button>
                  ) : (
                    column.header
                  )}
                </TableHead>
              )
            })}
          </TableRow>
        </TableHeader>

        {showRows && (
          <TableBody>
            {rows.map((row, index) => {
              const key = rowKey(row, index)
              const arriving = isArriving?.(row, index) ?? false
              const tint = tintOf?.(row, index)
              const interactive = Boolean(onRowSelect)

              return (
                <TableRow
                  key={key}
                  data-state={selectedKey !== null && key === selectedKey ? "selected" : undefined}
                  onClick={interactive ? () => onRowSelect?.(row, index) : undefined}
                  // A row is a control only when it leads somewhere. Giving every
                  // row a button role would flood the tab order of a 200-row table.
                  tabIndex={interactive ? 0 : undefined}
                  role={interactive ? "button" : undefined}
                  onKeyDown={
                    interactive
                      ? (event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault()
                            onRowSelect?.(row, index)
                          }
                        }
                      : undefined
                  }
                  className={cn(
                    interactive && "cursor-pointer",
                    arriving && "hs-arrival"
                  )}
                  style={
                    arriving && tint
                      ? ({ "--hs-arrival-tint": tint } as React.CSSProperties)
                      : undefined
                  }
                >
                  {columns.map((column) => {
                    const align = column.align ?? (column.numeric ? "end" : "start")
                    return (
                      <TableCell
                        key={column.id}
                        className={cn(
                          alignClass[align],
                          column.numeric && "hs-num",
                          column.hideBelow && hideBelowClass[column.hideBelow]
                        )}
                      >
                        {column.cell(row, index)}
                      </TableCell>
                    )
                  })}
                </TableRow>
              )
            })}
          </TableBody>
        )}
      </Table>

      {/* The three non-row states share one footprint so the table does not
          resize as it settles. */}
      {state === "loading" && (
        <div className="hs-scan border-hairline grid min-h-24 place-items-center border-t">
          {loadingLabel && <span className="hs-label">{loadingLabel}</span>}
        </div>
      )}

      {state === "error" && (
        <div className="border-hairline grid min-h-24 place-items-center gap-1 border-t px-3 py-6 text-center">
          <span className="hs-label text-sev-critical">{errorLabel}</span>
        </div>
      )}

      {isEmpty && (
        <div className="border-hairline grid min-h-24 place-items-center border-t px-3 py-6 text-center">
          <span className="hs-label">{emptyLabel}</span>
        </div>
      )}
    </div>
  )
}

export { DataTable }
