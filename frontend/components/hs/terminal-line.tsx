import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * One line of a monospace trace, with a leading marker.
 *
 * Built for Saqr's tool trace: an agent that says which tool it reached for,
 * and what came back, reads as a terminal transcript and not as a chat bubble.
 * The marker column is fixed width so a run of lines forms a straight gutter —
 * that column is the only thing holding the block together, since there is no
 * border and no background.
 *
 * Everything textual is caller-supplied; the component owns no copy.
 */

export type TerminalTone = "default" | "muted" | "critical" | "high" | "info" | "accent"

const toneClass: Record<TerminalTone, string> = {
  default: "text-ink",
  muted: "text-ink-dim",
  critical: "text-sev-critical",
  high: "text-sev-high",
  info: "text-sev-info",
  accent: "text-hs-azure",
}

export interface TerminalLineProps extends React.ComponentPropsWithoutRef<"div"> {
  /**
   * Leading glyph or icon. Defaults to a chevron, which is punctuation rather
   * than an icon — no emoji stands in for an icon anywhere in this system.
   */
  marker?: React.ReactNode
  tone?: TerminalTone
  /** Timestamp or sequence number, set dim in the inline-start gutter. */
  stamp?: React.ReactNode
  /** Indent depth for nested tool calls. One step is 2ch of the mono face. */
  depth?: number
  /** Show the caret and suppress the marker — for a line still being written. */
  pending?: boolean
}

const TerminalLine = React.forwardRef<HTMLDivElement, TerminalLineProps>(function TerminalLine(
  { marker = "›", tone = "default", stamp, depth = 0, pending = false, className, children, ...props },
  ref
) {
  return (
    <div
      ref={ref}
      data-slot="terminal-line"
      data-tone={tone}
      className={cn(
        "font-mono text-xs leading-relaxed",
        "flex items-start gap-2",
        toneClass[tone],
        className
      )}
      {...props}
    >
      {stamp && (
        <span className="hs-num text-ink-faint shrink-0 tabular-nums select-none">{stamp}</span>
      )}

      <span
        aria-hidden="true"
        className="w-[1ch] shrink-0 select-none text-center opacity-70"
        // Indentation is an inline-start margin rather than a left one, so a
        // nested trace still steps inward when the page flips to Arabic.
        style={depth > 0 ? { marginInlineStart: `${depth * 2}ch` } : undefined}
      >
        {pending ? "█" : marker}
      </span>

      <span className="min-w-0 flex-1 break-words whitespace-pre-wrap">{children}</span>
    </div>
  )
})

export { TerminalLine }
