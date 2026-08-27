"use client"

/**
 * The question field and the run controls, as a floating paper slip.
 *
 * It floats rather than sitting in the flow for the same reason the nav pill
 * does: the page below it is a document that grows, and a control that scrolls
 * away is a control the reader has to hunt for after every answer. The
 * elevation step is the system's `--elev-float`, the same one the pill uses, so
 * there is exactly one floating tier on the page and not two.
 *
 * Enter sends, Shift+Enter breaks the line — the convention every operator
 * already has in their fingers, and the reason this is a `<textarea>` and not
 * an `<input>`: a multi-line question about a MAC and a time window is normal
 * here, and an input silently removes the affordance.
 *
 * The primary control changes identity with the run: while a run is open it
 * cancels, because a run that cannot be stopped is a run that has to be waited
 * out — and cancelling also lets the backend collect the run rather than
 * continuing to bill for it.
 */
import * as React from "react"
import { RotateCcw } from "lucide-react"

import { TechnicalText } from "@/components/saqr/markdown"
import { Button } from "@/components/ui/button"
import { useFormatters } from "@/lib/format"
import { useT } from "@/lib/i18n"
import { cn } from "@/lib/utils"

/** Matches `AgentAskPayload.question`: `min_length=1, max_length=4000`. */
export const QUESTION_MAX = 4000

/** Ceiling for the auto-grow, in px. Past it the field scrolls itself. */
const MAX_FIELD_PX = 168

/**
 * How close to the ceiling the counter appears.
 *
 * A counter that is always on is a counter nobody reads, and `maxLength`
 * silently stops accepting characters — so the one moment it has to be visible
 * is the moment before that happens.
 */
const COUNTER_FROM = 240

export function SaqrComposer({
  value,
  onChange,
  onSend,
  onCancel,
  onRetry,
  isRunning,
  canRetry,
  className,
}: {
  value: string
  onChange: (next: string) => void
  onSend: () => void
  onCancel: () => void
  onRetry: () => void
  isRunning: boolean
  canRetry: boolean
  className?: string
}) {
  const t = useT()
  const f = useFormatters()
  const ref = React.useRef<HTMLTextAreaElement>(null)
  const hintId = React.useId()

  const remaining = QUESTION_MAX - value.length
  const showCounter = remaining <= COUNTER_FROM

  // Grow with the question up to a ceiling; past that the field scrolls rather
  // than pushing the document off the screen.
  React.useEffect(() => {
    const el = ref.current
    if (!el) return
    el.style.height = "auto"
    el.style.height = `${Math.min(el.scrollHeight, MAX_FIELD_PX)}px`
  }, [value])

  const send = () => {
    if (isRunning || !value.trim()) return
    onSend()
  }

  return (
    <div className={cn("flex min-w-0 flex-col gap-2", className)}>
      <div
        className={cn(
          "border-rule-soft bg-paper-1 hs-float rounded-xl border p-2.5",
          "focus-within:border-accent-soft transition-colors",
          // Stacked on a phone, inline from `sm` up. At 320px two labelled
          // controls beside the field leave it about 130px wide — narrow enough
          // that the placeholder alone wraps to three lines — so below `sm` the
          // field takes the full width and the controls sit under it.
          "flex flex-col gap-2 sm:flex-row sm:items-end"
        )}
      >
        <textarea
          ref={ref}
          rows={1}
          value={value}
          maxLength={QUESTION_MAX}
          onChange={(event) => onChange(event.target.value)}
          onKeyDown={(event) => {
            // `isComposing` guards an IME: Enter mid-composition commits the
            // candidate and must not also submit the question.
            if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
              event.preventDefault()
              send()
            }
          }}
          placeholder={t("saqr.placeholder")}
          aria-label={t("saqr.placeholder")}
          aria-describedby={hintId}
          disabled={isRunning}
          className={cn(
            "text-ink-0 placeholder:text-ink-3 min-w-0 flex-1 resize-none bg-transparent",
            "px-2 py-1.5 text-base leading-relaxed outline-none disabled:opacity-60"
          )}
        />

        <div className="flex shrink-0 items-center justify-end gap-1.5">
          {canRetry && !isRunning && (
            <Button size="sm" variant="ghost" onClick={onRetry} aria-label={t("saqr.retry")}>
              <RotateCcw aria-hidden="true" />
              {/* Below `sm` the label is dropped rather than the control: a
                  320px viewport cannot hold three labelled buttons, and the
                  ability to re-ask is worth more than the word for it. */}
              <span className="hidden sm:inline">{t("saqr.retry")}</span>
            </Button>
          )}

          {isRunning ? (
            <Button size="sm" variant="secondary" onClick={onCancel}>
              {t("saqr.stop")}
            </Button>
          ) : (
            <Button size="sm" onClick={send} disabled={!value.trim()}>
              {t("saqr.send")}
            </Button>
          )}
        </div>
      </div>

      {/* The helper line. It stays one row at every width by wrapping rather
          than truncating, and the counter takes the inline-end edge so the hint
          never has to move to make room for it. */}
      <div className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1 px-1 text-xs">
        {/* `Enter` / `Shift` are key names, not prose: pinned LTR so they do not
            reorder inside the Arabic hint around them. */}
        <p id={hintId} className="text-ink-3 min-w-0">
          <TechnicalText text={t("saqr.enterHint")} />
        </p>
        {showCounter && (
          <p
            className={cn(
              "ms-auto shrink-0",
              // Only once it actually matters does it stop being grey.
              remaining <= 0 ? "text-sev-high" : "text-ink-2"
            )}
            aria-live="polite"
          >
            {t("saqr.charsLeft", { n: f.number(Math.max(0, remaining)) })}
          </p>
        )}
      </div>
    </div>
  )
}
