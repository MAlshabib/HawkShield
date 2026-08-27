"use client"

/**
 * The question field and the run controls.
 *
 * Enter sends, Shift+Enter breaks the line — the convention every operator
 * already has in their fingers, and the reason this is a `<textarea>` and not
 * an `<input>`: a multi-line question about a MAC and a time window is normal
 * here, and an input silently truncates the affordance.
 *
 * The primary control is one button that changes identity with the run: while
 * a run is open it cancels, because a run that cannot be stopped is a run that
 * has to be waited out.
 */
import * as React from "react"
import { CornerDownLeft, RotateCcw, Square } from "lucide-react"

import { Button } from "@/components/ui/button"
import { useT } from "@/lib/i18n"
import { cn } from "@/lib/utils"

/** Matches `AgentAskPayload.question`: `min_length=1, max_length=4000`. */
export const QUESTION_MAX = 4000

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
  const ref = React.useRef<HTMLTextAreaElement>(null)

  // Grow with the question, up to a ceiling — past that the field scrolls
  // rather than pushing the trace off the screen.
  React.useEffect(() => {
    const el = ref.current
    if (!el) return
    el.style.height = "auto"
    el.style.height = `${Math.min(el.scrollHeight, 160)}px`
  }, [value])

  const send = () => {
    if (isRunning || !value.trim()) return
    onSend()
  }

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <div className="border-hairline bg-surface focus-within:border-hairline-strong flex items-end gap-2 rounded-sm border p-2 transition-colors">
        <textarea
          ref={ref}
          rows={1}
          value={value}
          maxLength={QUESTION_MAX}
          onChange={(event) => onChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
              event.preventDefault()
              send()
            }
          }}
          placeholder={t("saqr.placeholder")}
          aria-label={t("saqr.placeholder")}
          disabled={isRunning}
          className={cn(
            "text-ink placeholder:text-ink-faint min-w-0 flex-1 resize-none bg-transparent",
            "px-1 py-1 text-sm leading-relaxed outline-none disabled:opacity-60"
          )}
        />

        <div className="flex shrink-0 items-center gap-1.5">
          {canRetry && !isRunning && (
            <Button
              size="sm"
              variant="ghost"
              onClick={onRetry}
              aria-label={t("saqr.retry")}
              title={t("saqr.retry")}
            >
              <RotateCcw aria-hidden="true" />
              <span className="hidden sm:inline">{t("saqr.retry")}</span>
            </Button>
          )}

          {isRunning ? (
            <Button size="sm" variant="secondary" onClick={onCancel}>
              <Square aria-hidden="true" />
              {t("saqr.stop")}
            </Button>
          ) : (
            <Button size="sm" onClick={send} disabled={!value.trim()}>
              <CornerDownLeft aria-hidden="true" />
              {t("saqr.send")}
            </Button>
          )}
        </div>
      </div>

      <p className="text-ink-faint text-xs">{t("saqr.enterHint")}</p>
    </div>
  )
}
