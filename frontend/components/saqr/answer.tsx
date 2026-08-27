"use client"

/**
 * The answer pane.
 *
 * Two things it must get right. The text is **Markdown** — the model writes
 * `**bold**`, pipe tables and inline code, and the pane this replaces printed
 * those characters literally. And it is model prose that carries MACs,
 * timestamps and class identifiers, so it goes through `SaqrMarkdown`, which
 * isolates every one of them (see the bidi note there).
 *
 * The caret is a real signal, not decoration: it is shown while, and only
 * while, `token` events are still arriving. Nothing here animates typing that
 * has not happened.
 */
import * as React from "react"
import { Check, Copy } from "lucide-react"

import { SaqrMarkdown } from "@/components/saqr/markdown"
import { Button } from "@/components/ui/button"
import { Code } from "@/lib/format"
import { useT } from "@/lib/i18n"
import { cn } from "@/lib/utils"

export function SaqrAnswer({
  text,
  usedTools,
  streaming = false,
  className,
}: {
  text: string
  usedTools?: readonly string[]
  streaming?: boolean
  className?: string
}) {
  const t = useT()
  const [copied, setCopied] = React.useState(false)

  React.useEffect(() => {
    if (!copied) return
    const id = window.setTimeout(() => setCopied(false), 2000)
    return () => window.clearTimeout(id)
  }, [copied])

  const copy = React.useCallback(() => {
    // `navigator.clipboard` is undefined on an insecure origin, which is how
    // this is served on the Pi's LAN address. Failing silently would leave the
    // button looking broken; the state simply never flips instead.
    void navigator.clipboard
      ?.writeText(text)
      .then(() => setCopied(true))
      .catch(() => setCopied(false))
  }, [text])

  if (!text && !streaming) return null

  return (
    <section
      className={cn("border-hairline bg-surface-sunken flex flex-col gap-2 rounded-sm border p-3", className)}
      aria-label={t("saqr.answer.title")}
    >
      <header className="flex items-center gap-2">
        <span className="hs-label">{t("saqr.answer.title")}</span>
        <div className="ms-auto flex items-center gap-1">
          {text && (
            <Button
              size="sm"
              variant="ghost"
              onClick={copy}
              aria-label={t("saqr.answer.copy")}
              title={t("saqr.answer.copy")}
            >
              {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
              <span className="hidden sm:inline">
                {copied ? t("saqr.answer.copied") : t("saqr.answer.copy")}
              </span>
            </Button>
          )}
        </div>
      </header>

      <div className="min-w-0">
        <SaqrMarkdown text={text} />
        {streaming && (
          // A block caret in the mono face, on the same baseline as the prose.
          <span
            aria-hidden="true"
            className="bg-hs-azure ms-0.5 inline-block h-[1em] w-[0.5ch] translate-y-[0.15em] animate-pulse"
          />
        )}
      </div>

      {usedTools && usedTools.length > 0 && (
        <p className="text-ink-faint flex flex-wrap items-baseline gap-x-2 gap-y-1 text-xs">
          <span className="hs-label">{t("saqr.answer.usedTools")}</span>
          {usedTools.map((tool) => (
            <Code key={tool} className="text-ink-dim">
              {tool}
            </Code>
          ))}
        </p>
      )}
    </section>
  )
}
