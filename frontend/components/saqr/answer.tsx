"use client"

/**
 * The answer — the last section of the run document, and the only part of the
 * page set as prose rather than as evidence.
 *
 * Two things it has to get right. The text is **Markdown**: the model writes
 * `**bold**`, pipe tables and inline code, and a pane that renders the string
 * raw prints those characters literally. And it is model prose carrying MACs,
 * timestamps and class identifiers, so it goes through `SaqrMarkdown`, which
 * escapes everything through React (there is no `dangerouslySetInnerHTML` on
 * this path) and isolates every technical run as a whole Latin island.
 *
 * The caret is a real signal, not decoration: it is shown while, and only
 * while, `token` events are still arriving. Nothing here animates typing that
 * has not happened.
 */
import * as React from "react"
import { Check, Copy } from "lucide-react"

import { Eyebrow } from "@/components/hs/eyebrow"
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
    <section className={cn("flex min-w-0 flex-col gap-4", className)}>
      <header className="border-rule flex flex-wrap items-center gap-x-4 gap-y-1 border-b pb-2">
        <Eyebrow>{t("saqr.answer.title")}</Eyebrow>
        {text && (
          <Button
            size="sm"
            variant="ghost"
            onClick={copy}
            aria-label={t("saqr.answer.copy")}
            className="ms-auto"
          >
            {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
            <span className="hidden sm:inline">
              {copied ? t("saqr.answer.copied") : t("saqr.answer.copy")}
            </span>
          </Button>
        )}
      </header>

      {/* A reading measure. Prose that runs the full width of a result table is
          prose nobody finishes; the tables above are allowed to be wider than
          the sentence that explains them. */}
      <div className="min-w-0 max-w-[68ch]">
        <SaqrMarkdown text={text} />
        {streaming && (
          // A block caret on the prose baseline, shown only while `token`
          // events are actually arriving.
          <span
            aria-hidden="true"
            className="bg-accent ms-0.5 inline-block h-[1em] w-[0.5ch] translate-y-[0.15em] animate-pulse"
          />
        )}
      </div>

      {usedTools && usedTools.length > 0 && (
        <p className="text-ink-2 flex flex-wrap items-baseline gap-x-2 gap-y-1 text-xs">
          <span className="hs-label">{t("saqr.answer.usedTools")}</span>
          {usedTools.map((tool) => (
            <Code key={tool} className="text-ink-2">
              {tool}
            </Code>
          ))}
        </p>
      )}
    </section>
  )
}
