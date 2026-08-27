"use client"

/**
 * A small, safe Markdown renderer for Saqr's prose.
 *
 * Three constraints produced exactly this and nothing more:
 *
 * **No new dependency.** The answer is the one place in the product that
 * renders model-authored text, and the old chat pane shipped `**bold**` to the
 * screen literally because it rendered the string raw.
 *
 * **No `dangerouslySetInnerHTML`.** Everything here builds React elements, so
 * the model's text is escaped by React itself — there is no HTML-injection path
 * to get wrong, and none to review later. A raw `<script>` in an answer renders
 * as the characters `<script>`.
 *
 * **Bidi isolation is not optional.** This is the worst bidi surface in the
 * product: Arabic prose carrying MAC addresses, timestamps, class identifiers
 * and counts. Any Latin/numeric run mixed with neutral characters (`:` `.` `-`
 * `/` `(` `)`) is *visually reordered* by the bidi algorithm while the DOM stays
 * correct — a MAC renders with its octets shuffled and nothing looks broken.
 * `isolate()` below wraps every such run so that cannot happen, and it can only
 * ever match Latin/digit text, so Arabic prose passes through untouched.
 *
 * The supported subset is what the model actually emits: headings, bold,
 * italic, inline code, fenced code, ordered and unordered lists, block quotes,
 * pipe tables, horizontal rules and hard line breaks. Anything else is shown as
 * the literal characters the model wrote, which is honest and never wrong.
 */
import * as React from "react"

import { Code, Ltr, Mac } from "@/lib/format"
import { cn } from "@/lib/utils"

/* ── Bidi isolation ──────────────────────────────────────────────────────── */

/**
 * A maximal **Latin island**: a run of Latin letters/digits together with the
 * neutral punctuation that binds them, optionally opened by a bracket, and
 * always closed on a strong character.
 *
 * Isolating individual tokens is not enough, and this is the bug that proves
 * it. Saqr wrote `5180 MHz (ch 36, 5 GHz)` inside an Arabic sentence. With
 * token-level isolation, `5180`, `36` and `5` became three LTR islands and the
 * neutral text between them — `MHz (ch `, `, `, ` GHz)` — took the paragraph's
 * RTL direction. The cell rendered as `(ch 36, 5 GHz) 5180`: every character
 * correct, the order a lie. The unit of isolation has to be the whole Latin
 * phrase, not the tokens inside it.
 *
 * Arabic letters are deliberately outside the class, so a run always stops at
 * the first Arabic character and Arabic prose is never captured. Requiring the
 * match to *end* on a letter, digit or closing bracket keeps the trailing space
 * before an Arabic word outside the island, where it belongs.
 *
 * The optional leading operator is the second half of the same bug, and it is
 * worth spelling out because it survived the first fix. A minus is a *neutral*
 * character, so an island that starts at the digit leaves the sign outside it —
 * where the paragraph's RTL direction moves it to the far end of the run, and
 * `-60 dBm` renders as `60 dBm-`. Every RSSI reading in this product is
 * negative, so this was not an edge case, and the same happens to the `~` in
 * `(~99.38%)` and the `<` in `<10 ms`. All of them are only allowed to open an
 * island when a digit follows immediately, so a dash between two Arabic words
 * is still ordinary punctuation and never starts a Latin run.
 */
const latinIslandScanner = () =>
  /[([{]?(?:[-−+~≈<>≤≥](?=\d))?[A-Za-z0-9_](?:[A-Za-z0-9_ .,:;'"()[\]<>=+\-/*%&#!?@~$^|≈×·]*[A-Za-z0-9_)\]%])?/g

/**
 * Inside an island the direction is already settled, so this picks out only the
 * two things that still deserve their own treatment: a MAC, which `<Mac>`
 * upper-cases and gives a title, and a standalone figure, which takes the
 * tabular mono face.
 *
 * The thousands group must be a full `,ddd`, which is why `36,` in
 * `(ch 36, 5 GHz)` is no longer swallowed as a malformed separator: `36` is the
 * figure and the comma is punctuation, exactly as written.
 */
const islandTokenScanner = () =>
  /[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|[-−+]?\d{1,3}(?:,\d{3})+(?:\.\d+)?%?|[-−+]?\d+(?:\.\d+)?%?/g

const MAC_TOKEN = /^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$/
/**
 * A character that makes an adjacent digit run part of an identifier rather
 * than a figure. `:` and `/` are in here because a digit beside either is a
 * clock, a MAC octet or a path segment — `18:54:36` must not shed two figures.
 */
const IDENTIFIER_CHAR = /[A-Za-z0-9_.:/\-]/

function renderIsland(island: string, keyPrefix: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  const scanner = islandTokenScanner()
  let cursor = 0
  let n = 0

  let match = scanner.exec(island)
  while (match !== null) {
    const token = match[0]
    const start = match.index
    const end = start + token.length
    if (start > cursor) out.push(island.slice(cursor, start))
    const key = `${keyPrefix}-k${n++}`

    if (MAC_TOKEN.test(token)) {
      out.push(<Mac key={key} value={token} className="text-[0.95em]" />)
    } else if (
      /*
       * A figure only when it stands alone. Without this check the digits
       * *inside* identifiers get set in the tabular face and read as counts:
       * `Kr00k` becomes `Kr` + `00` + `k`, `deepseek-v4-flash` grows a figure,
       * `802.11w` becomes `802.11` + `w`, and a timestamp shatters into six.
       * Checking the characters either side is done here rather than with a
       * lookbehind so the pattern stays portable and legible.
       */
      !IDENTIFIER_CHAR.test(island[start - 1] ?? " ") &&
      !IDENTIFIER_CHAR.test(island[end] ?? " ")
    ) {
      out.push(
        <span key={key} className="hs-num">
          {token}
        </span>
      )
    } else {
      out.push(token)
    }

    cursor = end
    match = scanner.exec(island)
  }

  if (cursor < island.length) out.push(island.slice(cursor))
  return out
}

function isolate(text: string, keyPrefix: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  let cursor = 0
  let n = 0

  /*
   * A fresh instance per call, never a shared `/g` literal.
   *
   * `lastIndex` is mutable state living on the regex *object*, and these
   * scanners are re-entered: `renderInline` recurses into itself for the
   * contents of an emphasis span, and that inner loop runs `exec` to
   * exhaustion, which resets `lastIndex` to 0. Control then returns to the
   * outer loop, which resumes scanning from the start of its own string. That
   * is not a mis-render — it is a loop that never terminates and pins the tab,
   * and it only shows up once a model writes its first `**bold**`.
   */
  const islands = latinIslandScanner()
  let match = islands.exec(text)
  while (match !== null) {
    const island = match[0]
    // A zero-width match cannot happen (the pattern requires one alphanumeric),
    // but a guard here is cheaper than another hung tab.
    if (island.length === 0) {
      islands.lastIndex += 1
      match = islands.exec(text)
      continue
    }
    if (match.index > cursor) out.push(text.slice(cursor, match.index))
    const key = `${keyPrefix}-i${n++}`
    out.push(<Ltr key={key}>{renderIsland(island, key)}</Ltr>)
    cursor = match.index + island.length
    match = islands.exec(text)
  }

  if (cursor < text.length) out.push(text.slice(cursor))
  return out
}

/**
 * Plain text with its technical runs isolated, and nothing else interpreted.
 *
 * For the places that carry a MAC or a timestamp inside ordinary prose but are
 * not Markdown: a suggestion chip, the operator's own question. `bdi` isolates
 * the string as a whole without forcing a direction on it — the text may be in
 * either language — while `isolate` protects the runs inside it.
 */
export function TechnicalText({ text, className }: { text: string; className?: string }) {
  const parts = React.useMemo(() => isolate(text, "tt"), [text])
  return <bdi className={className}>{parts}</bdi>
}

/* ── Inline spans ────────────────────────────────────────────────────────── */

/**
 * Code first, then the two-character emphasis markers, then the
 * single-character ones — otherwise `**bold**` is eaten as an empty italic.
 * A link renders as its text only: an answer is not a place from which to
 * navigate, and a model-authored `href` is not a thing to hand a browser.
 */
const inlineScanner = () =>
  /(`+)([\s\S]*?)\1|\*\*([\s\S]+?)\*\*|__([\s\S]+?)__|\*([^*\n]+?)\*|_([^_\n]+?)_|\[([^\]]*)\]\([^)\s]*\)/g

function renderInline(text: string, keyPrefix: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  let cursor = 0
  let n = 0

  // Per-call instance — see the note in `isolate`. This one is the reason that
  // note exists: `renderInline` recurses.
  const inline = inlineScanner()
  let match = inline.exec(text)
  while (match !== null) {
    if (match.index > cursor) {
      out.push(...isolate(text.slice(cursor, match.index), `${keyPrefix}-t${n}`))
    }
    const key = `${keyPrefix}-m${n++}`
    const [whole, , code, boldStar, boldUnder, italStar, italUnder, linkText] = match

    if (code !== undefined) {
      // A code span is very often a MAC in this product. `<Mac>` and `<Code>`
      // are both isolated and monospaced; `<Mac>` additionally normalises case
      // and gives the value a title, which is worth the branch.
      const body = code.trim()
      out.push(
        /^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$/.test(body) ? (
          <Mac key={key} value={body} className="text-[0.95em]" />
        ) : (
          <Code
            key={key}
            className="bg-paper-2 border-rule rounded-sm border px-1 py-px text-[0.9em]"
          >
            {body}
          </Code>
        )
      )
    } else if (boldStar !== undefined || boldUnder !== undefined) {
      out.push(
        <strong key={key} className="text-ink-0 font-semibold">
          {renderInline(boldStar ?? boldUnder ?? "", key)}
        </strong>
      )
    } else if (italStar !== undefined || italUnder !== undefined) {
      out.push(
        <em key={key} className="italic">
          {renderInline(italStar ?? italUnder ?? "", key)}
        </em>
      )
    } else if (linkText !== undefined) {
      out.push(<React.Fragment key={key}>{renderInline(linkText, key)}</React.Fragment>)
    }

    cursor = match.index + whole.length
    match = inline.exec(text)
  }

  if (cursor < text.length) out.push(...isolate(text.slice(cursor), `${keyPrefix}-t${n}`))
  return out
}

/** Join lines of one paragraph with hard breaks, the way a chat answer reads. */
function withBreaks(lines: string[], keyPrefix: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  lines.forEach((line, i) => {
    if (i > 0) out.push(<br key={`${keyPrefix}-br${i}`} />)
    out.push(...renderInline(line, `${keyPrefix}-l${i}`))
  })
  return out
}

/* ── Blocks ──────────────────────────────────────────────────────────────── */

const FENCE = /^\s*(```|~~~)/
const HEADING = /^(#{1,6})\s+(.*)$/
const RULE = /^\s*([-*_])(?:\s*\1){2,}\s*$/
const QUOTE = /^\s*>\s?(.*)$/
const BULLET = /^\s*[-*+]\s+(.*)$/
const NUMBERED = /^\s*(\d+)[.)]\s+(.*)$/
const TABLE_DIVIDER = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/

function splitRow(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => cell.trim())
}

export interface SaqrMarkdownProps {
  text: string
  className?: string
}

/**
 * Render Saqr's answer.
 *
 * Every block below carries `dir="auto"` rather than inheriting the page
 * direction, and that is not a detail. Saqr answers in the locale it was asked
 * in, but the two can disagree — the operator switches language mid-session, or
 * reads back an earlier run — and an English paragraph inheriting `rtl` is
 * re-ordered wholesale: the sentence renders end-first with every word intact,
 * which looks like a model failure rather than a layout one. `auto` resolves
 * each block from its own first strong character, so an Arabic answer reads
 * right-to-left and an English one reads left-to-right on the same page.
 */
export function SaqrMarkdown({ text, className }: SaqrMarkdownProps) {
  const blocks = React.useMemo(() => parseBlocks(text), [text])
  return (
    <div className={cn("text-ink-0 flex flex-col gap-3 text-base leading-relaxed", className)}>
      {blocks}
    </div>
  )
}

function parseBlocks(text: string): React.ReactNode[] {
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n")
  const out: React.ReactNode[] = []
  let i = 0
  let n = 0

  while (i < lines.length) {
    const line = lines[i]
    const key = `b${n++}`

    /* blank ------------------------------------------------------------- */
    if (line.trim() === "") {
      i += 1
      continue
    }

    /* fenced code ------------------------------------------------------- */
    if (FENCE.test(line)) {
      const fence = line.trim().slice(0, 3)
      const body: string[] = []
      i += 1
      while (i < lines.length && !lines[i].trim().startsWith(fence)) {
        body.push(lines[i])
        i += 1
      }
      // An unterminated fence is common in a stream that is still arriving; the
      // partial body is shown rather than swallowed until the closer lands.
      if (i < lines.length) i += 1
      out.push(
        <pre
          key={key}
          dir="ltr"
          className="bg-paper-2 border-rule overflow-x-auto rounded-md border p-3"
        >
          <Code className="text-ink-2 text-xs whitespace-pre">{body.join("\n")}</Code>
        </pre>
      )
      continue
    }

    /* heading ----------------------------------------------------------- */
    const heading = HEADING.exec(line)
    if (heading) {
      const depth = Math.min(6, heading[1].length)
      out.push(
        <p
          key={key}
          dir="auto"
          role="heading"
          aria-level={Math.min(6, depth + 2)}
          className={cn(
            "text-ink-0 font-display font-medium",
            depth <= 2 ? "text-lg" : "text-base"
          )}
        >
          {renderInline(heading[2], key)}
        </p>
      )
      i += 1
      continue
    }

    /* horizontal rule --------------------------------------------------- */
    if (RULE.test(line)) {
      out.push(<hr key={key} className="border-rule border-t" />)
      i += 1
      continue
    }

    /* table -------------------------------------------------------------- */
    if (line.includes("|") && i + 1 < lines.length && TABLE_DIVIDER.test(lines[i + 1])) {
      const header = splitRow(line)
      i += 2
      const body: string[][] = []
      while (i < lines.length && lines[i].includes("|") && lines[i].trim() !== "") {
        body.push(splitRow(lines[i]))
        i += 1
      }
      out.push(
        // Prose tables are the one thing in an answer that can exceed the
        // column; it scrolls inside its own box rather than widening the page.
        <div key={key} className="border-rule overflow-x-auto rounded-md border">
          <table dir="auto" className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-rule border-b">
                {header.map((cell, c) => (
                  <th
                    key={`${key}-h${c}`}
                    dir="auto"
                    scope="col"
                    className="hs-label px-2.5 py-1.5 text-start whitespace-nowrap"
                  >
                    {renderInline(cell, `${key}-h${c}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {body.map((row, r) => (
                <tr key={`${key}-r${r}`} className="border-rule border-b last:border-b-0">
                  {header.map((_, c) => (
                    <td
                      key={`${key}-r${r}c${c}`}
                      dir="auto"
                      className="text-ink-2 px-2.5 py-1.5 text-start"
                    >
                      {renderInline(row[c] ?? "", `${key}-r${r}c${c}`)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
      continue
    }

    /* block quote -------------------------------------------------------- */
    if (QUOTE.test(line)) {
      const body: string[] = []
      while (i < lines.length) {
        const quoted = QUOTE.exec(lines[i])
        if (!quoted) break
        body.push(quoted[1])
        i += 1
      }
      out.push(
        // `border-s` / `ps-3`: the quote rule sits on the reading edge in both
        // directions. A `border-l` would land on the wrong side in Arabic.
        <blockquote
          key={key}
          dir="auto"
          className="border-rule-soft text-ink-1 border-s-2 ps-3"
        >
          {withBreaks(body, key)}
        </blockquote>
      )
      continue
    }

    /* lists --------------------------------------------------------------- */
    const ordered = NUMBERED.test(line)
    if (ordered || BULLET.test(line)) {
      const items: string[] = []
      let start = 1
      while (i < lines.length) {
        const match = ordered ? NUMBERED.exec(lines[i]) : BULLET.exec(lines[i])
        if (!match) break
        if (ordered && items.length === 0) start = Number(match[1]) || 1
        items.push(ordered ? match[2] : match[1])
        i += 1
      }
      const ListTag = ordered ? "ol" : "ul"
      out.push(
        // `ps-5` and `list-inside`-free markers: the marker column mirrors with
        // the text instead of being pinned to the physical left edge.
        React.createElement(
          ListTag,
          {
            key,
            start: ordered ? start : undefined,
            className: cn(
              "flex flex-col gap-1.5 ps-5",
              ordered ? "list-decimal" : "list-disc"
            ),
          },
          items.map((item, index) => (
            <li key={`${key}-li${index}`} dir="auto" className="marker:text-ink-3 ps-1">
              {renderInline(item, `${key}-li${index}`)}
            </li>
          ))
        )
      )
      continue
    }

    /* paragraph ----------------------------------------------------------- */
    const paragraph: string[] = []
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !FENCE.test(lines[i]) &&
      !HEADING.test(lines[i]) &&
      !RULE.test(lines[i]) &&
      !QUOTE.test(lines[i]) &&
      !BULLET.test(lines[i]) &&
      !NUMBERED.test(lines[i]) &&
      !(lines[i].includes("|") && i + 1 < lines.length && TABLE_DIVIDER.test(lines[i + 1]))
    ) {
      paragraph.push(lines[i])
      i += 1
    }
    if (paragraph.length > 0) {
      out.push(
        <p key={key} dir="auto" className="text-ink-0">
          {withBreaks(paragraph, key)}
        </p>
      )
    } else {
      // Defensive: a line that matched nothing and consumed nothing would spin.
      out.push(
        <p key={key} dir="auto" className="text-ink-0">
          {renderInline(line, key)}
        </p>
      )
      i += 1
    }
  }

  return out
}
