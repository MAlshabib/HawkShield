"use client"

/**
 * A destructive action Saqr described but **did not perform**.
 *
 * An admin-gated tool answers a request to change data with a plan and a
 * one-shot token instead of acting:
 *
 * ```json
 * { "requires_confirmation": true, "action": "delete_detections",
 *   "summary": "...", "affected_estimate": 128,
 *   "confirm_token": "...", "expires_in_s": 120 }
 * ```
 *
 * This card is the only place that token can be spent, and the only thing that
 * spends it is a person pressing Confirm. There is no timer, no "confirm if the
 * estimate is small", no confirm-on-Enter and no path through `lib/saqr.ts`
 * that reaches `confirmAction` by itself. Declining sends nothing at all —
 * a token that never leaves the browser cannot act.
 *
 * The stated expiry is a fact about the token, not a countdown: it is printed
 * once, from `expires_in_s`, and never animated down to zero. A card that
 * counts down is a card that pressures a decision, and the failure mode of an
 * expired token is benign — the server refuses it and Saqr proposes again.
 *
 * Three things are stated before the buttons, because a person cannot consent
 * to something they have not been told: **what** would happen (the machine
 * action name and the server's own sentence), **how much** it touches (the
 * row estimate, or an explicit statement that none was reported), and that
 * nothing has happened yet.
 *
 * The card is defensive by construction. `readConfirmation` returns `null` for
 * every result today's backend sends, so this renders nowhere until the field
 * appears on the wire; and a confirmation that arrives *without* a usable token
 * still renders, with Confirm disabled, rather than silently vanishing.
 */
import * as React from "react"
import { ShieldAlert } from "lucide-react"

import { StatusPill } from "@/components/hs/status-pill"
import { Button } from "@/components/ui/button"
import { Code, Ltr, useFormatters } from "@/lib/format"
import { useT } from "@/lib/i18n"
import type { SaqrConfirmation, SaqrConfirmState } from "@/lib/saqr"
import { cn } from "@/lib/utils"

export function SaqrConfirmCard({
  confirmation,
  question,
  state,
  busy,
  onConfirm,
  onCancel,
  className,
}: {
  confirmation: SaqrConfirmation
  /** The question this action belongs to; re-sent verbatim with the token. */
  question: string
  /** `undefined` until the operator has decided. */
  state: SaqrConfirmState | undefined
  /** A run is open. Confirming would be refused, so the control says why. */
  busy: boolean
  onConfirm: (token: string, question: string) => void
  onCancel: (token: string) => void
  className?: string
}) {
  const t = useT()
  const f = useFormatters()

  const settled = state === "confirmed" || state === "cancelled"
  const token = confirmation.token

  return (
    <div
      role="group"
      aria-label={t("saqr.confirm.title")}
      className={cn(
        "flex min-w-0 flex-col gap-3 rounded-lg border p-4",
        // The caution grade, not the critical one: critical is reserved for a
        // detection the sensor made, and this is a question being put to the
        // operator. Tinted with `color-mix` against the live token so it
        // re-themes with its subtree rather than needing a `dark:` twin.
        settled
          ? "border-rule-soft bg-paper-1"
          : [
              "border-[color-mix(in_oklch,var(--sev-high)_36%,transparent)]",
              "bg-[color-mix(in_oklch,var(--sev-high)_10%,transparent)]",
            ],
        className
      )}
    >
      <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-2">
        <ShieldAlert aria-hidden="true" className="text-sev-high size-4 shrink-0" />
        <span className="text-ink-0 text-sm font-medium">{t("saqr.confirm.title")}</span>
        {!settled && <StatusPill tone="high">{t("saqr.confirm.pending")}</StatusPill>}
      </div>

      <p className="text-ink-1 text-sm">{t("saqr.confirm.lead")}</p>

      {/* The machine name of the action, beside its label. It is an identifier
          and stays Latin in both languages, so it is isolated as a whole. */}
      {confirmation.action && (
        <p className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-1">
          <span className="hs-label">{t("saqr.confirm.action")}</span>
          <Code className="text-ink-1 text-xs">{confirmation.action}</Code>
        </p>
      )}

      {/* The server's own sentence, shown verbatim. It is evidence of what the
          backend intends to do, and paraphrasing it here would make this card
          a claim about the action rather than a quotation of it. */}
      {confirmation.summary && (
        <p className="min-w-0">
          <Ltr className="text-ink-1 font-mono text-xs break-words">{confirmation.summary}</Ltr>
        </p>
      )}

      {/* How much it touches. An absent estimate is stated, never rendered as
          zero — "affects 0 rows" is a different claim from "we did not count". */}
      <p className="text-ink-1 text-sm">
        {confirmation.affectedEstimate === null
          ? t("saqr.confirm.affectedUnknown")
          : t("saqr.confirm.affected", { n: f.number(confirmation.affectedEstimate) })}
      </p>

      {confirmation.expiresInS !== null && !settled && (
        <p className="text-ink-2 text-xs">
          {t("saqr.confirm.expires", { s: f.number(Math.round(confirmation.expiresInS)) })}
        </p>
      )}

      {settled ? (
        <p className="text-ink-2 text-sm">
          {state === "confirmed" ? t("saqr.confirm.sent") : t("saqr.confirm.cancelled")}
        </p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            {/* Cancel comes first in source order so the keyboard path reaches
                the safe control before the destructive one. */}
            <Button
              size="sm"
              variant="outline"
              onClick={() => token && onCancel(token)}
              disabled={!token}
            >
              {t("saqr.confirm.cancel")}
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => token && onConfirm(token, question)}
              disabled={!token || busy}
            >
              {t("saqr.confirm.confirm")}
            </Button>
          </div>
          {busy && token && <p className="text-ink-2 text-xs">{t("saqr.confirm.busy")}</p>}
        </>
      )}
    </div>
  )
}
