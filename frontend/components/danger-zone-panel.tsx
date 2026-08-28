"use client"

/**
 * Operator control for `POST /admin/purge` — the "delete all detections" lever.
 *
 * Deleting the `packets` table returns every count on every surface to zero, so
 * this is the most destructive thing the console can do. It is never a one-click
 * wipe: the button opens a confirmation dialog that states exactly what happens,
 * shows the current stored count, and stays disabled until the operator types
 * the sentinel word. The copy speaks of *detections* / *records* — an attack is
 * an event in the world, a row is our record of one, and only the record is
 * being deleted.
 *
 * Errors are mapped in `lib/purge.ts` (which never throws) and rendered as a
 * localised line, exactly as the simulate panel renders `lib/simulate.ts`.
 */
import * as React from "react"
import { Loader2, Trash2, TriangleAlert } from "lucide-react"

import { Panel } from "@/components/hs/panel"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { useToast } from "@/hooks/use-toast"
import { useFormatters } from "@/lib/format"
import { useT } from "@/lib/i18n"
import {
  PURGE_SENTINEL,
  runPurge,
  type PurgeMessage,
  type PurgeResult,
  type PurgeScope,
} from "@/lib/purge"

// The one red on the page, mixed to a hairline so the panel reads as a warning
// edge rather than a filled alarm — the same idiom the connection banner uses.
const CRITICAL_EDGE = "border-[color-mix(in_oklch,var(--sev-critical)_42%,transparent)]"

export function DangerZonePanel({
  storedCount,
  onPurged,
  className,
}: {
  /** Current `/health.packets`, or null while the probe is still in flight. */
  storedCount: number | null
  /** Called after a successful purge so the host page can refresh its figures. */
  onPurged?: () => void
  className?: string
}) {
  const t = useT()
  const f = useFormatters()
  const { toast } = useToast()

  const [open, setOpen] = React.useState(false)
  const [scope, setScope] = React.useState<PurgeScope>("all")
  const [typed, setTyped] = React.useState("")
  const [running, setRunning] = React.useState(false)
  const [error, setError] = React.useState<{ title: PurgeMessage; message: PurgeMessage; detail: string | null } | null>(null)
  const [last, setLast] = React.useState<PurgeResult | null>(null)

  const confirmed = typed === PURGE_SENTINEL

  const start = (next: PurgeScope) => {
    setScope(next)
    setTyped("")
    setError(null)
    setOpen(true)
  }

  // Reset the transient state whenever the dialog closes, so a re-open is clean.
  const onOpenChange = (next: boolean) => {
    setOpen(next)
    if (!next && !running) {
      setTyped("")
      setError(null)
    }
  }

  const confirm = async () => {
    if (!confirmed || running) return
    setRunning(true)
    setError(null)
    const outcome = await runPurge(scope)
    setRunning(false)

    if (outcome.ok) {
      setLast(outcome.result)
      setOpen(false)
      setTyped("")
      toast({
        title: t("admin.purge.done"),
        description: t("admin.purge.doneDetail", { n: f.number(outcome.result.deleted) }),
      })
      onPurged?.()
    } else {
      setError({ title: outcome.title, message: outcome.message, detail: outcome.detail })
      toast({
        variant: "destructive",
        title: t(outcome.title.key, outcome.title.vars),
        description: t(outcome.message.key, outcome.message.vars),
      })
    }
  }

  const countKnown = typeof storedCount === "number"

  return (
    <Panel
      label={t("admin.purge.title")}
      title={t("admin.purge.subtitle")}
      aria-label={t("admin.purge.aria")}
      className={`${CRITICAL_EDGE}${className ? ` ${className}` : ""}`}
    >
      <div className="flex flex-col gap-4">
        <p className="text-ink-1 max-w-[68ch] text-sm">{t("admin.purge.explainer")}</p>

        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <Button variant="destructive" onClick={() => start("all")}>
            <Trash2 aria-hidden="true" />
            {t("admin.purge.deleteAll")}
          </Button>
          <Button variant="outline" onClick={() => start("simulated")}>
            {t("admin.purge.deleteSimulated")}
          </Button>
          <span className="hs-label ms-auto">
            {countKnown ? (
              <>
                {t("admin.purge.storedNow")}{" "}
                <span className="hs-num text-ink-0">{f.number(storedCount as number)}</span>
              </>
            ) : (
              t("admin.purge.storedUnknown")
            )}
          </span>
        </div>

        {last && (
          <p className="text-ink-2 text-xs">
            {t("admin.purge.lastRun", { n: f.number(last.deleted) })}
          </p>
        )}
      </div>

      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className={CRITICAL_EDGE}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <TriangleAlert className="text-sev-critical size-5 shrink-0" aria-hidden="true" />
              {scope === "all"
                ? t("admin.purge.dialog.titleAll")
                : t("admin.purge.dialog.titleSimulated")}
            </DialogTitle>
            <DialogDescription>
              {scope === "all"
                ? t("admin.purge.dialog.bodyAll")
                : t("admin.purge.dialog.bodySimulated")}
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-4">
            {/* The current stored count, so the operator knows the size of what
                they are about to remove. */}
            <div className="border-rule-soft bg-paper-2 flex items-center justify-between gap-3 rounded-md border px-3 py-2">
              <span className="hs-label">{t("admin.purge.storedNow")}</span>
              <span className="hs-num text-ink-0 text-sm">
                {countKnown ? f.number(storedCount as number) : "—"}
              </span>
            </div>

            {/* Type-to-enable. The sentinel is Latin in every locale, so the
                label carries it in an LTR span and the Arabic copy tells the
                operator to type the Latin word. */}
            <div className="flex flex-col gap-1.5">
              <label htmlFor="purge-confirm" className="text-ink-1 text-sm">
                {t("admin.purge.typeToConfirm")}{" "}
                <span className="hs-ltr text-ink-0 font-mono font-medium">{PURGE_SENTINEL}</span>
              </label>
              <Input
                id="purge-confirm"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                aria-invalid={typed.length > 0 && !confirmed}
                className="hs-ltr font-mono"
                placeholder={PURGE_SENTINEL}
              />
            </div>

            {error && (
              <div className="border-rule-soft bg-paper-2 flex flex-col gap-1 rounded-md border p-3">
                <span className="text-sev-critical text-sm font-medium">
                  {t(error.title.key, error.title.vars)}
                </span>
                <span className="text-ink-1 text-xs">
                  {t(error.message.key, error.message.vars)}
                </span>
                {error.detail && (
                  <span className="hs-ltr text-ink-2 font-mono text-xs">{error.detail}</span>
                )}
              </div>
            )}
          </div>

          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" disabled={running}>
                {t("common.cancel")}
              </Button>
            </DialogClose>
            <Button variant="destructive" onClick={confirm} disabled={!confirmed || running}>
              {running ? (
                <Loader2 className="animate-spin" aria-hidden="true" />
              ) : (
                <Trash2 aria-hidden="true" />
              )}
              {running
                ? t("admin.purge.deleting")
                : scope === "all"
                  ? t("admin.purge.confirmAll")
                  : t("admin.purge.confirmSimulated")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Panel>
  )
}

export default DangerZonePanel
