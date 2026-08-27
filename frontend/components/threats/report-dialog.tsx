"use client"

/**
 * The detection report: `GET /reports/summary?days=N` on screen, `POST
 * /reports/export` to disk.
 *
 * The V1 modal also offered "Send by email", which was a `mailto:` link with
 * the period and a total pasted into the body — no attachment, no server, and
 * `/reports/email` had already been removed from the contract. A share button
 * that shares nothing is worse than no share button, so it is gone. The PDF
 * download is real: the backend renders it and this streams the blob.
 */
import * as React from "react"
import { Download, FileText, Loader2 } from "lucide-react"

import { Panel } from "@/components/hs/panel"
import { StatusPill } from "@/components/hs/status-pill"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useToast } from "@/hooks/use-toast"
import { apiFetch, apiFetchJson } from "@/lib/api"
import { attackColorVar, attackLabels, severityOf } from "@/lib/colors"
import { toAttackType } from "@/lib/detections"
import { useFormatters } from "@/lib/format"
import { useLocale, useT, type TranslationKey } from "@/lib/i18n"

type ReportSummary = {
  period?: string
  totals?: Record<string, number>
  summary?: {
    totalAttacks?: number
    mostFrequentType?: string
    peakHour?: number
    uniqueSources?: number
  }
}

const REPORT_RANGES: readonly { days: number; key: TranslationKey }[] = [
  { days: 1, key: "time.range.hours24" },
  { days: 7, key: "time.range.days7" },
  { days: 30, key: "time.range.days30" },
]

function Line({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="border-rule flex items-baseline justify-between gap-4 border-b py-2 last:border-0">
      <span className="hs-label shrink-0">{label}</span>
      <span className="text-ink-0 min-w-0 text-end text-sm">{children}</span>
    </div>
  )
}

export function ReportDialog() {
  const t = useT()
  const f = useFormatters()
  const { dir } = useLocale()
  const { toast } = useToast()

  const [open, setOpen] = React.useState(false)
  const [days, setDays] = React.useState(7)
  const [data, setData] = React.useState<ReportSummary | null>(null)
  const [failed, setFailed] = React.useState(false)
  const [loading, setLoading] = React.useState(false)
  const [exporting, setExporting] = React.useState(false)

  React.useEffect(() => {
    if (!open) return
    let alive = true
    setLoading(true)
    setFailed(false)

    void (async () => {
      try {
        const json = await apiFetchJson<ReportSummary>(`/reports/summary?days=${days}`, {
          cache: "no-store",
        })
        if (alive) setData(json)
      } catch {
        if (alive) {
          setData(null)
          setFailed(true)
        }
      } finally {
        if (alive) setLoading(false)
      }
    })()

    return () => {
      alive = false
    }
  }, [open, days])

  const download = async () => {
    setExporting(true)
    try {
      const res = await apiFetch("/reports/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ days }),
      })
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      // The filename is an identifier, not copy: ASCII in both locales.
      a.download = `hawkshield-report-${days}d-${new Date().toISOString().slice(0, 10)}.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      toast({ title: t("report.downloaded"), description: t("report.downloadedDetail") })
    } catch {
      toast({ variant: "destructive", title: t("report.downloadFailed") })
    } finally {
      setExporting(false)
    }
  }

  const totals = data?.totals ?? null
  const classRows = React.useMemo(() => {
    if (!totals) return []
    return Object.entries(totals)
      .map(([key, n]) => {
        const type = toAttackType(key)
        return { key, type, value: Number(n) || 0 }
      })
      .filter((r) => r.value > 0)
      .sort((a, b) => b.value - a.value)
  }, [totals])

  const s = data?.summary
  const peak = typeof s?.peakHour === "number" ? s.peakHour : null
  const frequent = s?.mostFrequentType ? toAttackType(s.mostFrequentType) : null

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      {/* Not a DialogTrigger: the button also lives in a toolbar whose other
          controls are plain buttons, and asChild-wrapping changes its focus
          order relative to them. */}
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        <FileText aria-hidden="true" />
        {t("report.open")}
      </Button>

      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("report.title")}</DialogTitle>
          <DialogDescription>{t("report.description")}</DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="hs-label">{t("report.range")}</span>
            <Select dir={dir} value={String(days)} onValueChange={(v) => setDays(Number(v))}>
              <SelectTrigger className="w-44" aria-label={t("report.range")}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {REPORT_RANGES.map((r) => (
                  <SelectItem key={r.days} value={String(r.days)}>
                    {t(r.key)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <Panel label={t("report.summary")} loading={loading && !data}>
            {failed && !data ? (
              <p className="text-sev-critical hs-label py-4">{t("report.loadFailed")}</p>
            ) : (
              <div className="flex flex-col">
                <Line label={t("report.period")}>
                  {/* The backend composes this string itself ("Last 7 day(s)"),
                      so the localised range label is shown instead and the
                      server's own words are not passed off as translated. */}
                  {t(REPORT_RANGES.find((r) => r.days === days)?.key ?? "time.range.days7")}
                </Line>
                <Line label={t("dashboard.ledger.total")}>
                  <span className="hs-num">{f.number(s?.totalAttacks ?? null)}</span>
                </Line>
                <Line label={t("dashboard.ledger.uniqueSources")}>
                  <span className="hs-num">{f.number(s?.uniqueSources ?? null)}</span>
                </Line>
                <Line label={t("dashboard.peakHours")}>
                  {peak === null ? (
                    <span className="text-ink-2 text-xs">{t("report.notReported")}</span>
                  ) : (
                    // `18:00` is a clock reading; isolated so it cannot flip.
                    <span className="hs-num">{String(peak).padStart(2, "0")}:00</span>
                  )}
                </Line>
                <Line label={t("dashboard.classes.title")}>
                  {frequent === null ? (
                    <span className="text-ink-2 text-xs">{t("report.notReported")}</span>
                  ) : (
                    <span className="inline-flex items-center gap-2">
                      <span
                        aria-hidden="true"
                        className="size-2 shrink-0 rounded-full"
                        style={{ background: attackColorVar(frequent) }}
                      />
                      <span className="hs-ltr">{attackLabels[frequent]}</span>
                    </span>
                  )}
                </Line>
              </div>
            )}
          </Panel>

          <Panel label={t("report.byClass")} loading={loading && !data}>
            {classRows.length === 0 ? (
              <p className="hs-label py-4 text-center">
                {failed && !data ? t("report.loadFailed") : t("report.empty")}
              </p>
            ) : (
              <ul className="flex flex-col">
                {classRows.map((row) => (
                  <li
                    key={row.key}
                    className="border-rule flex items-center justify-between gap-3 border-b py-2 last:border-0"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span
                        aria-hidden="true"
                        className="size-2 shrink-0 rounded-full"
                        style={{ background: attackColorVar(row.type) }}
                      />
                      <span className="hs-ltr text-ink-0 truncate text-sm">
                        {attackLabels[row.type]}
                      </span>
                      <StatusPill tone={severityOf(row.type)}>
                        {t(`severity.${severityOf(row.type)}`)}
                      </StatusPill>
                    </span>
                    <span className="hs-num text-ink-0 shrink-0 text-sm">{f.number(row.value)}</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => setOpen(false)}>
            {t("common.close")}
          </Button>
          <Button onClick={download} disabled={exporting}>
            {exporting ? (
              <Loader2 className="animate-spin" aria-hidden="true" />
            ) : (
              <Download aria-hidden="true" />
            )}
            {exporting ? t("report.downloading") : t("report.download")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
