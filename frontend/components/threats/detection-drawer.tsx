"use client"

/**
 * Everything the sensor stored about one detection, in a sheet on the reading
 * edge.
 *
 * The V1 drawer showed "Duration" and "Packets". Neither has ever been present
 * on a `/attacks` row, so both were permanent em-dashes — which quietly taught
 * the operator that "—" means zero. They are dropped, not carried forward: a
 * field the backend cannot answer does not get a row here. Everything that IS
 * shown comes off the row, and anything null says "not reported" in words.
 *
 * Every value is a technical literal — MAC, hex, dBm, a channel number — so
 * every one goes through `<Mac>`, `<Timestamp>`, `hs-num` or `<Quantity>`. An
 * unisolated `-57 dBm` renders as `dBm 57-` inside the Arabic page; see
 * `components/quantity.tsx` for why a figure and its unit are isolated
 * separately rather than as one run.
 */
import * as React from "react"

import { Hairline } from "@/components/hs/hairline"
import { StatusPill } from "@/components/hs/status-pill"
import { Quantity } from "@/components/quantity"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { attackColorVar, attackLabels } from "@/lib/colors"
import { Mac, Timestamp, useFormatters } from "@/lib/format"
import { useLocale, useT } from "@/lib/i18n"
import type { Detection } from "@/components/threats/detection"

/** "Not reported" in words. Never a dash that could be read as a zero. */
function Unreported() {
  const t = useT()
  return <span className="text-ink-faint text-xs">{t("landing.notReported")}</span>
}

function Field({ label, children }: { label: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="border-hairline flex items-baseline justify-between gap-4 border-b py-1.5 last:border-0">
      <span className="hs-label shrink-0">{label}</span>
      <span className="text-ink min-w-0 text-end text-sm break-words">{children}</span>
    </div>
  )
}

export function DetectionDrawer({
  detection,
  onClose,
}: {
  detection: Detection | null
  onClose: () => void
}) {
  const t = useT()
  const f = useFormatters()
  const { isRTL } = useLocale()

  // Rendering is driven by the last non-null detection so the sheet can animate
  // out with its content intact rather than emptying mid-slide.
  const [shown, setShown] = React.useState<Detection | null>(detection)
  React.useEffect(() => {
    if (detection) setShown(detection)
  }, [detection])

  const d = detection ?? shown
  const open = detection !== null

  return (
    <Sheet open={open} onOpenChange={(next) => !next && onClose()}>
      <SheetContent
        // `right` is read as inline-end by `components/ui/sheet.tsx`, so the
        // panel arrives from the reading edge in both directions.
        side={isRTL ? "left" : "right"}
        className="w-full gap-0 overflow-y-auto sm:max-w-md"
      >
        {d && (
          <>
            <SheetHeader className="gap-1.5">
              <SheetTitle className="flex items-center gap-2 text-base">
                <span
                  aria-hidden="true"
                  className="size-2.5 shrink-0 rounded-full"
                  style={{ background: attackColorVar(d.type) }}
                />
                {/* The class identifier is what the model emits: Latin in both
                    locales, and isolated so it cannot be reordered. */}
                <span className="hs-ltr">{attackLabels[d.type]}</span>
                <StatusPill tone={d.severity}>{t(`severity.${d.severity}`)}</StatusPill>
              </SheetTitle>
              <SheetDescription>{t("threats.detail.description")}</SheetDescription>
            </SheetHeader>

            <div className="flex flex-col gap-5 p-4">
              <section className="flex flex-col gap-2">
                <Hairline label={t("threats.detail.overview")} />
                <div className="flex flex-col">
                  <Field label={t("threats.detail.eventId")}>
                    <span className="hs-num">{d.id || <Unreported />}</span>
                  </Field>
                  <Field label={t("threats.detail.timestamp")}>
                    {d.ms === null ? <Unreported /> : <Timestamp value={d.ms} />}
                  </Field>
                  <Field label={t("threats.detail.class")}>
                    {/* The raw label, not our narrowed key: the drawer is where
                        an operator checks what the model actually said. */}
                    {d.rawLabel ? <span className="hs-ltr font-mono">{d.rawLabel}</span> : <Unreported />}
                  </Field>
                  <Field label={t("threats.detail.confidence")}>
                    {d.confidence === null ? <Unreported /> : <span className="hs-num">{f.percent(d.confidence, 1)}</span>}
                  </Field>
                  <Field label={t("threats.detail.anomaly")}>
                    {d.anomaly === null ? <Unreported /> : <span className="hs-num">{f.percent(d.anomaly, 1)}</span>}
                  </Field>
                  <Field label={t("threats.detail.origin")}>
                    {d.sim ? (
                      <StatusPill tone="neutral">{t("common.simulated")}</StatusPill>
                    ) : (
                      <span className="text-ink-dim text-sm">{t("threats.detail.live")}</span>
                    )}
                  </Field>
                </div>
              </section>

              <section className="flex flex-col gap-2">
                <Hairline label={t("threats.detail.network")} />
                <div className="flex flex-col">
                  <Field label={t("threats.column.sourceMac")}>
                    {d.srcMac ? <Mac value={d.srcMac} className="text-sm" /> : <Unreported />}
                  </Field>
                  <Field label={t("threats.column.destMac")}>
                    {d.dstMac ? <Mac value={d.dstMac} className="text-sm" /> : <Unreported />}
                  </Field>
                  <Field label={t("threats.detail.bssid")}>
                    {d.bssid ? <Mac value={d.bssid} className="text-sm" /> : <Unreported />}
                  </Field>
                  <Field label={t("threats.detail.ssid")}>
                    {d.ssid ? <span className="hs-ltr font-mono text-sm">{d.ssid}</span> : <Unreported />}
                  </Field>
                  <Field label={t("threats.detail.interface")}>
                    {d.iface ? <span className="hs-ltr font-mono text-sm">{d.iface}</span> : <Unreported />}
                  </Field>
                  <Field label={t("threats.detail.frameType")}>
                    {d.wlanType === null && d.wlanSubtype === null ? (
                      <Unreported />
                    ) : (
                      <span className="hs-num">
                        {f.number(d.wlanType)} / {f.number(d.wlanSubtype)}
                      </span>
                    )}
                  </Field>
                  <Field label={t("threats.detail.frameLength")}>
                    {d.frameLen === null ? (
                      <Unreported />
                    ) : (
                      <Quantity value={f.number(d.frameLen)} unit={t("units.bytes")} />
                    )}
                  </Field>
                  <Field label={t("threats.detail.retry")}>
                    {d.retry === null ? <Unreported /> : d.retry ? t("common.yes") : t("common.no")}
                  </Field>
                </div>
              </section>

              <section className="flex flex-col gap-2">
                <Hairline label={t("threats.detail.signal")} />
                <div className="flex flex-col">
                  <Field label={t("threats.detail.channel")}>
                    {d.channel === null ? <Unreported /> : <span className="hs-num">{f.number(d.channel)}</span>}
                  </Field>
                  <Field label={t("threats.detail.frequency")}>
                    {d.freq === null ? (
                      <Unreported />
                    ) : (
                      <Quantity value={f.number(d.freq)} unit={t("units.mhz")} />
                    )}
                  </Field>
                  <Field label={t("threats.detail.rssi")}>
                    {d.rssi === null ? (
                      <Unreported />
                    ) : (
                      <Quantity value={f.number(d.rssi)} unit={t("units.dbm")} />
                    )}
                  </Field>
                  <Field label={t("threats.detail.dataRate")}>
                    {d.dataRate === null ? (
                      <Unreported />
                    ) : (
                      <Quantity value={f.number(d.dataRate)} unit={t("units.mbps")} />
                    )}
                  </Field>
                </div>
              </section>

              <p className="text-ink-faint text-xs">{t("time.timezone")}</p>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}
