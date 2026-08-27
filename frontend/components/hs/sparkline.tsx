import * as React from "react"

import { cn } from "@/lib/utils"

/**
 * A tiny inline trend line, drawn as raw SVG.
 *
 * No charting library: this renders beside a number in a table cell, there may
 * be forty of them on screen, and the deploy target is a Pi 4B. It is also a
 * Tufte sparkline in the strict sense — no axes, no grid, no labels, no
 * tooltip. If a reader needs to know a value, the number it sits next to is
 * the value; the line only carries shape.
 */

export interface SparklineProps
  extends Omit<React.ComponentPropsWithoutRef<"svg">, "children" | "values"> {
  values: readonly number[]
  width?: number
  height?: number
  /** Any CSS colour. Defaults to the live accent token so it re-themes. */
  stroke?: string
  /** Fill the area under the line at low opacity. Off for dense tables. */
  area?: boolean
  /** Mark the final point — "where it ended up" is usually the reason to look. */
  showLast?: boolean
  /**
   * Accessible summary. Omit to hide the line from assistive tech, which is
   * correct when the adjacent number already carries the information.
   */
  label?: string
}

/** Guard for a flat series: a zero range would divide by zero and blank the line. */
function scale(values: readonly number[], height: number, padding: number) {
  const min = Math.min(...values)
  const max = Math.max(...values)
  const range = max - min
  const usable = height - padding * 2
  if (range === 0) return () => padding + usable / 2
  return (v: number) => padding + usable - ((v - min) / range) * usable
}

const Sparkline = React.forwardRef<SVGSVGElement, SparklineProps>(function Sparkline(
  {
    values,
    width = 72,
    height = 20,
    stroke = "var(--color-accent)",
    area = false,
    showLast = true,
    label,
    className,
    ...props
  },
  ref
) {
  const geometry = React.useMemo(() => {
    if (values.length < 2) return null

    // Half the stroke weight, so the extremes are not clipped by the viewBox.
    const padding = 1.5
    const y = scale(values, height, padding)
    const step = (width - padding * 2) / (values.length - 1)
    const points = values.map((v, i) => [padding + i * step, y(v)] as const)

    return {
      line: points.map(([px, py]) => `${px.toFixed(2)},${py.toFixed(2)}`).join(" "),
      areaPath:
        `M ${points[0][0].toFixed(2)},${(height - padding).toFixed(2)} ` +
        points.map(([px, py]) => `L ${px.toFixed(2)},${py.toFixed(2)}`).join(" ") +
        ` L ${points[points.length - 1][0].toFixed(2)},${(height - padding).toFixed(2)} Z`,
      last: points[points.length - 1],
    }
  }, [values, width, height])

  return (
    <svg
      ref={ref}
      data-slot="sparkline"
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role={label ? "img" : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
      className={cn("block overflow-visible", className)}
      {...props}
    >
      {geometry ? (
        <>
          {area && <path d={geometry.areaPath} fill={stroke} fillOpacity={0.12} stroke="none" />}
          <polyline
            points={geometry.line}
            fill="none"
            stroke={stroke}
            strokeWidth={1.5}
            strokeLinecap="round"
            strokeLinejoin="round"
            vectorEffect="non-scaling-stroke"
          />
          {showLast && <circle cx={geometry.last[0]} cy={geometry.last[1]} r={1.75} fill={stroke} />}
        </>
      ) : (
        /* Fewer than two samples is not an error, it is "not enough history
           yet". A flat hairline says that without claiming a trend. */
        <line
          x1={0}
          y1={height / 2}
          x2={width}
          y2={height / 2}
          stroke="var(--color-rule-soft)"
          strokeWidth={1}
          vectorEffect="non-scaling-stroke"
        />
      )}
    </svg>
  )
})

export { Sparkline }
