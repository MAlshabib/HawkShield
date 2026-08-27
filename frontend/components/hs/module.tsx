import * as React from "react"

import { Panel, PanelGrid, type PanelProps } from "@/components/hs/panel"

/**
 * DEPRECATED — use `components/hs/panel` directly.
 *
 * `Module` was the V2 instrument container. Falcon Paper replaces it with
 * `Panel`, but a straight deletion would break every page that has not been
 * rebuilt yet (`app/(app)/**`, `components/threats/*`, `components/MapTrilateration`,
 * `components/simulate-panel`), all of which are owned by other engineers and
 * are mid-rewrite. So this file stays as a one-hop alias: the old name, the old
 * props, the new component underneath.
 *
 * It carries no styling of its own. When the last importer has moved to
 * `Panel`, delete this file — `git grep "hs/module"` returning nothing is the
 * signal.
 */

export type ModuleProps = PanelProps

const Module = React.forwardRef<HTMLElement, ModuleProps>(function Module(props, ref) {
  return <Panel ref={ref} data-slot="module" {...props} />
})

const ModuleGrid = PanelGrid

export { Module, ModuleGrid }
