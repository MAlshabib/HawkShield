#!/usr/bin/env node
/**
 * Refuses a production build that would inline a development API host.
 *
 * `NEXT_PUBLIC_*` values are substituted into the bundle at build time, so a
 * stray `.env.local` — or an exported shell variable — silently bakes
 * `http://localhost:8010` into every page. The build succeeds, the export looks
 * correct, and the app is dead the moment it is served from anywhere else: on
 * the Raspberry Pi every request goes to a host that does not exist there.
 *
 * In production the frontend and the API are the same origin, so the correct
 * value is empty. This check exists because that failure is invisible until
 * someone opens the deployed page, which is usually in front of an audience.
 *
 * Set `HAWKSHIELD_ALLOW_API_BASE=1` to build with a host on purpose.
 */
import { existsSync, readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const HERE = dirname(fileURLToPath(import.meta.url))
const KEY = "NEXT_PUBLIC_API_BASE"

/** Env files Next.js loads for a production build, in precedence order. */
const ENV_FILES = [".env.production.local", ".env.local", ".env.production", ".env"]

function fromEnvFiles() {
  const hits = []
  for (const name of ENV_FILES) {
    const path = resolve(HERE, "..", name)
    if (!existsSync(path)) continue
    for (const raw of readFileSync(path, "utf8").split(/\r?\n/)) {
      const line = raw.trim()
      if (!line || line.startsWith("#")) continue
      const eq = line.indexOf("=")
      if (eq === -1) continue
      if (line.slice(0, eq).trim() !== KEY) continue
      const value = line
        .slice(eq + 1)
        .trim()
        .replace(/^["']|["']$/g, "")
      if (value) hits.push({ name, value })
    }
  }
  return hits
}

if (process.env.HAWKSHIELD_ALLOW_API_BASE === "1") {
  console.log(`build-env: ${KEY} allowed explicitly`)
  process.exit(0)
}

const problems = fromEnvFiles()
const inherited = (process.env[KEY] ?? "").trim()
if (inherited) problems.push({ name: "the environment", value: inherited })

if (problems.length === 0) {
  console.log(`build-env: ${KEY} is empty — the bundle will call its own origin`)
  process.exit(0)
}

console.error(
  [
    "",
    `  Refusing to build: ${KEY} is set, and it would be inlined into the bundle.`,
    "",
    ...problems.map((p) => `      ${p.name}: ${p.value}`),
    "",
    "  In production the API and the frontend are the same origin, so this must",
    "  be empty. A build with a host in it looks fine here and is dead on the Pi.",
    "",
    "  Remove it (frontend/.env.local is the usual culprit), or, if you really",
    "  mean it, build with HAWKSHIELD_ALLOW_API_BASE=1.",
    "",
  ].join("\n")
)
process.exit(1)
