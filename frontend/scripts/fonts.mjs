#!/usr/bin/env node
/**
 * Copies the Thmanyah Sans web fonts into `public/fonts/thmanyah`.
 *
 * The Thmanyah licence permits free personal and commercial use but asks that
 * the files be obtained from the foundry and not redistributed by an app, so
 * the woff2 files are gitignored and this script puts them in place instead.
 * A fresh clone therefore has no font until someone runs `npm run fonts`.
 *
 * Source, in order of precedence:
 *   1. THMANYAH_FONT_DIR in the environment
 *   2. the paths in FALLBACK_SOURCES below
 *
 * Get the family from https://font.thmanyah.com/ if you have no local copy.
 */
import { existsSync, mkdirSync, readdirSync, copyFileSync, statSync } from "node:fs"
import { join, resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"

const HERE = dirname(fileURLToPath(import.meta.url))
const DEST = resolve(HERE, "..", "public", "fonts", "thmanyah")

/** Weights the stylesheet actually declares. Missing any of these is fatal. */
const REQUIRED = [
  "thmanyahsans-Light.woff2",
  "thmanyahsans-Regular.woff2",
  "thmanyahsans-Medium.woff2",
  "thmanyahsans-Bold.woff2",
  "thmanyahsans-Black.woff2",
]

const FALLBACK_SOURCES = [
  "D:/atqen/branding/fonts/thmanyahsans/woff2",
  resolve(HERE, "..", "..", "..", "branding", "fonts", "thmanyahsans", "woff2"),
]

function findSource() {
  const candidates = [process.env.THMANYAH_FONT_DIR, ...FALLBACK_SOURCES].filter(Boolean)
  for (const dir of candidates) {
    if (!existsSync(dir) || !statSync(dir).isDirectory()) continue
    const present = new Set(readdirSync(dir))
    if (REQUIRED.every((f) => present.has(f))) return dir
  }
  return null
}

function main() {
  const missing = REQUIRED.filter((f) => !existsSync(join(DEST, f)))
  if (missing.length === 0) {
    console.log(`fonts: already in place (${REQUIRED.length} files in public/fonts/thmanyah)`)
    return
  }

  const src = findSource()
  if (!src) {
    // Fail loudly. A silent fall back to a system font is the worst outcome:
    // the build succeeds, nobody notices, and the typography is simply wrong.
    console.error(
      [
        "",
        "  Thmanyah Sans not found, and it is not committed to this repository.",
        "",
        `  Missing: ${missing.join(", ")}`,
        "",
        "  Point the script at your copy:",
        "      THMANYAH_FONT_DIR=/path/to/thmanyahsans/woff2 npm run fonts",
        "",
        "  Or download the family from https://font.thmanyah.com/ first.",
        "",
      ].join("\n")
    )
    process.exit(1)
  }

  mkdirSync(DEST, { recursive: true })
  for (const file of REQUIRED) copyFileSync(join(src, file), join(DEST, file))
  console.log(`fonts: copied ${REQUIRED.length} files from ${src}`)
}

main()
