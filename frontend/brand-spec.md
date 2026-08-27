# HawkShield — Brand Spec

The single source of truth for identity in the V2 front-end. Everything here is
derived from the real mark and the project poster. **Nothing in this file is
invented** — hexes were sampled from `public/logo-neon.png`, not chosen.

Design direction: **Falcon Ops** — tactical instrument (Bloomberg Terminal /
Tufte school). Structure comes from hairlines and tabular data, not from cards,
gradients or glass.

---

## Assets

| File | What it is |
|---|---|
| `public/logo-neon.png` | **The mark.** 779×779, transparent, two-tone, as the team drew it. Do not redraw, do not trace by hand, do not substitute a CSS silhouette. |
| `public/hawkshield-mark.png` | Same mark, tight-cropped to its bbox and squared at 1024px, transparent. Use this in-app — the original has ~17% dead margin that makes optical sizing unreliable. |
| `app/favicon.ico` | 16/24/32/48/64/128/256, mark on the light field. |
| `app/icon.png`, `app/apple-icon.png` | 512 / 180, same treatment. |
| `docs/assets/Project_Poster.jpg` | Source for the wordmark's proportions and the product's voice. |

The mark reads as **a Wi-Fi signal whose bottom dot is a hawk's head**: two azure
arcs above, a deep-navy hawk head in profile facing right below, white crescent
eye, hooked beak, a solid navy dot at the base.

**Icons are composited on the light field (`#F5F7FA`), not on transparency.** The
navy head on a transparent ground vanishes in a dark browser tab.

### Rules
- The mark ships **flat**. No neon `drop-shadow` stack — V1 wrapped it in three
  cyan glows that overwrote the actual brand colours with a colour the logo does
  not contain.
- No hand-drawn hawk. If a vector is ever needed it comes from tracing the real
  raster.
- Never a "brand name in a coloured box" stand-in.

---

## Colour

Sampled from the raster:

| Token | Value | Where it comes from |
|---|---|---|
| `--hs-navy` | `#0E2A55` | the hawk head |
| `--hs-azure` | `#2E8FDD` | the Wi-Fi arcs |

Substrate and semantics:

| Token | Dark | Light |
|---|---|---|
| `--bg` | `#070B12` | `#F5F7FA` |
| `--surface` | `#0D1420` | `#FFFFFF` |
| `--hairline` | `#1A2434` | `#DDE3EB` |
| `--ink` | `#E8EEF6` | `#101A2B` |
| `--ink-dim` | `#7E8FA6` | `#5A6B82` |
| `--sev-critical` | `#E5484D` | `#C62A2F` |
| `--sev-high` | `#F0A020` | `#B87400` |
| `--sev-info` | `--hs-azure` | `#1E6FBF` |

Colour is **semantic only** — it encodes severity or class identity, never
decoration. At most four hues on screen at once. The V1 palette's fuchsia
`#E879F9` and indigo `#818CF8` are off-brand and are gone.

---

## Type

Self-hosted via `@fontsource/*`; the build and the runtime both work offline.
V1 pulled Inter from Google at build time, which is why building required
internet.

| Role | Family | Notes |
|---|---|---|
| Display (Latin) | **Space Grotesk** | Squared terminals — the closest available match to the poster's wide-tracked techno wordmark. |
| Body (Latin) | **IBM Plex Sans** | |
| Body + display (Arabic) | **IBM Plex Sans Arabic** | Same superfamily as the Latin body, so metrics match and an Arabic page is not a degraded English one. |
| Data / mono | **IBM Plex Mono** | `font-variant-numeric: tabular-nums` globally. |

Inter, Roboto, Arial and `system-ui` are not display faces here.
Fluid scale via `clamp()`; h1:body ratio ≥ 4×.

---

## Voice

From the poster: institutional, factual, quietly confident. "Every packet
matters." Framed around securing Saudi Arabia's digital future.

**HawkShield is an IDS, not an IPS.** `README.md:16-19` says so explicitly. V1's
UI claimed "Intrusion Prevention System" and "detecting and blocking" — copy that
the project itself disowns. V2 says *detects*, *classifies*, *reports*. Never
*blocks* or *prevents*.

The agent is **Saqr / صقر**.

---

## Anti-patterns (all of these are V1 regressions to avoid)

- Purple→pink→blue gradients, or gradient text as decoration
- Glassmorphism (`backdrop-filter` + translucent cards)
- Rounded cards with a coloured left border
- Emoji standing in for icons
- Neon glow on the logo
- Fabricated data — V1's home page invented random attack toasts every 15–30s
