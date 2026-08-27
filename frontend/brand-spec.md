# HawkShield — Brand Spec

The single source of truth for identity in the V3 front-end. Everything here is
derived from the real mark and the project poster. **Nothing in this file is
invented** — the two brand hues were sampled from `public/logo-neon.png`, not
chosen, and every other value is derived from them in oklch.

Design direction: **Falcon Paper** — a paper instrument. Structure comes from
two hairline weights, four paper steps and one accent. It replaces V2's *Falcon
Ops* tactical console outright; nothing of that system survives except the mark
itself and the voice.

The system is implemented in `app/globals.css` and rendered end to end at
**`/design`**. If a primitive is not on that page, it does not exist yet.

---

## Why paper

HawkShield is a Wi-Fi **detection** system shown to competition judges first and
operated second. A dark tactical console performs competence at an audience that
already knows what a console is; it tells a judge nothing except that the team
has seen a hacker film. Paper is the harder and more honest register: it has to
earn attention with hierarchy and specificity instead of borrowing it from
genre.

Audience: judges, then operators. Use case: prove the sensor is detecting real
attacks, and let someone interrogate that. Tone: technical, but inviting.

---

## Assets

| File | What it is |
|---|---|
| `public/logo-neon.png` | **The mark.** 779×779, transparent, two-tone, as the team drew it. Do not redraw, do not trace by hand, do not substitute a CSS silhouette. |
| `public/hawkshield-mark.png` | Same mark, tight-cropped to its bbox and squared at 1024px, transparent. Use this in-app — the original has ~17% dead margin that makes optical sizing unreliable. |
| `app/favicon.ico` | 16/24/32/48/64/128/256, mark on the light field. |
| `app/icon.png`, `app/apple-icon.png` | 512 / 180, same treatment. |
| `docs/assets/Project_Poster.jpg` | Source for the product's voice. |

The mark reads as **a Wi-Fi signal whose bottom dot is a hawk's head**: two azure
arcs above, a deep-navy hawk head in profile facing right below, white crescent
eye, hooked beak, a solid navy dot at the base.

**Icons are composited on the light field, not on transparency.** The navy head
on a transparent ground vanishes in a dark browser tab.

### Rules
- The mark ships **flat**. No glow stack, no filter, no drop-shadow.
- No hand-drawn hawk. If a vector is ever needed it comes from tracing the real
  raster.
- Never a "brand name in a coloured box" stand-in.

### Wordmark

**"HawkShield", sentence case, display face, weight 700, tight tracking.** With
`split`, "Shield" takes the accent azure.

V2 set the wordmark uppercase at 0.2–0.28em tracking, borrowed off the poster.
That is dropped: on paper, wide-tracked all-caps reads as defence-contractor
letterhead, which is the register this system exists to leave behind. Colour,
not spacing, now carries the identity — and Arabic never receives tracking at
all, so a spacing-based logotype could not have survived translation anyway.

The wordmark is pinned `dir="ltr"`: a logotype does not reorder under RTL even
though the page around it does.

---

## Colour

Two hues are sampled from the raster and everything else is derived from them
in oklch:

| Brand | Hex | oklch | Where it comes from |
|---|---|---|---|
| navy | `#0E2A55` | `oklch(29.1% .085 259)` | the hawk head |
| azure | `#2E8FDD` | `oklch(63.2% .147 247.5)` | the Wi-Fi arcs |

### Tokens

Declared in `app/globals.css`. `@theme` carries the palette; `:root` carries
what is derived from it; `.dark` re-authors both.

| Token | Light | Dark | Role |
|---|---|---|---|
| `--color-paper-0` | `oklch(98.6% .004 250)` | `oklch(16.5% .018 258)` | the page |
| `--color-paper-1` | `oklch(96.4% .008 250)` | `oklch(20.5% .020 258)` | card |
| `--color-paper-2` | `oklch(93.4% .012 250)` | `oklch(25% .022 258)` | elevated / hover |
| `--color-paper-3` | `oklch(89.5% .016 250)` | `oklch(31% .024 258)` | fill — never a text substrate |
| `--color-ink-0` | `oklch(19% .030 258)` | `oklch(96% .006 250)` | primary |
| `--color-ink-1` | `oklch(36% .026 258)` | `oklch(84.5% .012 250)` | body |
| `--color-ink-2` | `oklch(50% .022 258)` | `oklch(70.5% .016 252)` | secondary |
| `--color-ink-3` | `oklch(60.5% .017 258)` | `oklch(56.5% .018 254)` | mute — placeholders only |
| `--color-accent` | `oklch(60% .150 250)` | `oklch(73.5% .130 244)` | identity azure, large type / icons |
| `--color-accent-cta` | `oklch(50% .148 252)` | `oklch(80% .090 242)` | text-safe azure, 4.5:1+ |
| `--color-accent-soft` | `oklch(74% .100 250)` | `oklch(55% .110 248)` | soft fills |
| `--color-accent-tint` | `oklch(94.5% .022 250)` | `oklch(28% .045 252)` | the page tint, selected rows |
| `--color-navy` | `oklch(29.1% .085 259)` | *(unchanged)* | brand navy |
| `--color-cta` | → navy | → ink-0 | the primary pill **(role inverts)** |
| `--color-cta-ink` | → paper-0 | → paper-0 | text on the pill |
| `--color-companion` | `oklch(78% .150 70)` | `oklch(80% .140 72)` | amber, fills and dots |
| `--color-companion-ink` | `oklch(55% .113 62)` | `oklch(82% .130 72)` | amber, text-safe |
| `--color-critical` | `oklch(58% .200 25)` | `oklch(70% .170 24)` | the one red |
| `--color-focus` | `oklch(42% .190 262)` | `oklch(88% .062 240)` | focus ring |
| `--color-shadow` | → navy | `oklch(6% .012 258)` | what a shadow is made of |
| `--color-rule` | ink-0 @ 8% | ink-0 @ 11% | hairline |
| `--color-rule-soft` | ink-0 @ 14% | ink-0 @ 19% | card edge |

**The CTA-safe azure is authored at chroma .148, not .170.** `oklch(50% .170 252)`
falls outside sRGB; the browser would clip it to a colour nobody chose.

**`--color-navy` does not move between themes** — a brand colour is a constant.
What inverts is the *role*: `--color-cta` is navy-on-paper in light and
paper-on-ink in dark, because navy on a near-black page is invisible.

**`--color-focus` is deliberately not the accent.** A ring drawn in the same hue
as the control it surrounds vanishes the moment that control is itself
accent-filled. It also carries `outline-offset: 3px`, so it is always measured
against the page paper (8.0:1 light, 12.6:1 dark) and never against a fill.

### Contrast, measured

| Pair | Light | Dark |
|---|---|---|
| ink-0 / paper-0 | 17.8 | 17.2 |
| ink-1 / paper-0 | 10.4 | 12.0 |
| ink-2 / paper-0 | 5.8 | 7.4 |
| ink-3 / paper-0 | 3.7 | 4.2 |
| accent-cta / paper-0 | 5.8 | 10.4 |
| accent / paper-0 (large only) | 3.8 | 8.3 |
| critical / paper-0 | 4.6 | 6.7 |
| companion-ink / paper-0 | 4.8 | 10.8 |
| paper-0 on the CTA fill | 13.4 | 17.2 |

`--color-companion` as *text* on paper is 2.0:1 and fails. That is why
`--color-companion-ink` exists: the fill and the text step of the same hue are
separate tokens, and mixing them up is the standard way an amber badge ends up
unreadable.

### Threat classes

Nine identities in `lib/colors.ts`, mirrored as `--cls-*`. Two severity anchors
(`evil_twin` critical red, `krack` companion amber) plus a six-step
azure-to-slate ramp, so a legend reads as the ordinal scale these classes
genuinely are.

Lightness is banded **0.527–0.615** so a single value clears 3:1 against *both*
papers. This is the one part of the palette that must not be theme-split:
recharts and inline SVG fills consume the values as literal hex and cannot ask
which theme is active.

Colour is **semantic only** — it encodes severity or class identity, never
decoration. At most four hues on screen at once.

---

## Type

Two families. Self-hosted; the build and the runtime both work offline.

| Role | Family | Notes |
|---|---|---|
| Display + body, **both scripts** | **Thmanyah Sans** | 300 / 400 / 500 / 700 / 900. Covers Latin (all 52), digits, punctuation *and* Arabic — verified — which is why one face serves both languages. `@font-face`-declared in `globals.css` with `font-display: swap`. |
| Data / mono | **IBM Plex Mono** | 400 / 500 via `@fontsource`. Figures, MACs, SQL, timestamps, eyebrows. Latin-only. |

V2 shipped four families (Space Grotesk + IBM Plex Sans + IBM Plex Sans Arabic +
IBM Plex Mono). Three of them are gone from `package.json` and `app/layout.tsx`.

The Thmanyah woff2 files are gitignored — the foundry permits free use but asks
that the files not be redistributed by an app — so `scripts/fonts.mjs` puts them
in place. `predev` / `prebuild` run it automatically; a fresh clone runs
`npm run fonts`.

### Scale

`--text-micro` 11px · `xs` 12 · `sm` 14 · `base` 16 · `md` 17 · `lg` 20 ·
`xl` 24 · then fluid: `2xl` `3xl` `4xl` `5xl` `display`. Body sits at 16px, not
V2's 14px operator density: a judge reading this for the first time is not an
operator scanning it for the thousandth.

`--text-display` is capped at 4.75rem so the hero still fits the fold at
1280×800 with its eyebrow, lede and CTA.

### Emphasis — the accent word

The reference this system is cut from sets its emphasis word in an italic serif.
**We do not, and cannot.** Thmanyah has no italic; Arabic script has no italics
at all, so the device could not survive translation; and an italicised word
inside an upright heading is one of the most reliable generated-looking tells
there is.

Emphasis is **weight and colour**: `components/hs/accent-word.tsx` sets the word
in the display face at weight 900 in `--color-accent`, against bold ink
siblings. One primitive, used on every page, so the device cannot drift.

Headings are always roman. `globals.css` declares `font-style: normal` on
`h1`–`h6` explicitly rather than assuming it.

### Arabic

Arabic is a first-class page, not a translation layer over Latin metrics.

- **Never `letter-spacing`.** Arabic is cursive: letters join, and a letter's
  shape depends on its neighbours. Tracking prises those joins apart. The
  `.hs-label` rule in `globals.css` drops tracking and switches family for
  `[lang="ar"]` automatically, so no call site has to remember.
- **Never a Latin-only fallback.** Thmanyah covers both scripts, so body and
  display are solved by the stack itself. The *mono* face has no Arabic at all,
  so any Arabic inside a mono context switches family — that is exactly what the
  `.hs-label` override does.
- **Figures and technical strings are pinned LTR** (`.hs-num`, `.hs-ltr`).
  Inside an RTL paragraph, a string opening with a neutral character takes the
  paragraph direction: `−42 dBm` renders as `dBm 42−` and a MAC reverses. The
  DOM would be right and the screen wrong.
- **Logical properties only** throughout — `margin-inline`, `padding-inline`,
  `inset-inline`, `border-inline-*`, and the `ms-/me-/ps-/pe-/start-/end-`
  utilities. No `left`/`right` anywhere in the design layer.

---

## Structure

Hallmark macrostructure **Marquee Hero**, genre modern-minimal, nav **N5
floating pill**, footer **Ft5 statement**.

| Primitive | File | What it is |
|---|---|---|
| `NavPill` | `components/hs/nav-pill.tsx` | N5. Content-sized, detached, blurred backdrop. Centred with `start-0 end-0 mx-auto`, never `left-1/2`. |
| `Eyebrow` | `components/hs/eyebrow.tsx` | The mono micro-label, bare or as a pill, with an optional live dot. |
| `AccentWord` | `components/hs/accent-word.tsx` | The emphasis device. Display sizes only. |
| `Panel` / `PanelGrid` | `components/hs/panel.tsx` | The repeating card. Replaces V2's `Module`. |
| `DataCard` | `components/hs/data-card.tsx` | The hero object: mono rows, right-aligned figures, status pill, big total, thin severity bar. |
| `Marquee` | `components/hs/marquee.tsx` | One tracked-uppercase strip, hero only, `aria-hidden`, reduced-motion safe. |
| `SectionHead` | `components/hs/section-head.tsx` | Mono eyebrow above the headline, body column offset to the inline-end edge. Single-column at every width — see the note in the file. |
| `StatementFooter` | `components/hs/statement-footer.tsx` | Ft5. One closing sentence, then wordmark, links and the legal line. |
| `StatusPill`, `Metric`, `Sparkline`, `DataTable`, `Hairline`, `TerminalLine`, `Radar` | `components/hs/` | Carried over from V2 and re-cut onto the paper tokens. |

`components/hs/module.tsx` is a deprecated one-hop alias for `Panel`, kept only
so the not-yet-rebuilt pages keep compiling. Delete it when `git grep "hs/module"`
comes back empty.

### Elevation, radius, motion

- **Radii** 6 / 12 / 20 / 28 / pill. Buttons are always pills.
- **Two elevation steps**: a card lift and a floating lift. In dark the card
  step resolves to nothing — a shadow on graphite is a smudge — and the hairline
  does the work instead.
- **Four loops, all load-bearing**: the live dot ("is the sensor listening?"),
  the arrival wash (a new detection tints itself with its class colour and
  decays — the wash *is* the notification, there is no toast), the scan (a line
  down a panel that is filling in, instead of a spinner), and the hero marquee.
  Under `prefers-reduced-motion: reduce` every one stops and resolves to a
  complete still frame. That is the test a motion has to pass to be allowed.
- **Focus rings never animate.** A keyboard user needs the ring the instant
  focus lands.

---

## Voice

From the poster: institutional, factual, quietly confident. "Every packet
matters." Framed around securing Saudi Arabia's digital future.

**HawkShield is an IDS, not an IPS.** `README.md:16-19` says so explicitly. V1's
UI claimed "Intrusion Prevention System" and "detecting and blocking" — copy the
project itself disowns. We say *detects*, *classifies*, *reports*. Never *blocks*
or *prevents*, and never that a network is clean: absence of a detection is
absence of a pill, not a green one. There is deliberately no success tone in
`StatusPill`.

The agent is **Saqr / صقر**.

---

## Anti-patterns

Everything below is banned outright in this system.

- Fabricated data. `/design` shows placeholders and says so on every block that
  carries one; where a figure would imply a measurement nobody has taken it is
  set as an em dash.
- Gradient text, or purple→pink→blue gradients of any kind.
- Glassmorphism **as a card style**. The nav pill's `backdrop-filter` is the one
  sanctioned use — it has to stay legible over scrolling content.
- Rounded cards with a coloured left border.
- Emoji standing in for icons. One icon library (Lucide) and nothing else.
- Italic headings, and italic emphasis words inside headings.
- Re-drawn browser chrome: fake window bars, traffic-light dots, phone frames,
  IDE chrome, terminal frames. `TerminalLine` is a *line*, never a window.
- Neon glow on the logo.
- Physical CSS properties (`left`, `right`, `ml-`, `mr-`, `pl-`, `pr-`).
- `letter-spacing` on Arabic; any Latin-only fallback for Arabic text.
- `transition-all`, uniform hover-scale, or more than one hover effect at once.
- A second shadow tier, or a third rule weight.
