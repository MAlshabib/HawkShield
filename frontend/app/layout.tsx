import type React from "react"
import type { Metadata } from "next"

/**
 * Self-hosted type. V1 pulled Inter through `next/font/google`, which is why
 * `next build` needed internet — a hard blocker for a Raspberry Pi demo behind
 * a captive network. These are the four families named in `brand-spec.md`.
 *
 * The list below is exactly the one `app/globals.css` names above its
 * `--font-display / --font-body / --font-arabic / --font-mono` tokens. Per-weight
 * files, not the package index: the index pulls every weight and every subset,
 * which is roughly an order of magnitude of font bytes nobody renders. Keep the
 * two lists in step — a stack whose face never loads falls silently through to
 * its generic fallback and simply looks slightly wrong.
 */
import "@fontsource/space-grotesk/400.css"
import "@fontsource/space-grotesk/500.css"
import "@fontsource/space-grotesk/700.css"
import "@fontsource/ibm-plex-sans/400.css"
import "@fontsource/ibm-plex-sans/500.css"
import "@fontsource/ibm-plex-sans/600.css"
import "@fontsource/ibm-plex-sans-arabic/400.css"
import "@fontsource/ibm-plex-sans-arabic/500.css"
import "@fontsource/ibm-plex-sans-arabic/600.css"
import "@fontsource/ibm-plex-mono/400.css"
import "@fontsource/ibm-plex-mono/500.css"

import { Toaster } from "@/components/ui/toaster"
import { LocaleProvider } from "@/components/providers/locale-provider"
import { ThemeProvider } from "@/components/providers/theme-provider"
import "./globals.css"
import "leaflet/dist/leaflet.css"

/**
 * HawkShield is an intrusion **detection** system. It detects, classifies and
 * reports; it does not block or prevent. V1's metadata claimed "Intrusion
 * Prevention System", a claim README.md §Scope explicitly disowns — and
 * metadata is exactly the copy that ends up in a search result or a link
 * preview, where nobody is around to correct it.
 */
export const metadata: Metadata = {
  title: "HawkShield — Wi-Fi Intrusion Detection",
  description:
    "HawkShield detects and classifies Wi-Fi attacks in real time from a Raspberry Pi sensor, and reports what it found. " +
    "يكتشف HawkShield هجمات Wi-Fi ويصنّفها لحظيًا، ثم يبلّغ عمّا رصده.",
  applicationName: "HawkShield",
  keywords: ["HawkShield", "Wi-Fi", "IDS", "intrusion detection", "802.11", "Saqr"],
}

/**
 * Applied before first paint, ahead of React. Without it every load flashes
 * light-and-LTR before the providers mount, which on an Arabic page means the
 * entire layout visibly jumps sides. Deliberately tiny and dependency-free: it
 * blocks rendering, so it has to be cheap, and it must never throw — a locked
 * down browser that denies `localStorage` should still get a working page.
 *
 * The keys and the fallbacks mirror `lib/i18n/types.ts` and `theme-provider`.
 * If those change, change this too.
 */
const PRE_HYDRATION = `(function(){try{
var d=document.documentElement;
var t=localStorage.getItem("hawkshield.theme");
var dark=t==="dark"||((t!=="light")&&matchMedia("(prefers-color-scheme: dark)").matches);
d.classList.toggle("dark",dark);
d.style.colorScheme=dark?"dark":"light";
var l=localStorage.getItem("hawkshield.locale");
if(l!=="ar"&&l!=="en"){l=(navigator.language||"en").toLowerCase().indexOf("ar")===0?"ar":"en";}
d.lang=l;d.dir=l==="ar"?"rtl":"ltr";
}catch(e){}})();`

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    // `lang`/`dir`/`class` here are only the build-time defaults; the script
    // above rewrites all three before paint, so React must be told not to treat
    // the difference as a hydration failure.
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: PRE_HYDRATION }} />
      </head>
      <body className="min-h-screen antialiased">
        <ThemeProvider>
          <LocaleProvider>
            {children}
            <Toaster />
          </LocaleProvider>
        </ThemeProvider>
      </body>
    </html>
  )
}
