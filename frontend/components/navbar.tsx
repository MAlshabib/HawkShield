"use client"

/**
 * The application shell's top bar.
 *
 * Two rules govern everything here. Every visible string comes from `useT()` —
 * there is no English literal left to forget when the page flips to Arabic. And
 * every offset is a logical property (`ms-*`, `gap`, `border-e`, `start-*`), so
 * the bar mirrors itself in RTL without a single `[dir="rtl"]` override.
 *
 * `/admin` is deliberately not listed. It is the operator's simulate lever and
 * is reachable only by typing the URL (see `app/(app)/admin/page.tsx`).
 */
import { useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { Menu } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { CommandBar } from "@/components/hs/command-bar"
import { Logo, Wordmark } from "@/components/brand/logo"
import { useLocale, useT } from "@/lib/i18n"
import type { TranslationKey } from "@/lib/i18n"
import { cn } from "@/lib/utils"

type NavItem = { href: string; key: TranslationKey }

const NAVIGATION: readonly NavItem[] = [
  { href: "/dashboard", key: "nav.dashboard" },
  { href: "/threats", key: "nav.threats" },
  { href: "/map", key: "nav.map" },
  { href: "/saqr", key: "nav.saqr" },
]

/** Trailing-slash routes (`trailingSlash: true`) must still match `/threats`. */
function isActive(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(`${href}/`)
}

const linkBase = cn(
  "rounded-md px-3 py-2 text-sm font-medium transition-colors",
  "text-[color:var(--ink-dim)] hover:text-[color:var(--ink)]",
  "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--hs-azure)]",
)

export function Navbar() {
  const pathname = usePathname()
  const t = useT()
  const { isRTL } = useLocale()
  const [isOpen, setIsOpen] = useState(false)

  const items = NAVIGATION.map((item) => ({ ...item, active: isActive(pathname, item.href) }))

  return (
    <header className="sticky top-0 z-50 border-b border-[color:var(--hairline)] bg-[color:var(--surface)]">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-4 px-4 sm:px-6 lg:px-8">
        <Link
          href="/"
          className={cn(
            "flex items-center gap-2.5",
            "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--hs-azure)]",
          )}
        >
          {/* `decorative` because the wordmark beside it already names the
              product; two accessible names for one link reads as a stutter.
              `Wordmark` is a logotype and pins itself to `dir="ltr"`, so it does
              not reorder under RTL even though the bar around it mirrors. */}
          <Logo size={28} decorative />
          <Wordmark size="sm" className="text-[color:var(--ink)]" />
        </Link>

        <nav aria-label={t("nav.primary")} className="hidden items-center gap-1 md:flex">
          {items.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              aria-current={item.active ? "page" : undefined}
              className={cn(linkBase, item.active && "text-[color:var(--ink)] bg-[color:var(--hairline)]/40")}
            >
              {t(item.key)}
            </Link>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <CommandBar />

          <div className="md:hidden">
            <Sheet open={isOpen} onOpenChange={setIsOpen}>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon" aria-label={t("nav.openMenu")}>
                  <Menu className="h-5 w-5" aria-hidden />
                </Button>
              </SheetTrigger>
              {/* The drawer enters from the inline-end edge in both directions.
                  `Sheet` only understands the physical sides, so the side is
                  computed from the locale rather than overridden in CSS. */}
              <SheetContent
                side={isRTL ? "left" : "right"}
                className="border-[color:var(--hairline)] bg-[color:var(--surface)]"
              >
                <nav aria-label={t("nav.primary")} className="mt-8 flex flex-col gap-1">
                  {items.map((item) => (
                    <Link
                      key={item.href}
                      href={item.href}
                      onClick={() => setIsOpen(false)}
                      aria-current={item.active ? "page" : undefined}
                      className={cn(
                        linkBase,
                        "text-start",
                        item.active && "text-[color:var(--ink)] bg-[color:var(--hairline)]/40",
                      )}
                    >
                      {t(item.key)}
                    </Link>
                  ))}
                </nav>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </div>
    </header>
  )
}

// Kept for the older import path used elsewhere in the tree.
export { Navbar as HawkShieldNavbar }
