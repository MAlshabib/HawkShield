"use client"

import { useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { Menu } from "lucide-react"
import { cn } from "@/lib/utils"
import Logo from "@/components/Logo"

const navigation = [
  { name: "Home", href: "/home" },
  { name: "Dashboard", href: "/dashboard" },
  { name: "Attacks", href: "/attacks" },
  { name: "RAG System", href: "/rag" },
]

export function Navbar() {
  const pathname = usePathname()
  const [isOpen, setIsOpen] = useState(false)

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 glassmorphism border-b border-cyan-500/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <Link href="/home" className="flex items-center space-x-2 group">
            <div className="flex items-center gap-2">
              <Logo size={28} aria-hidden />
              <span className="text-xl font-bold text-white group-hover:text-cyan-300 transition-colors tracking-wide">
                HawkShield
              </span>
            </div>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            {navigation.map((item) => (
              <Link
                key={item.name}
                href={item.href}
                className={cn(
                  "px-3 py-2 rounded-md text-sm font-medium transition-all duration-200",
                  pathname === item.href
                    ? "text-cyan-400 cyber-glow bg-cyan-400/10"
                    : "text-gray-300 hover:text-cyan-400 hover:bg-cyan-400/5",
                )}
              >
                {item.name}
              </Link>
            ))}
          </div>

          {/* Mobile Navigation */}
          <div className="md:hidden">
            <Sheet open={isOpen} onOpenChange={setIsOpen}>
              <SheetTrigger asChild>
                <Button variant="ghost" size="icon" className="text-gray-300 hover:text-cyan-400">
                  <Menu className="h-6 w-6" />
                </Button>
              </SheetTrigger>
              <SheetContent side="right" className="glassmorphism border-cyan-500/20">
                <div className="flex flex-col space-y-4 mt-8">
                  {navigation.map((item) => (
                    <Link
                      key={item.name}
                      href={item.href}
                      onClick={() => setIsOpen(false)}
                      className={cn(
                        "px-3 py-2 rounded-md text-sm font-medium transition-all duration-200",
                        pathname === item.href
                          ? "text-cyan-400 cyber-glow bg-cyan-400/10"
                          : "text-gray-300 hover:text-cyan-400 hover:bg-cyan-400/5",
                      )}
                    >
                      {item.name}
                    </Link>
                  ))}
                </div>
              </SheetContent>
            </Sheet>
          </div>
        </div>
      </div>
    </nav>
  )
}

// Add named export alias for compatibility from "./navbar"
export { Navbar as HawkShieldNavbar }
