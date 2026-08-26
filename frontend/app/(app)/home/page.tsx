"use client"

import { useEffect } from "react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ArrowRight, CheckCircle } from "lucide-react"
import { attackColors, attackLabels, type AttackType } from "@/lib/colors"
import { useToast } from "@/hooks/use-toast"
import Logo from "@/components/Logo"

export default function HomePage() {
  const { toast } = useToast()

  useEffect(() => {
    const showRandomToast = () => {
      const attackTypes: AttackType[] = ["ssdp", "evil_twin", "krack", "deauth", "reassoc", "rogueap", "other"]
      const channels = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13, 14]

      const randomType = attackTypes[Math.floor(Math.random() * attackTypes.length)]
      const randomChannel = channels[Math.floor(Math.random() * channels.length)]
      const randomRssi = Math.floor(Math.random() * 60) - 90

      toast({
        title: `New ${attackLabels[randomType]} attack`,
        description: `Ch ${randomChannel} • RSSI ${randomRssi} • ${new Date().toLocaleTimeString()}`,
        action: (
          <Link href={`/attacks?type=${randomType}`} className="underline text-cyan-300 hover:text-cyan-200">
            View in Attacks
          </Link>
        ),
        className: "border border-cyan-500/40 bg-[#040A14]/90",
        style: { boxShadow: `0 0 12px ${attackColors[randomType]}50` },
      })
    }

    // Show initial toast after 3 seconds
    const initialTimeout = setTimeout(showRandomToast, 3000)

    // Then show random toasts every 15-30 seconds
    const interval = setInterval(
      () => {
        if (Math.random() > 0.3) {
          // 70% chance to show toast
          showRandomToast()
        }
      },
      Math.random() * 15000 + 15000,
    ) // 15-30 seconds

    return () => {
      clearTimeout(initialTimeout)
      clearInterval(interval)
    }
  }, [toast])

  return (
    <div className="min-h-screen wifi-wave">
      {/* Hero Section */}
      <div className="relative flex items-center justify-center min-h-screen px-4">
        {/* Background Neon Logo */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none -z-10">
          <Logo size={700} className="opacity-20" aria-hidden />
        </div>

        <div className="text-center max-w-4xl mx-auto">
          {/* Status Badge */}
          <div className="flex justify-center mb-8">
            <Badge className="bg-green-500/20 text-green-400 border-green-500/30 px-4 py-2 text-sm drop-in">
              <CheckCircle className="w-4 h-4 mr-2" />
              Protected
            </Badge>
          </div>

          <h1 className="text-4xl sm:text-6xl font-extrabold animated-gradient-text drop-in">
            WiFi Intrusion Prevention System
          </h1>

          <p className="mt-4 text-cyan-100/80 drop-in delay-1 max-w-2xl mx-auto text-lg md:text-xl leading-relaxed">
            HawkShield protects your wireless network in real time by detecting and blocking advanced Wi‑Fi attacks such
            as Deauth, Evil Twin, KRACK, SSDP abuse, and more.
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center mt-12 drop-in delay-2">
            <Button
              asChild
              size="lg"
              className="bg-cyan-500 hover:bg-cyan-600 text-white cyber-glow px-8 py-3"
            >
              <Link href="/dashboard" className="flex items-center">
                Go to Dashboard
                <ArrowRight className="ml-2 h-5 w-5" />
              </Link>
            </Button>
            <Button
              asChild
              variant="outline"
              size="lg"
              className="border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/10 px-8 py-3 bg-transparent"
            >
              <Link href="/attacks">View Attacks</Link>
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
