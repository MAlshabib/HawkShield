import type React from "react"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import { Toaster } from "@/components/ui/toaster"
import "./globals.css"
import 'leaflet/dist/leaflet.css'

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-sans",
})

export const metadata: Metadata = {
  title: "HawkShield - WiFi Intrusion Prevention System",
  description: "AI-powered WiFi security monitoring and intrusion prevention",
  generator: "v0.app",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className={`dark ${inter.variable}`}>
      <body className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 font-sans antialiased">
        {children}
        <Toaster />
      </body>
    </html>
  )
}
