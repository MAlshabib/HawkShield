"use client"

import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { AlertTriangle, Clock, Wifi, Signal, Package, Shield } from "lucide-react"
import { attackColors, attackLabels } from "@/lib/colors"
import type { AttackEvent } from "@/app/(app)/attacks/page"

interface AttackDetailDrawerProps {
  attack: AttackEvent | null
  onClose: () => void
}

export function AttackDetailDrawer({ attack, onClose }: AttackDetailDrawerProps) {
  if (!attack) return null

  const getSeverityColor = (severity: AttackEvent["severity"]) => {
    switch (severity) {
      case "High":
        return "bg-red-500/20 text-red-400 border-red-500/30"
      case "Medium":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
      case "Low":
        return "bg-green-500/20 text-green-400 border-green-500/30"
    }
  }

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60
    return `${minutes}m ${remainingSeconds}s`
  }

  return (
    <Sheet open={!!attack} onOpenChange={onClose}>
      <SheetContent className="glassmorphism border-cyan-500/20 w-full sm:max-w-lg overflow-y-auto">
        <SheetHeader className="space-y-4">
          <SheetTitle className="flex items-center space-x-3">
            <AlertTriangle className="w-6 h-6" style={{ color: attackColors[attack.type] }} />
            <div>
              <div className="text-xl" style={{ color: attackColors[attack.type] }}>
                {attackLabels[attack.type]} Attack
              </div>
              <div className="text-sm text-gray-400 font-normal">Event ID: {attack.id}</div>
            </div>
          </SheetTitle>
        </SheetHeader>

        <div className="space-y-6 mt-6">
          {/* Basic Info */}
          <Card className="glassmorphism border-cyan-500/20">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Shield className="w-5 h-5 mr-2 text-cyan-400" />
                Attack Details
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-gray-400">Timestamp</div>
                  <div className="text-white font-mono">
                    <time dateTime={new Date(attack.timestamp).toISOString()} suppressHydrationWarning>
                      {new Date(attack.timestamp).toLocaleString()}
                    </time>
                  </div>
                </div>
                <div>
                  <div className="text-sm text-gray-400">Severity</div>
                  <Badge className={getSeverityColor(attack.severity)}>{attack.severity}</Badge>
                </div>
                <div>
                  <div className="text-sm text-gray-400">Channel</div>
                  <div className="text-white">{attack.channel}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-400">RSSI</div>
                  <div className="text-white font-mono">{attack.rssi} dBm</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Network Info */}
          <Card className="glassmorphism border-cyan-500/20">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Wifi className="w-5 h-5 mr-2 text-cyan-400" />
                Network Information
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <div className="text-sm text-gray-400">Source MAC Address</div>
                <div className="text-white font-mono text-sm">{attack.sourceMac}</div>
                {attack.details?.vendor && (
                  <div className="text-xs text-gray-400 mt-1">Vendor: {attack.details.vendor}</div>
                )}
              </div>
              <div>
                <div className="text-sm text-gray-400">Destination MAC Address</div>
                <div className="text-white font-mono text-sm">{attack.destMac}</div>
              </div>
              <div>
                <div className="text-sm text-gray-400">Protocol</div>
                <div className="text-white">{attack.details?.protocol ?? "802.11"}</div>
              </div>
            </CardContent>
          </Card>

          {/* Attack Metrics */}
          <Card className="glassmorphism border-cyan-500/20">
            <CardHeader>
              <CardTitle className="text-white flex items-center">
                <Signal className="w-5 h-5 mr-2 text-cyan-400" />
                Attack Metrics
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-sm text-gray-400 flex items-center">
                    <Clock className="w-4 h-4 mr-1" />
                    Duration
                  </div>
                  <div className="text-white font-mono">{attack.details?.duration != null ? formatDuration(attack.details.duration) : "—"}</div>
                </div>
                <div>
                  <div className="text-sm text-gray-400 flex items-center">
                    <Package className="w-4 h-4 mr-1" />
                    Packets
                  </div>
                  <div className="text-white">{attack.details?.packets != null ? attack.details.packets.toLocaleString() : "—"}</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </SheetContent>
    </Sheet>
  )
}
