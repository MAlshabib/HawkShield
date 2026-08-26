"use client"

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ChevronLeft, ChevronRight, AlertTriangle } from "lucide-react"
import { attackColors, attackLabels } from "@/lib/colors"
import type { AttackEvent } from "@/app/(app)/attacks/page"
import { useMemo } from "react";

interface AttacksTableProps {
  attacks: AttackEvent[]
  onAttackClick: (attack: AttackEvent) => void
  currentPage: number
  totalPages: number
  onPageChange: (page: number) => void
}

export function AttacksTable({ attacks, onAttackClick, currentPage, totalPages, onPageChange }: AttacksTableProps) {
  const riyadhFormatter = useMemo(() => new Intl.DateTimeFormat('en-GB', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZone: 'Asia/Riyadh',
  }), []);

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

  const formatTimestamp = (date: Date | string | number) => {
    const d = date instanceof Date ? date : new Date(date);
    return riyadhFormatter.format(d);
  };

  const formatRSSI = (rssi: number) => {
    return `${rssi} dBm`
  }

  return (
    <div className="glassmorphism border-cyan-500/20 rounded-lg overflow-hidden">
      {/* Table */}
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="border-gray-700 hover:bg-transparent">
              <TableHead className="text-gray-300">Time</TableHead>
              <TableHead className="text-gray-300">Type</TableHead>
              <TableHead className="text-gray-300">Source MAC</TableHead>
              <TableHead className="text-gray-300">Dest MAC</TableHead>
              <TableHead className="text-gray-300">Severity</TableHead>
              <TableHead className="text-gray-300">Channel</TableHead>
              <TableHead className="text-gray-300">RSSI</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {attacks.map((attack) => (
              <TableRow
                key={attack.id}
                className="border-gray-700 hover:bg-slate-800/30 cursor-pointer transition-colors"
                style={{
                  borderLeft: `3px solid ${attackColors[attack.type]}`,
                }}
                onClick={() => onAttackClick(attack)}
              >
                <TableCell className="text-gray-300 font-mono text-sm">
                  <time dateTime={new Date(attack.timestamp as any).toISOString()} suppressHydrationWarning>
                    {formatTimestamp(attack.timestamp)}
                  </time>
                </TableCell>
                <TableCell>
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="w-4 h-4" style={{ color: attackColors[attack.type] }} />
                    <span className="font-medium" style={{ color: attackColors[attack.type] }}>
                      {attackLabels[attack.type]}
                    </span>
                  </div>
                </TableCell>
                <TableCell className="font-mono text-sm text-gray-300">{attack.sourceMac}</TableCell>
                <TableCell className="font-mono text-sm text-gray-300">{attack.destMac}</TableCell>
                <TableCell>
                  <Badge className={`text-xs ${getSeverityColor(attack.severity)}`}>{attack.severity}</Badge>
                </TableCell>
                <TableCell className="text-gray-300">{attack.channel}</TableCell>
                <TableCell className="text-gray-300 font-mono text-sm">{formatRSSI(attack.rssi)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-6 py-4 border-t border-gray-700">
          <div className="text-sm text-gray-400">
            Page {currentPage} of {totalPages}
          </div>
          <div className="flex items-center space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => onPageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="glassmorphism border-cyan-500/30 hover:bg-cyan-500/10 disabled:opacity-50"
            >
              <ChevronLeft className="w-4 h-4" />
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => onPageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="glassmorphism border-cyan-500/30 hover:bg-cyan-500/10 disabled:opacity-50"
            >
              <ChevronRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
