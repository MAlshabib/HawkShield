"use client"

import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Checkbox } from "@/components/ui/checkbox"
import { Search, Filter, X } from "lucide-react"
import { attackColors, attackLabels, type AttackType } from "@/lib/colors"
import type { AttacksFilters as FiltersType, AttackEvent } from "@/app/(app)/attacks/page"

interface AttacksFiltersProps {
  filters: FiltersType
  onFiltersChange: (filters: FiltersType) => void
}

export function AttacksFiltersComponent({ filters, onFiltersChange }: AttacksFiltersProps) {
  const attackTypes = Object.keys(attackColors) as AttackType[]
  const severities: AttackEvent["severity"][] = ["Low", "Medium", "High"]

  const updateFilters = (updates: Partial<FiltersType>) => {
    onFiltersChange({ ...filters, ...updates })
  }

  const toggleType = (type: AttackType) => {
    const newTypes = filters.types.includes(type) ? filters.types.filter((t) => t !== type) : [...filters.types, type]
    updateFilters({ types: newTypes })
  }

  const toggleSeverity = (severity: AttackEvent["severity"]) => {
    const newSeverities = filters.severities.includes(severity)
      ? filters.severities.filter((s) => s !== severity)
      : [...filters.severities, severity]
    updateFilters({ severities: newSeverities })
  }

  const clearAllFilters = () => {
    onFiltersChange({
      search: "",
      timeRange: "24h",
      types: [],
      severities: [],
    })
  }

  const hasActiveFilters = filters.search || filters.types.length > 0 || filters.severities.length > 0

  return (
    <div className="glassmorphism border-cyan-500/20 rounded-lg p-4 space-y-4">
      <div className="flex flex-col lg:flex-row gap-4">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
          <Input
            placeholder="Search by MAC address, attack type, or ID..."
            value={filters.search}
            onChange={(e) => updateFilters({ search: e.target.value })}
            className="pl-10 glassmorphism border-cyan-500/30"
          />
        </div>

        {/* Time Range */}
        <Select
          value={filters.timeRange}
          onValueChange={(value: FiltersType["timeRange"]) => updateFilters({ timeRange: value })}
        >
          <SelectTrigger className="w-32 glassmorphism border-cyan-500/30">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="glassmorphism border-cyan-500/30">
            <SelectItem value="1h">Last Hour</SelectItem>
            <SelectItem value="6h">Last 6 Hours</SelectItem>
            <SelectItem value="24h">Last 24 Hours</SelectItem>
            <SelectItem value="7d">Last 7 Days</SelectItem>
            <SelectItem value="30d">Last 30 Days</SelectItem>
          </SelectContent>
        </Select>

        {/* Attack Types Filter */}
        <Popover>
          <PopoverTrigger asChild>
            <Button variant="outline" className="glassmorphism border-cyan-500/30 hover:bg-cyan-500/10 bg-transparent">
              <Filter className="w-4 h-4 mr-2" />
              Attack Types
              {filters.types.length > 0 && (
                <Badge className="ml-2 bg-cyan-500/20 text-cyan-400 border-cyan-500/30">{filters.types.length}</Badge>
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-80 glassmorphism border-cyan-500/30">
            <div className="space-y-3">
              <h4 className="font-medium text-white">Attack Types</h4>
              <div className="grid grid-cols-2 gap-2">
                {attackTypes.map((type) => (
                  <div key={type} className="flex items-center space-x-2">
                    <Checkbox
                      id={type}
                      checked={filters.types.includes(type)}
                      onCheckedChange={() => toggleType(type)}
                    />
                    <label
                      htmlFor={type}
                      className="text-sm cursor-pointer"
                      style={{ color: attackColors[type] }}
                    >
                      {attackLabels[type]}
                    </label>
                  </div>
                ))}
              </div>
            </div>
          </PopoverContent>
        </Popover>

        {/* Severity Filter */}
        <Popover>
          <PopoverTrigger asChild>
            <Button variant="outline" className="glassmorphism border-cyan-500/30 hover:bg-cyan-500/10 bg-transparent">
              Severity
              {filters.severities.length > 0 && (
                <Badge className="ml-2 bg-cyan-500/20 text-cyan-400 border-cyan-500/30">
                  {filters.severities.length}
                </Badge>
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-48 glassmorphism border-cyan-500/30">
            <div className="space-y-3">
              <h4 className="font-medium text-white">Severity Levels</h4>
              <div className="space-y-2">
                {severities.map((severity) => (
                  <div key={severity} className="flex items-center space-x-2">
                    <Checkbox
                      id={severity}
                      checked={filters.severities.includes(severity)}
                      onCheckedChange={() => toggleSeverity(severity)}
                    />
                    <label htmlFor={severity} className="text-sm cursor-pointer text-gray-300">
                      {severity}
                    </label>
                  </div>
                ))}
              </div>
            </div>
          </PopoverContent>
        </Popover>

        {/* Clear Filters */}
        {hasActiveFilters && (
          <Button
            variant="ghost"
            onClick={clearAllFilters}
            className="text-gray-400 hover:text-white hover:bg-slate-800/50"
          >
            <X className="w-4 h-4 mr-2" />
            Clear
          </Button>
        )}
      </div>

      {/* Active Filters Display */}
      {hasActiveFilters && (
        <div className="flex flex-wrap gap-2">
          {filters.types.map((type) => (
            <Badge
              key={type}
              className="cursor-pointer hover:opacity-80"
              style={{
                backgroundColor: `${attackColors[type]}20`,
                color: attackColors[type],
                borderColor: `${attackColors[type]}40`,
              }}
              onClick={() => toggleType(type)}
            >
              {attackLabels[type]}
              <X className="w-3 h-3 ml-1" />
            </Badge>
          ))}
          {filters.severities.map((severity) => (
            <Badge
              key={severity}
              variant="outline"
              className="cursor-pointer hover:opacity-80 border-gray-500/30 text-gray-300"
              onClick={() => toggleSeverity(severity)}
            >
              {severity}
              <X className="w-3 h-3 ml-1" />
            </Badge>
          ))}
        </div>
      )}
    </div>
  )
}
