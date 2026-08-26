"use client";

import { useEffect, useState } from "react";
import { Dialog, DialogContent, DialogTrigger, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FileText, Mail, Download } from "lucide-react";
import { attackColors, attackLabels, type AttackType } from "@/lib/colors";
import { useToast } from "@/hooks/use-toast";
import { apiFetch, apiFetchJson } from "@/lib/api";

type ReportSummary = {
  period: string;
  totals: Record<string, number>;
  summary: {
    totalAttacks: number;
    mostFrequentType: string;
    peakHour: number;
    uniqueSources: number;
  };
};

export function ReportModal() {
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [data, setData] = useState<ReportSummary | null>(null);
  const [days, setDays] = useState(7);
  const { toast } = useToast();

  // Load the summary whenever the modal is opened.
  useEffect(() => {
    if (!isOpen) return;
    (async () => {
      setIsLoading(true);
      try {
        const json = await apiFetchJson<ReportSummary>(`/reports/summary?days=${days}`, { cache: "no-store" });
        setData(json);
      } catch (e: any) {
        toast({
          title: "Failed to load report summary",
          description: String(e?.message ?? e),
          className: "border border-red-500/40 bg-[#040A14]/90",
        });
      } finally {
        setIsLoading(false);
      }
    })();
  }, [isOpen, days]);

  const handleDownloadPDF = async () => {
    setIsGenerating(true);
    try {
      const res = await apiFetch("/reports/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ days }),
      });
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `hawkshield-report-${Date.now()}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      toast({
        title: "Report Downloaded",
        description: "The PDF report has been saved to your device.",
        className: "border border-green-500/40 bg-[#040A14]/90",
      });
    } catch (e: any) {
      toast({
        title: "Export failed",
        description: String(e?.message ?? e),
        className: "border border-red-500/40 bg-[#040A14]/90",
      });
    } finally {
      setIsGenerating(false);
    }
  };

  const handleSendEmail = () => {
    // Client-side mailto only; there is no server-side email endpoint (see CONTRACT.md - /reports/email was removed).
    const subject = encodeURIComponent("HawkShield – Attack Report");
    const body = encodeURIComponent(`Period: ${data?.period ?? "-"}\nTotal attacks: ${data?.summary.totalAttacks ?? 0}`);
    window.location.href = `mailto:?subject=${subject}&body=${body}`;
  };

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button variant="default" className="bg-cyan-500 hover:bg-cyan-600">
          <FileText className="w-4 h-4 mr-2" />
          Generate Report
        </Button>
      </DialogTrigger>

      <DialogContent className="bg-[#060E1A]/95 border border-cyan-900/40 max-w-2xl">
        <DialogTitle className="sr-only">Attack Report</DialogTitle>

        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <img src="/logo-neon.png" alt="HawkShield" className="h-8 w-auto object-contain" />
            <h3 className="text-xl font-semibold text-cyan-100">Attack Report</h3>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-sm text-cyan-200/70">Days:</span>
            <input
              type="number"
              min={1}
              className="w-20 rounded-md bg-transparent border border-cyan-900/40 px-2 py-1 text-cyan-100"
              value={days}
              onChange={(e) => setDays(Math.max(1, Number(e.target.value) || 7))}
            />
          </div>
        </div>

        {isLoading ? (
          <div className="text-cyan-200/70">Loading summary…</div>
        ) : !data ? (
          <div className="text-red-400">No data.</div>
        ) : (
          <>
            <div className="text-cyan-200/80 mb-4">{data.period}</div>

            {/* Totals */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
              {Object.entries(data.totals).map(([type, count]) => (
                <div key={type} className="text-center">
                  <Badge
                    variant="outline"
                    className="w-full justify-center py-2"
                    style={{
                      borderColor: attackColors[type as AttackType] ?? "#22d3ee",
                      color: attackColors[type as AttackType] ?? "#22d3ee",
                    }}
                  >
                    {attackLabels[type as AttackType] ?? type}
                  </Badge>
                  <div className="text-2xl font-bold text-cyan-100 mt-1">{count.toLocaleString()}</div>
                </div>
              ))}
            </div>

            {/* Summary */}
            <div className="bg-[#0A1628]/50 rounded-lg p-4 space-y-2 text-cyan-100/80 mb-6">
              <h4 className="font-semibold text-cyan-200 mb-2">Executive Summary</h4>
              <p>• <strong>{data.summary.totalAttacks.toLocaleString()}</strong> total attack attempts</p>
              <p>• Most common: <strong>{attackLabels[data.summary.mostFrequentType as AttackType] ?? data.summary.mostFrequentType}</strong></p>
              <p>• Peak activity at <strong>{data.summary.peakHour}:00</strong></p>
              <p>• <strong>{data.summary.uniqueSources}</strong> unique source MACs</p>
            </div>
          </>
        )}

        <div className="flex justify-end gap-3">
          <Button
            variant="secondary"
            onClick={handleSendEmail}
            className="bg-[#0A1628] border-cyan-700/50 text-cyan-200 hover:bg-cyan-900/20"
          >
            <Mail className="w-4 h-4 mr-2" />
            Send via Email (mailto)
          </Button>

          <Button onClick={handleDownloadPDF} disabled={isGenerating} className="bg-cyan-500 hover:bg-cyan-600">
            <Download className="w-4 h-4 mr-2" />
            {isGenerating ? "Generating..." : "Download PDF"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
