"use client";

import React, { useState } from "react";
import {
  Radio,
  Search,
  Filter,
  ShieldAlert,
  Terminal,
  ExternalLink,
  ChevronRight,
  Eye,
  CheckCircle2,
  AlertOctagon,
  Clock,
  Layers,
} from "lucide-react";
import { SecurityIncident, Severity } from "../../lib/types";

interface LiveTelemetryStreamProps {
  incidents: SecurityIncident[];
  onTriggerAttackSample?: () => void;
}

export default function LiveTelemetryStream({ incidents, onTriggerAttackSample }: LiveTelemetryStreamProps) {
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [searchTerm, setSearchTerm] = useState<string>("");

  const filteredIncidents = incidents.filter((inc) => {
    if (filterSeverity !== "ALL" && inc.severity !== filterSeverity) return false;
    if (searchTerm.trim() !== "") {
      const q = searchTerm.toLowerCase();
      return (
        inc.attack_type.toLowerCase().includes(q) ||
        inc.session_id.toLowerCase().includes(q) ||
        inc.ip_address.toLowerCase().includes(q) ||
        inc.cwe.toLowerCase().includes(q) ||
        inc.endpoint.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.25)]";
      case "HIGH":
        return "bg-orange-500/20 text-orange-300 border-orange-500/40";
      case "MEDIUM":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40";
      default:
        return "bg-blue-500/20 text-blue-300 border-blue-500/40";
    }
  };

  const getActionBadge = (action: string) => {
    switch (action) {
      case "QUARANTINE_BLOCK":
        return "bg-red-500/20 text-red-300 border-red-500/30";
      case "ISOLATE_CONTAIN":
        return "bg-amber-500/20 text-amber-300 border-amber-500/30";
      case "RATE_LIMIT":
        return "bg-yellow-500/20 text-yellow-300 border-yellow-500/30";
      default:
        return "bg-blue-500/10 text-blue-300 border-blue-500/20";
    }
  };

  return (
    <div className="space-y-6">
      {/* Control Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-4 glass-panel">
        <div className="flex items-center gap-3">
          <div className="relative flex-1 sm:w-80">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
            <input
              type="text"
              placeholder="Filter by session, IP, endpoint, or CWE..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 rounded-xl bg-white/[0.04] border border-white/[0.08] text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-blue-400/50"
            />
          </div>

          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-zinc-400" />
            {(["ALL", "CRITICAL", "HIGH", "MEDIUM"] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all duration-150 ${
                  filterSeverity === sev
                    ? "bg-blue-600 text-white shadow-sm"
                    : "bg-white/[0.03] text-zinc-400 hover:text-white hover:bg-white/[0.06]"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs text-zinc-400">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Live Ingestion Stream
          </span>
          <span className="text-zinc-600">|</span>
          <span className="font-mono text-zinc-300">{filteredIncidents.length} events</span>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="glass-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-white/[0.02] border-b border-white/[0.08] text-zinc-400 uppercase font-mono tracking-wider text-[11px]">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Attack Vector &amp; CWE</th>
                <th className="py-3 px-4">Target Endpoint</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Fast-Path Containment</th>
                <th className="py-3 px-4">Bayesian Conf.</th>
                <th className="py-3 px-4 text-right">Inspection</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {filteredIncidents.map((inc) => (
                <tr
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  className={`cursor-pointer transition-colors hover:bg-white/[0.03] ${
                    selectedIncident?.id === inc.id ? "bg-blue-600/10 border-l-2 border-l-blue-400" : ""
                  }`}
                >
                  <td className="py-3.5 px-4 font-mono text-zinc-400 whitespace-nowrap">
                    {new Date(inc.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-3.5 px-4">
                    <div className="font-semibold text-white flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-400 flex-shrink-0" />
                      <span>{inc.attack_type}</span>
                    </div>
                    <span className="text-[10px] font-mono text-blue-400">{inc.cwe}</span>
                  </td>
                  <td className="py-3.5 px-4 font-mono text-zinc-300">
                    <span className="px-1.5 py-0.5 rounded bg-white/[0.05] text-[10px] text-zinc-400 mr-1.5 font-bold">
                      {inc.method}
                    </span>
                    {inc.endpoint}
                  </td>
                  <td className="py-3.5 px-4">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getSeverityBadge(inc.severity)}`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="py-3.5 px-4">
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${getActionBadge(inc.containment_action)}`}>
                      {inc.containment_action}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 font-mono">
                    <span className="text-emerald-400 font-semibold">
                      {(inc.bayesian_confidence * 100).toFixed(2)}%
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedIncident(inc);
                      }}
                      className="p-1.5 rounded-lg bg-white/[0.04] text-zinc-300 hover:text-white hover:bg-white/[0.08] transition"
                    >
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Detail Drawer / Modal */}
      {selectedIncident && (
        <div className="p-6 glass-panel border-blue-500/30 bg-blue-950/20 space-y-4 animate-in fade-in duration-200">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2">
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getSeverityBadge(selectedIncident.severity)}`}>
                  {selectedIncident.severity}
                </span>
                <h3 className="text-base font-bold text-white">{selectedIncident.attack_type}</h3>
              </div>
              <p className="text-xs text-zinc-400 mt-1">{selectedIncident.details}</p>
            </div>
            <button
              onClick={() => setSelectedIncident(null)}
              className="text-xs font-semibold text-zinc-400 hover:text-white px-2 py-1 rounded bg-white/[0.05]"
            >
              Close
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
            <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <span className="text-zinc-500 block text-[10px] uppercase">Session &amp; Client</span>
              <span className="text-zinc-300">{selectedIncident.session_id}</span>
              <span className="text-zinc-500 block text-[10px] mt-1">IP: {selectedIncident.ip_address}</span>
            </div>
            <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <span className="text-zinc-500 block text-[10px] uppercase">OpenTelemetry Trace</span>
              <span className="text-blue-300 truncate block">{selectedIncident.trace_id}</span>
              <span className="text-emerald-400 block text-[10px] mt-1">HTTP {selectedIncident.response_status} BLOCKED</span>
            </div>
            <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <span className="text-zinc-500 block text-[10px] uppercase">Bayesian Multi-Pillar Score</span>
              <span className="text-emerald-400 font-bold text-sm">{(selectedIncident.bayesian_confidence * 100).toFixed(4)}%</span>
              <span className="text-zinc-500 block text-[10px] mt-1">P(Vuln | SAST, DAST, Runtime)</span>
            </div>
          </div>

          {selectedIncident.raw_payload && (
            <div className="space-y-1.5">
              <span className="text-xs font-mono text-zinc-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-zinc-400" />
                Raw Intercepted Payload:
              </span>
              <pre className="p-3 rounded-xl bg-black/60 border border-white/[0.08] text-xs font-mono text-red-300 overflow-x-auto whitespace-pre-wrap">
                {selectedIncident.raw_payload}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
