"use client";

import React, { useState } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Users,
  Network,
  AlertTriangle,
  Flame,
  CheckCircle,
  XCircle,
  HelpCircle,
} from "lucide-react";
import { SessionRiskProfile, ContainmentLevel } from "../../lib/types";

interface SessionRiskMatrixProps {
  sessions: SessionRiskProfile[];
  onResetSession: (sessionId: string) => Promise<void>;
  onTriggerExploitForSession?: (sessionId: string) => Promise<void>;
}

export default function SessionRiskMatrix({
  sessions,
  onResetSession,
  onTriggerExploitForSession,
}: SessionRiskMatrixProps) {
  const [resettingId, setResettingId] = useState<string | null>(null);

  const handleReset = async (sessionId: string) => {
    setResettingId(sessionId);
    await onResetSession(sessionId);
    setResettingId(null);
  };

  const getContainmentBadge = (level: ContainmentLevel) => {
    switch (level) {
      case "MONITOR":
        return {
          label: "MONITOR (0-25)",
          color: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
          barColor: "bg-emerald-500",
        };
      case "RATE_LIMIT":
        return {
          label: "RATE_LIMIT (26-50)",
          color: "bg-yellow-500/10 text-yellow-300 border-yellow-500/30",
          barColor: "bg-yellow-500",
        };
      case "REQUIRE_CHALLENGE":
        return {
          label: "CHALLENGE (51-75)",
          color: "bg-amber-500/10 text-amber-300 border-amber-500/30",
          barColor: "bg-amber-500",
        };
      case "ISOLATE_CONTAIN":
        return {
          label: "ISOLATE (76-90)",
          color: "bg-orange-500/10 text-orange-300 border-orange-500/30",
          barColor: "bg-orange-500",
        };
      case "QUARANTINE_BLOCK":
        return {
          label: "QUARANTINE (91-100)",
          color: "bg-rose-500/20 text-rose-300 border-rose-500/40 shadow-[0_0_10px_rgba(244,63,94,0.3)]",
          barColor: "bg-rose-500",
        };
    }
  };

  return (
    <div className="space-y-6">
      {/* NAT Disambiguation Architecture Callout */}
      <div className="p-4 rounded-2xl bg-blue-950/20 border border-blue-500/20 backdrop-blur-xl">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-xl bg-blue-500/20 text-blue-400 border border-blue-400/30">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-white flex items-center gap-2">
              Shared-IP NAT Disambiguation Engine (Agent 8)
              <span className="px-2 py-0.5 rounded-full text-[10px] bg-blue-500/20 text-blue-300 border border-blue-400/30 font-mono">
                Granular Session Isolation
              </span>
            </h4>
            <p className="text-xs text-zinc-400 mt-1 leading-relaxed">
              Traditional IP-based rate limiters or firewalls indiscriminately block entire corporate offices, mobile networks, or universities when an attacker strikes.
              CyberShield couples cookie cryptographic entropy, TLS fingerprints, and route profiles to quarantine the malicious session while preserving uninterrupted access for legitimate shoppers sharing IP <span className="font-mono text-zinc-300 font-bold">198.51.100.42</span>.
            </p>
          </div>
        </div>
      </div>

      {/* Graduated Containment Progression Legend */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
        <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] text-center">
          <span className="text-[10px] font-mono uppercase text-emerald-400 font-bold block">Level 1: Monitor</span>
          <span className="text-xs text-zinc-300 font-semibold mt-1 block">Risk 0–25</span>
          <p className="text-[10px] text-zinc-500 mt-0.5">Passive telemetry logging</p>
        </div>
        <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] text-center">
          <span className="text-[10px] font-mono uppercase text-yellow-400 font-bold block">Level 2: Rate Limit</span>
          <span className="text-xs text-zinc-300 font-semibold mt-1 block">Risk 26–50</span>
          <p className="text-[10px] text-zinc-500 mt-0.5">Redis token bucket throttling</p>
        </div>
        <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] text-center">
          <span className="text-[10px] font-mono uppercase text-amber-400 font-bold block">Level 3: Challenge</span>
          <span className="text-xs text-zinc-300 font-semibold mt-1 block">Risk 51–75</span>
          <p className="text-[10px] text-zinc-500 mt-0.5">Proof-of-work cryptographic challenge</p>
        </div>
        <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] text-center">
          <span className="text-[10px] font-mono uppercase text-orange-400 font-bold block">Level 4: Isolate</span>
          <span className="text-xs text-zinc-300 font-semibold mt-1 block">Risk 76–90</span>
          <p className="text-[10px] text-zinc-500 mt-0.5">Read-only sandbox restriction</p>
        </div>
        <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] text-center">
          <span className="text-[10px] font-mono uppercase text-rose-400 font-bold block">Level 5: Quarantine</span>
          <span className="text-xs text-zinc-300 font-semibold mt-1 block">Risk 91–100</span>
          <p className="text-[10px] text-zinc-500 mt-0.5">HTTP 403 Fast-path total block</p>
        </div>
      </div>

      {/* Active Sessions Matrix Table */}
      <div className="glass-panel overflow-hidden">
        <div className="p-4 border-b border-white/[0.08] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-bold text-white">Active Session Risk &amp; Quarantine Registry</h3>
          </div>
          <span className="text-xs text-zinc-400 font-mono">{sessions.length} tracked sessions</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-white/[0.02] border-b border-white/[0.08] text-zinc-400 uppercase font-mono tracking-wider text-[11px]">
              <tr>
                <th className="py-3 px-4">Session Identity</th>
                <th className="py-3 px-4">Network &amp; NAT Cluster</th>
                <th className="py-3 px-4">Dynamic Risk Score (0–100)</th>
                <th className="py-3 px-4">Containment State</th>
                <th className="py-3 px-4">Attack History</th>
                <th className="py-3 px-4 text-right">Admin Override</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/[0.04]">
              {sessions.map((sess) => {
                const badge = getContainmentBadge(sess.containment_level);
                return (
                  <tr key={sess.session_id} className="hover:bg-white/[0.02] transition">
                    <td className="py-3.5 px-4">
                      <div className="font-mono font-semibold text-white flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full ${sess.is_quarantined ? "bg-rose-500" : "bg-emerald-400"}`} />
                        {sess.session_id}
                      </div>
                      <span className="text-[10px] text-zinc-400 truncate max-w-xs block mt-0.5 font-sans">
                        {sess.user_agent}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono">
                      <span className="text-zinc-200 block">{sess.ip_address}</span>
                      {sess.nat_cluster && (
                        <span className="inline-block mt-0.5 px-1.5 py-0.2 rounded text-[10px] bg-blue-500/10 text-blue-300 border border-blue-500/20">
                          {sess.nat_cluster}
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 w-48">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono font-bold text-zinc-100">{sess.risk_score} / 100</span>
                        <span className="text-[10px] text-zinc-400">{sess.last_activity}</span>
                      </div>
                      <div className="w-full h-2 rounded-full bg-white/[0.08] overflow-hidden">
                        <div
                          className={`h-full transition-all duration-500 ${badge.barColor}`}
                          style={{ width: `${Math.max(sess.risk_score, 4)}%` }}
                        />
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold border ${badge.color}`}>
                        {badge.label}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      {sess.attack_history.length > 0 ? (
                        <div className="space-y-0.5">
                          {sess.attack_history.slice(-2).map((att, idx) => (
                            <span key={idx} className="block text-[11px] font-mono text-rose-300 truncate max-w-xs">
                              &bull; {att}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-[11px] text-emerald-400 font-mono">None (Benign Shopping Session)</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      {sess.risk_score > 0 ? (
                        <button
                          onClick={() => handleReset(sess.session_id)}
                          disabled={resettingId === sess.session_id}
                          className="px-2.5 py-1 rounded-lg bg-white/[0.05] border border-white/[0.1] text-zinc-300 hover:text-white hover:bg-white/[0.1] text-xs font-semibold inline-flex items-center gap-1 transition"
                        >
                          <RefreshCw className={`w-3 h-3 ${resettingId === sess.session_id ? "animate-spin" : ""}`} />
                          Reset
                        </button>
                      ) : (
                        <span className="text-[11px] text-zinc-500 font-mono">Nominal</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
