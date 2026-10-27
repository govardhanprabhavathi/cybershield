"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  LayoutDashboard,
  Radio,
  Users,
  Layers,
  Wrench,
  BarChart3,
  ShieldAlert,
  ShoppingBag,
  Sparkles,
  Zap,
  RotateCw,
  Flame,
} from "lucide-react";
import { api } from "../lib/api";
import {
  TelemetryStats,
  SecurityIncident,
  SessionRiskProfile,
  TriangulatedDossier,
  RemediationProposal,
  SimulationScenario,
  SimulationReport,
} from "../lib/types";
import ExecutiveKPIs from "../components/dashboard/ExecutiveKPIs";
import LiveTelemetryStream from "../components/dashboard/LiveTelemetryStream";
import SessionRiskMatrix from "../components/dashboard/SessionRiskMatrix";
import EvidenceTriangulationView from "../components/dashboard/EvidenceTriangulationView";
import RemediationWorkbench from "../components/dashboard/RemediationWorkbench";
import TrafficSimulator from "../components/dashboard/TrafficSimulator";

type TabKey = "kpis" | "stream" | "sessions" | "triangulation" | "remediation" | "simulator";

export default function SecurityCommandCenter() {
  const [activeTab, setActiveTab] = useState<TabKey>("kpis");
  const [stats, setStats] = useState<TelemetryStats | null>(null);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [sessions, setSessions] = useState<SessionRiskProfile[]>([]);
  const [dossiers, setDossiers] = useState<TriangulatedDossier[]>([]);
  const [proposals, setProposals] = useState<RemediationProposal[]>([]);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [quickNotification, setQuickNotification] = useState<string | null>(null);

  const loadData = async () => {
    setIsRefreshing(true);
    try {
      const [s, inc, sess, dos, rem] = await Promise.all([
        api.getTelemetryStats(),
        api.getIncidents(),
        api.getSessions(),
        api.getDossiers(),
        api.getRemediationProposals(),
      ]);
      setStats(s);
      setIncidents(inc);
      setSessions(sess);
      setDossiers(dos);
      setProposals(rem);
    } catch (err) {
      console.error("Failed to load command center data:", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleResetSession = async (sessionId: string) => {
    await api.resetSessionRisk(sessionId);
    await loadData();
    setQuickNotification(`Session ${sessionId} risk reset to 0 in Redis.`);
    setTimeout(() => setQuickNotification(null), 3000);
  };

  const handleApplyPatch = async (proposalId: string) => {
    const ok = await api.applyPatch(proposalId);
    if (ok) await loadData();
    return ok;
  };

  const handleRollbackPatch = async (proposalId: string) => {
    const ok = await api.rollbackPatch(proposalId);
    if (ok) await loadData();
    return ok;
  };

  const handleRunSimulation = async (scenario: SimulationScenario): Promise<SimulationReport> => {
    const report = await api.runSimulation(scenario);
    await loadData();
    return report;
  };

  const handleQuickExploit = async (type: "SQLI" | "BOLA" | "CART_TAMPER" | "BRUTE_FORCE") => {
    const res = await api.triggerExploit(type);
    await loadData();
    setQuickNotification(res.message);
    setTimeout(() => setQuickNotification(null), 5000);
  };

  const tabs: { key: TabKey; label: string; icon: React.ReactNode; badge?: string }[] = [
    { key: "kpis", label: "Executive KPIs", icon: <LayoutDashboard className="w-4 h-4" /> },
    { key: "stream", label: "Threat Stream", icon: <Radio className="w-4 h-4" />, badge: `${incidents.length}` },
    { key: "sessions", label: "Session Matrix", icon: <Users className="w-4 h-4" />, badge: `${sessions.length}` },
    { key: "triangulation", label: "Evidence Triangulation", icon: <Layers className="w-4 h-4" />, badge: "P \u2265 0.99" },
    { key: "remediation", label: "Automated Remediation", icon: <Wrench className="w-4 h-4" />, badge: "AST" },
    { key: "simulator", label: "Traffic Simulator", icon: <BarChart3 className="w-4 h-4" /> },
  ];

  return (
    <div className="space-y-6">
      {/* Top Console Command Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-6 glass-panel border-blue-500/20">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-blue-500/10 text-blue-300 border border-blue-400/30 shadow-[0_0_15px_rgba(59,130,246,0.15)]">
              Operations Center
            </span>
            <span className="text-xs font-mono text-zinc-400">Surface B Console</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight mt-2">
            CyberShield Autonomous Defense Console
          </h1>
          <p className="text-xs sm:text-sm text-zinc-400 mt-1 max-w-2xl">
            Real-time observability and response engine uniting 11 specialized autonomous agents.
            Deterministic fast-path containment operating at sub-2ms latency with zero false positives.
          </p>
        </div>

        {/* Quick Exploit Trigger Bar & Demo Actions */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 p-1 rounded-xl bg-white/[0.03] border border-white/[0.08]">
            <span className="text-[11px] font-mono text-zinc-400 px-2 flex items-center gap-1">
              <Flame className="w-3.5 h-3.5 text-rose-400" />
              Quick Exploit:
            </span>
            <button
              onClick={() => handleQuickExploit("SQLI")}
              className="px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 transition"
              title="Test CWE-89 SQL Injection against search endpoint"
            >
              SQLi
            </button>
            <button
              onClick={() => handleQuickExploit("BOLA")}
              className="px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition"
              title="Test CWE-284 BOLA cross-tenant order ID lookup"
            >
              BOLA
            </button>
            <button
              onClick={() => handleQuickExploit("CART_TAMPER")}
              className="px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition"
              title="Test CWE-840 negative quantity cart balance tampering"
            >
              Cart Logic
            </button>
          </div>

          <Link
            href="/store"
            className="px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition shadow-[0_0_15px_rgba(37,99,235,0.3)]"
          >
            <ShoppingBag className="w-3.5 h-3.5" />
            <span>Storefront Demo &rarr;</span>
          </Link>
        </div>
      </div>

      {/* Floating Notification */}
      {quickNotification && (
        <div className="p-3.5 rounded-xl bg-blue-950/70 border border-blue-400/40 text-xs font-mono text-blue-200 flex items-center justify-between shadow-[0_0_25px_rgba(59,130,246,0.25)] animate-in fade-in">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{quickNotification}</span>
          </div>
          <button
            onClick={() => setQuickNotification(null)}
            className="text-[10px] text-zinc-400 hover:text-white px-2 py-0.5 rounded bg-white/[0.05]"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* 6-Tab Navigation Bar */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-none">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-all duration-200 border ${
                isActive
                  ? "bg-blue-600 text-white border-blue-400/50 shadow-[0_0_20px_rgba(37,99,235,0.35)]"
                  : "bg-white/[0.03] text-zinc-400 hover:text-white hover:bg-white/[0.06] border-white/[0.06]"
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
              {tab.badge && (
                <span
                  className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                    isActive ? "bg-white/20 text-white" : "bg-white/[0.08] text-zinc-300"
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Active Tab View Body */}
      <div className="transition-all duration-200">
        {activeTab === "kpis" && stats && <ExecutiveKPIs stats={stats} />}
        {activeTab === "stream" && <LiveTelemetryStream incidents={incidents} />}
        {activeTab === "sessions" && (
          <SessionRiskMatrix sessions={sessions} onResetSession={handleResetSession} />
        )}
        {activeTab === "triangulation" && <EvidenceTriangulationView dossiers={dossiers} />}
        {activeTab === "remediation" && (
          <RemediationWorkbench
            proposals={proposals}
            onApplyPatch={handleApplyPatch}
            onRollbackPatch={handleRollbackPatch}
          />
        )}
        {activeTab === "simulator" && <TrafficSimulator onRunSimulation={handleRunSimulation} />}
      </div>
    </div>
  );
}
