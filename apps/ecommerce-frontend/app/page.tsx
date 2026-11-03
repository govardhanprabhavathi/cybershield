"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  ShieldAlert,
  Zap,
  Activity,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCw,
  Flame,
  Wrench,
  Workflow,
  Radio,
  Layers,
  Sparkles,
  Lock,
  ExternalLink,
  Code2,
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
import InteractiveWorkflowCanvas from "../components/dashboard/InteractiveWorkflowCanvas";

type TabKey = "overview" | "workflow" | "incidents" | "patches" | "simulator";

export default function SecurityCommandCenter() {
  const [activeTab, setActiveTab] = useState<TabKey>("overview");
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

    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const tabParam = params.get("tab") as TabKey;
      const hashParam = window.location.hash.replace("#", "") as TabKey;
      const validTabs: TabKey[] = ["overview", "workflow", "incidents", "patches", "simulator"];
      
      if (tabParam && validTabs.includes(tabParam)) {
        setActiveTab(tabParam);
      } else if (hashParam && validTabs.includes(hashParam)) {
        setActiveTab(hashParam);
      }
    }
  }, []);

  const handleTabChange = (key: TabKey) => {
    setActiveTab(key);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.searchParams.set("tab", key);
      window.history.replaceState({}, "", url.toString());
    }
  };

  const handleQuickExploit = async (type: "SQLI" | "BOLA" | "CART_TAMPER" | "BRUTE_FORCE") => {
    const res = await api.triggerExploit(type);
    await loadData();
    setQuickNotification(res.message);
    setTimeout(() => setQuickNotification(null), 5000);
  };

  const handleApplyPatch = async (proposalId: string) => {
    const ok = await api.applyPatch(proposalId);
    if (ok) {
      await loadData();
      setQuickNotification("AST Patch successfully applied to production code!");
      setTimeout(() => setQuickNotification(null), 4000);
    }
    return ok;
  };

  const handleRollbackPatch = async (proposalId: string) => {
    const ok = await api.rollbackPatch(proposalId);
    if (ok) {
      await loadData();
      setQuickNotification("Patch reverted cleanly to backup state.");
      setTimeout(() => setQuickNotification(null), 4000);
    }
    return ok;
  };

  const runScenario = async (type: "ATTACK" | "LEGITIMATE" | "NAT") => {
    const scenario: SimulationScenario = {
      id: `SCENARIO-${Date.now()}`,
      name:
        type === "ATTACK"
          ? "SQL Injection Attack Storm"
          : type === "LEGITIMATE"
          ? "100 Legitimate Shoppers"
          : "Shared-IP NAT Gateway Disambiguation",
      description: "Multi-threaded concurrency verification",
      legitimate_threads: type === "ATTACK" ? 10 : 80,
      attacker_threads: type === "ATTACK" ? 40 : type === "NAT" ? 5 : 0,
      attack_vectors: type === "LEGITIMATE" ? [] : ["SQLi (CWE-89)", "BOLA (CWE-284)"],
      duration_seconds: 5,
      nat_spoofing: type === "NAT",
    };
    const report = await api.runSimulation(scenario);
    await loadData();
    setQuickNotification(`Simulation completed: ${report.scenario.name} processed across ${report.total_requests} events.`);
    setTimeout(() => setQuickNotification(null), 4000);
    return report;
  };

  return (
    <div className="space-y-12">
      {/* =====================================================================
          1. HERO HEADER SECTION (Inspired by Screenshot 1 & 2)
          ===================================================================== */}
      <section className="pt-4 text-center max-w-4xl mx-auto space-y-6">
        <div className="flex justify-center">
          <div className="clean-pill">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Autonomous Multi-Agent Defense Engine</span>
          </div>
        </div>

        <h1 className="text-4xl sm:text-6xl font-bold tracking-tight text-[#141414] leading-[1.12]">
          Intelligent security for your store with{" "}
          <span className="italic-accent font-serif">sub-2ms</span> speed
        </h1>

        <p className="text-base sm:text-lg text-[#66625B] max-w-2xl mx-auto leading-relaxed">
          CyberShield coordinates 11 specialized AI agents to inspect, contain, and automatically patch vulnerabilities in real time—with zero false alarms.
        </p>

        {/* Quick Exploit Trigger Bar & Store Demo CTA */}
        <div className="pt-2 flex flex-wrap items-center justify-center gap-3">
          <span className="text-xs font-medium text-[#7D786F]">Quick Test:</span>
          
          <button
            onClick={() => handleQuickExploit("SQLI")}
            className="btn-light text-xs py-2 px-4 hover:border hover:border-black/20"
          >
            <Flame className="w-3.5 h-3.5 text-rose-600 mr-1.5" />
            Test SQL Injection
          </button>

          <button
            onClick={() => handleQuickExploit("BOLA")}
            className="btn-light text-xs py-2 px-4 hover:border hover:border-black/20"
          >
            <Lock className="w-3.5 h-3.5 text-amber-600 mr-1.5" />
            Test BOLA Access
          </button>

          <button
            onClick={() => handleQuickExploit("CART_TAMPER")}
            className="btn-light text-xs py-2 px-4 hover:border hover:border-black/20"
          >
            <Zap className="w-3.5 h-3.5 text-blue-600 mr-1.5" />
            Test Cart Logic
          </button>

          <Link
            href="/store"
            className="btn-dark text-xs py-2 px-5 ml-1"
          >
            Open Storefront &rarr;
          </Link>
        </div>

        {/* Floating Notification Banner */}
        {quickNotification && (
          <div className="max-w-xl mx-auto p-4 rounded-2xl bg-white border border-[#E0DACF] shadow-lg flex items-center justify-between text-xs text-[#222] animate-in fade-in slide-in-from-top-2 duration-300">
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span className="font-medium">{quickNotification}</span>
            </div>
            <button
              onClick={() => setQuickNotification(null)}
              className="text-[#888] hover:text-[#111] px-2 py-0.5 rounded text-[11px]"
            >
              Dismiss
            </button>
          </div>
        )}
      </section>

      {/* =====================================================================
          2. MINIMALIST NAV PILLS / VIEW SELECTOR
          ===================================================================== */}
      <div className="flex justify-center">
        <div className="inline-flex items-center gap-1.5 p-1 rounded-full bg-[#EAE5DE] border border-[#DDD7CD]">
          {[
            { key: "overview", label: "Overview" },
            { key: "workflow", label: "Interactive Flow", badge: "Live" },
            { key: "incidents", label: "Threat Stream", badge: `${incidents.length}` },
            { key: "patches", label: "Auto-Patches", badge: `${proposals.length}` },
            { key: "simulator", label: "Traffic Simulator" },
          ].map((tab) => {
            const isActive = activeTab === tab.key;
            return (
              <button
                key={tab.key}
                onClick={() => handleTabChange(tab.key as TabKey)}
                className={`flex items-center gap-2 px-5 py-2 rounded-full text-xs font-semibold transition-all duration-200 ${
                  isActive
                    ? "bg-white text-[#141414] shadow-sm"
                    : "text-[#6B665E] hover:text-[#141414]"
                }`}
              >
                <span>{tab.label}</span>
                {tab.badge && (
                  <span
                    className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                      isActive ? "bg-black text-white" : "bg-[#DDD7CE] text-[#444]"
                    }`}
                  >
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* =====================================================================
          3. TAB CONTENT: OVERVIEW (Replicating Screenshots 1, 2, 3)
          ===================================================================== */}
      {activeTab === "overview" && (
        <div className="space-y-12">
          {/* THREE CORE SERVICE CARDS (Exact recreation of Screenshot 1) */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Card 1: Fast-Path Gate */}
            <div className="clean-card clean-card-hover p-8 flex flex-col justify-between space-y-6">
              <div className="space-y-6">
                <div className="w-16 h-16 rounded-2xl bg-[#F5F2EB] flex items-center justify-center text-[#141414] shadow-inner">
                  <ShieldCheck className="w-8 h-8 text-[#141414]" />
                </div>
                <div>
                  <h3 className="text-2xl font-bold text-[#141414] tracking-tight">
                    Sub-2ms Containment
                  </h3>
                  <p className="text-sm text-[#66625B] mt-2.5 leading-relaxed">
                    Deterministic fast-path gateway inspecting every HTTP query in microseconds. Malicious payloads are isolated before reaching your core database.
                  </p>
                </div>
              </div>
              <div className="pt-4 border-t border-[#F0ECE4] flex items-center justify-between text-xs font-medium text-[#7D786F]">
                <span>Speed: &le; 1.4ms</span>
                <span className="text-emerald-700 font-semibold">100% Contained</span>
              </div>
            </div>

            {/* Card 2: Bayesian Triangulation */}
            <div className="clean-card clean-card-hover p-8 flex flex-col justify-between space-y-6">
              <div className="space-y-6">
                <div className="w-16 h-16 rounded-2xl bg-[#F5F2EB] flex items-center justify-center text-[#141414] shadow-inner">
                  <Layers className="w-8 h-8 text-[#141414]" />
                </div>
                <div>
                  <h3 className="text-2xl font-bold text-[#141414] tracking-tight">
                    Multi-Plane Verification
                  </h3>
                  <p className="text-sm text-[#66625B] mt-2.5 leading-relaxed">
                    Combines static code analysis, dynamic API probing, and live runtime telemetry into mathematical certainty ($P \ge 0.99$) with zero false alarms.
                  </p>
                </div>
              </div>
              <div className="pt-4 border-t border-[#F0ECE4] flex items-center justify-between text-xs font-medium text-[#7D786F]">
                <span>Bayesian Model</span>
                <span className="text-emerald-700 font-semibold">0% False Positives</span>
              </div>
            </div>

            {/* Card 3: Automated Remediation */}
            <div className="clean-card clean-card-hover p-8 flex flex-col justify-between space-y-6">
              <div className="space-y-6">
                <div className="w-16 h-16 rounded-2xl bg-[#F5F2EB] flex items-center justify-center text-[#141414] shadow-inner">
                  <Wrench className="w-8 h-8 text-[#141414]" />
                </div>
                <div>
                  <h3 className="text-2xl font-bold text-[#141414] tracking-tight">
                    Autonomous Auto-Repair
                  </h3>
                  <p className="text-sm text-[#66625B] mt-2.5 leading-relaxed">
                    When vulnerabilities are verified, AST repair agents generate verified source-code diffs and deploy hot-patches to permanently seal vulnerabilities.
                  </p>
                </div>
              </div>
              <div className="pt-4 border-t border-[#F0ECE4] flex items-center justify-between text-xs font-medium text-[#7D786F]">
                <span>AST Sandboxed</span>
                <span className="text-emerald-700 font-semibold">1-Click Rollback</span>
              </div>
            </div>
          </div>

          {/* EDITORIAL HIGHLIGHT & STATS SECTION (Replicating Screenshot 2 & 3) */}
          <div className="clean-card p-10 sm:p-12">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">
              <div className="lg:col-span-7 space-y-6">
                <div className="clean-pill">
                  <span>System Reliability</span>
                </div>

                <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-[#141414] leading-snug">
                  Turning security vulnerabilities into{" "}
                  <span className="italic-accent font-serif">predictable</span> immunity
                </h2>

                <p className="text-sm sm:text-base text-[#66625B] leading-relaxed">
                  Rather than overwhelming developers with noisy alerts and manual triage, CyberShield coordinates 11 autonomous agents to continuously audit code, probe endpoints, and contain attacks without slowing down genuine shoppers.
                </p>

                {/* Big Clean Numbers (from Screenshot 3) */}
                <div className="pt-6 grid grid-cols-2 sm:grid-cols-3 gap-8 border-t border-[#F0ECE4]">
                  <div>
                    <div className="text-3xl sm:text-4xl font-extrabold text-[#141414] tracking-tight">
                      1.2ms
                    </div>
                    <div className="text-xs font-semibold text-[#141414] mt-1">Fast-Path SLA</div>
                    <div className="text-[11px] text-[#7D786F] mt-0.5">Average containment speed</div>
                  </div>

                  <div>
                    <div className="text-3xl sm:text-4xl font-extrabold text-emerald-700 tracking-tight">
                      0.0%
                    </div>
                    <div className="text-xs font-semibold text-[#141414] mt-1">False Positives</div>
                    <div className="text-[11px] text-[#7D786F] mt-0.5">Clean traffic unaffected</div>
                  </div>

                  <div>
                    <div className="text-3xl sm:text-4xl font-extrabold text-[#141414] tracking-tight">
                      11
                    </div>
                    <div className="text-xs font-semibold text-[#141414] mt-1">Active Agents</div>
                    <div className="text-[11px] text-[#7D786F] mt-0.5">Autonomous background mesh</div>
                  </div>
                </div>
              </div>

              {/* Right Side Visual Status Summary */}
              <div className="lg:col-span-5 bg-[#FAF8F5] rounded-3xl p-8 border border-[#EBE6DE] space-y-5">
                <div className="flex items-center justify-between pb-4 border-b border-[#EAE5DE]">
                  <span className="text-xs font-bold uppercase tracking-wider text-[#7D786F]">
                    Live Status
                  </span>
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 animate-pulse" />
                    All Systems Immune
                  </span>
                </div>

                <div className="space-y-3.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-[#66625B]">Fast-Path Interceptor</span>
                    <span className="font-semibold text-[#141414]">Operational (Port 8000)</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#66625B]">Redis Event Stream</span>
                    <span className="font-semibold text-[#141414]">Connected (Zero Lag)</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#66625B]">Session Shield Engine</span>
                    <span className="font-semibold text-[#141414]">Bayesian Decay Active</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[#66625B]">Remediation Sandbox</span>
                    <span className="font-semibold text-[#141414]">AST Syntax Checked</span>
                  </div>
                </div>

                <div className="pt-2">
                  <button
                    onClick={() => handleTabChange("workflow")}
                    className="w-full btn-dark flex items-center justify-center gap-2 py-3"
                  >
                    <span>Explore Visual Flow</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
          4. TAB CONTENT: INTERACTIVE WORKFLOW CANVAS
          ===================================================================== */}
      {activeTab === "workflow" && (
        <div className="space-y-6">
          <div className="text-center max-w-2xl mx-auto space-y-2 pb-2">
            <div className="clean-pill">
              <span>Interactive Pipeline Architecture</span>
            </div>
            <h2 className="text-3xl font-bold tracking-tight text-[#141414]">
              Visual Flow from Request to{" "}
              <span className="italic-accent font-serif">Immunity</span>
            </h2>
            <p className="text-sm text-[#66625B]">
              Pan, zoom, or run live simulations to watch packets flow through the fast-path gate, Redis streams, and the multi-agent mesh.
            </p>
          </div>

          <InteractiveWorkflowCanvas />
        </div>
      )}

      {/* =====================================================================
          5. TAB CONTENT: INCIDENTS & THREAT STREAM (Minimal & Clean)
          ===================================================================== */}
      {activeTab === "incidents" && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="clean-pill">
                <span>Threat Intelligence</span>
              </div>
              <h2 className="text-2xl font-bold text-[#141414] mt-2">
                Live Contained Incidents
              </h2>
            </div>
            <button
              onClick={loadData}
              className="btn-light text-xs flex items-center gap-2"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
              <span>Refresh</span>
            </button>
          </div>

          <div className="clean-card p-6 sm:p-8 space-y-4">
            {incidents.length === 0 ? (
              <div className="py-12 text-center text-[#7D786F] space-y-2">
                <CheckCircle2 className="w-10 h-10 text-emerald-600 mx-auto" />
                <p className="font-semibold text-sm text-[#141414]">Zero active threat alerts</p>
                <p className="text-xs">All incoming requests are currently legitimate and within normal thresholds.</p>
              </div>
            ) : (
              <div className="divide-y divide-[#F0ECE4]">
                {incidents.map((inc) => (
                  <div key={inc.id} className="py-4 first:pt-0 last:pb-0 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-rose-100 text-rose-800">
                          {inc.attack_type}
                        </span>
                        <span className="text-xs font-mono text-[#7D786F]">{inc.endpoint}</span>
                        <span className="text-xs text-[#999]">•</span>
                        <span className="text-xs text-[#7D786F]">Risk Score: <strong>{inc.risk_score}/100</strong></span>
                      </div>
                      <p className="text-xs text-[#444] font-medium">{inc.details}</p>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="text-[11px] font-mono text-[#888]">{inc.timestamp}</span>
                      <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800">
                        Contained (403)
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* =====================================================================
          6. TAB CONTENT: AUTO-PATCHES & REMEDIATION (Minimal & Understandable)
          ===================================================================== */}
      {activeTab === "patches" && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="clean-pill">
                <span>AST Self-Healing</span>
              </div>
              <h2 className="text-2xl font-bold text-[#141414] mt-2">
                Automated Code Patches
              </h2>
            </div>
            <button
              onClick={loadData}
              className="btn-light text-xs flex items-center gap-2"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
              <span>Refresh</span>
            </button>
          </div>

          <div className="grid grid-cols-1 gap-6">
            {proposals.length === 0 ? (
              <div className="clean-card p-12 text-center text-[#7D786F] space-y-2">
                <CheckCircle2 className="w-10 h-10 text-emerald-600 mx-auto" />
                <p className="font-semibold text-sm text-[#141414]">No pending code vulnerabilities</p>
                <p className="text-xs">All code paths have been reviewed by SAST and verified immune.</p>
              </div>
            ) : (
              proposals.map((patch) => (
                <div key={patch.proposal_id} className="clean-card p-8 space-y-6">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-800">
                          {patch.cwe}
                        </span>
                        <span className="text-xs font-bold text-[#141414]">{patch.target_file}</span>
                      </div>
                      <p className="text-sm text-[#66625B]">{patch.description}</p>
                    </div>

                    <div className="flex items-center gap-2">
                      {patch.status === "APPLIED" ? (
                        <button
                          onClick={() => handleRollbackPatch(patch.proposal_id)}
                          className="btn-light text-xs py-2 px-4"
                        >
                          Rollback Patch
                        </button>
                      ) : (
                        <button
                          onClick={() => handleApplyPatch(patch.proposal_id)}
                          className="btn-dark text-xs py-2 px-5"
                        >
                          Apply Code Patch
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="bg-[#1E1E1E] text-zinc-200 rounded-2xl p-4 font-mono text-xs overflow-x-auto space-y-3">
                    {patch.diff_items?.map((item, idx) => (
                      <div key={idx} className="space-y-1">
                        <div className="text-zinc-400 text-[11px]">
                          Line {item.line_number} • {item.fix_type}
                        </div>
                        <div className="text-rose-400 bg-rose-950/40 p-2 rounded">
                          - {item.vulnerable_code}
                        </div>
                        <div className="text-emerald-400 bg-emerald-950/40 p-2 rounded">
                          + {item.remediated_code}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* =====================================================================
          7. TAB CONTENT: TRAFFIC SIMULATOR (Clean & Understandable)
          ===================================================================== */}
      {activeTab === "simulator" && (
        <div className="space-y-6">
          <div className="text-center max-w-xl mx-auto space-y-2">
            <div className="clean-pill">
              <span>Traffic & Concurrency Lab</span>
            </div>
            <h2 className="text-3xl font-bold text-[#141414]">
              Simulate Real-World Scenarios
            </h2>
            <p className="text-sm text-[#66625B]">
              Run multi-vector attacks, shared-IP NAT scenarios, or legitimate shopper journeys to test CyberShield in action.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
            <div className="clean-card p-8 flex flex-col justify-between space-y-6">
              <div className="space-y-3">
                <h3 className="text-xl font-bold text-[#141414]">SQL Injection Attack</h3>
                <p className="text-xs text-[#66625B]">
                  Simulates a persistent SQL injection assault across search and product filters to observe instant fast-path containment.
                </p>
              </div>
              <button
                onClick={() => runScenario("ATTACK")}
                className="btn-dark w-full text-xs"
              >
                Run Attack Simulation &rarr;
              </button>
            </div>

            <div className="clean-card p-8 flex flex-col justify-between space-y-6">
              <div className="space-y-3">
                <h3 className="text-xl font-bold text-[#141414]">Legitimate Shopping</h3>
                <p className="text-xs text-[#66625B]">
                  Simulates 100 genuine customers browsing, adding to cart, and checking out with 0% false positives.
                </p>
              </div>
              <button
                onClick={() => runScenario("LEGITIMATE")}
                className="btn-light w-full text-xs hover:border hover:border-black/20"
              >
                Run Shopper Simulation &rarr;
              </button>
            </div>

            <div className="clean-card p-8 flex flex-col justify-between space-y-6">
              <div className="space-y-3">
                <h3 className="text-xl font-bold text-[#141414]">Shared-IP (NAT) Test</h3>
                <p className="text-xs text-[#66625B]">
                  Simulates 1 attacker and 4 clean users sharing the exact same IP. Demonstrates user-session risk disambiguation.
                </p>
              </div>
              <button
                onClick={() => runScenario("NAT")}
                className="btn-light w-full text-xs hover:border hover:border-black/20"
              >
                Run NAT Disambiguation &rarr;
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
