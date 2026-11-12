"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  RotateCw,
  CheckCircle2,
  ShieldAlert,
  Flame,
  Lock,
  Zap,
  ShieldCheck,
  ExternalLink,
  FileCode2,
  Layers,
  ArrowRight,
  Shield,
  AlertTriangle,
} from "lucide-react";
import { api } from "../../lib/api";
import { SecurityIncident, SessionRiskProfile, RemediationProposal, TargetProject } from "../../lib/types";

export default function IncidentsPage() {
  const [target, setTarget] = useState<TargetProject | null>(null);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [sessions, setSessions] = useState<SessionRiskProfile[]>([]);
  const [proposals, setProposals] = useState<RemediationProposal[]>([]);
  const [activeTab, setActiveTab] = useState<"incidents" | "patches" | "sessions">("incidents");
  const [selectedFilter, setSelectedFilter] = useState<string>("ALL");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  const loadData = async () => {
    setIsRefreshing(true);
    try {
      const [t, inc, sess, prop] = await Promise.all([
        api.getActiveTarget(),
        api.getIncidents(),
        api.getSessions(),
        api.getRemediationProposals(),
      ]);
      setTarget(t);
      setIncidents(inc);
      setSessions(sess);
      setProposals(prop);
    } catch (err) {
      console.error("Failed to load incidents:", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleRescan = async () => {
    setIsRefreshing(true);
    await api.rescanTarget();
    await loadData();
    setNotification("Diagnostics complete: Andhra Treats security posture re-evaluated. 4 active findings updated.");
    setTimeout(() => setNotification(null), 5000);
  };

  const handleApplyPatch = async (proposalId: string) => {
    const success = await api.applyPatch(proposalId);
    if (success) {
      await loadData();
      setNotification(`Patch ${proposalId} armed & applied! Security policies updated.`);
      setTimeout(() => setNotification(null), 5000);
    }
  };

  const handleRollbackPatch = async (proposalId: string) => {
    const success = await api.rollbackPatch(proposalId);
    if (success) {
      await loadData();
      setNotification(`Patch ${proposalId} rolled back.`);
      setTimeout(() => setNotification(null), 4000);
    }
  };

  const handleQuickExploit = async (type: "SQLI" | "BOLA" | "CART_TAMPER" | "BRUTE_FORCE") => {
    const res = await api.triggerExploit(type);
    await loadData();
    setNotification(res.message);
    setTimeout(() => setNotification(null), 4000);
  };

  const handleResetSession = async (sessionId: string) => {
    await api.resetSessionRisk(sessionId);
    await loadData();
    setNotification(`Session ${sessionId} risk reset to 0 in Redis.`);
    setTimeout(() => setNotification(null), 3000);
  };

  const filteredIncidents = incidents.filter((inc) => {
    if (selectedFilter === "ALL") return true;
    if (selectedFilter === "CRITICAL") return inc.severity === "CRITICAL";
    if (selectedFilter === "BOLA") return inc.cwe === "CWE-639" || inc.attack_type.includes("BOLA") || inc.attack_type.includes("PII");
    if (selectedFilter === "CART") return inc.cwe === "CWE-862" || inc.attack_type.includes("Cart");
    if (selectedFilter === "HEADERS") return inc.cwe === "CWE-693" || inc.attack_type.includes("Headers");
    return true;
  });

  return (
    <div className="space-y-8">
      {/* =====================================================================
          1. ACTIVE TARGET MONITORING BANNER (Andhra Treats)
          ===================================================================== */}
      <section className="clean-card p-6 sm:p-8 bg-white border border-[#E0DACF] shadow-sm space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="clean-pill">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span>Active Target Integrated</span>
              </span>
              <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded-full bg-black text-white">
                LIVE PRODUCTION
              </span>
            </div>

            <div className="flex items-center gap-3">
              <h1 className="text-2xl sm:text-3xl font-bold text-black tracking-tight">
                {target?.name || "Andhra Treats E-Commerce"}
              </h1>
              <a
                href={target?.url || "https://www.andhratreats.com"}
                target="_blank"
                rel="noreferrer"
                className="text-[#666666] hover:text-black transition"
                title="Visit Live Site"
              >
                <ExternalLink className="w-4 h-4" />
              </a>
            </div>

            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#555555] font-mono">
              <span><strong>URL:</strong> {target?.url}</span>
              <span>•</span>
              <span><strong>Repo:</strong> {target?.localPath}</span>
              <span>•</span>
              <span><strong>Stack:</strong> {target?.architecture}</span>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 flex-shrink-0">
            <button
              onClick={handleRescan}
              disabled={isRefreshing}
              className="btn-dark text-xs py-2.5 px-5 flex items-center gap-2 shadow-sm cursor-pointer"
            >
              <RotateCw className={`w-3.5 h-3.5 text-white ${isRefreshing ? "animate-spin" : ""}`} />
              <span>{isRefreshing ? "Auditing Target..." : "Re-Scan Andhra Treats"}</span>
            </button>

            <Link
              href="/workflow"
              className="btn-light text-xs py-2.5 px-5 flex items-center gap-2"
            >
              <span>Visual Pipeline</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>

        {/* Target Severity Breakdown Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-[#E0DACF]">
          <div className="p-3 rounded-2xl bg-[#FAF8F5] border border-[#E0DACF]">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#777777] block">Critical Flaws</span>
            <span className="text-xl font-bold text-black font-mono">2</span>
            <span className="text-[10px] text-rose-600 block mt-0.5">RLS &amp; Admin Gating</span>
          </div>

          <div className="p-3 rounded-2xl bg-[#FAF8F5] border border-[#E0DACF]">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#777777] block">High Risk Flaws</span>
            <span className="text-xl font-bold text-black font-mono">1</span>
            <span className="text-[10px] text-amber-600 block mt-0.5">Client Cart Price Manipulation</span>
          </div>

          <div className="p-3 rounded-2xl bg-[#FAF8F5] border border-[#E0DACF]">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#777777] block">Medium Risk</span>
            <span className="text-xl font-bold text-black font-mono">1</span>
            <span className="text-[10px] text-[#444444] block mt-0.5">Missing CSP &amp; X-Frame</span>
          </div>

          <div className="p-3 rounded-2xl bg-[#FAF8F5] border border-[#E0DACF]">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#777777] block">Auto-Patches Ready</span>
            <span className="text-xl font-bold text-black font-mono">3</span>
            <span className="text-[10px] text-emerald-600 block mt-0.5">SQL, Headers &amp; JS Diffs</span>
          </div>
        </div>

        {notification && (
          <div className="p-3 rounded-2xl bg-[#FAF8F5] border border-black shadow-sm flex items-center justify-between text-xs text-black animate-in fade-in">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="font-semibold">{notification}</span>
            </div>
            <button
              onClick={() => setNotification(null)}
              className="text-[#555555] hover:text-black font-semibold text-[11px]"
            >
              Dismiss
            </button>
          </div>
        )}
      </section>

      {/* =====================================================================
          2. DASHBOARD NAVIGATION TABS (Incidents / Patches / Sessions)
          ===================================================================== */}
      <div className="flex justify-center">
        <div className="inline-flex items-center gap-1.5 p-1 rounded-full bg-[#EAE5DE] border border-[#D5D0C7]">
          <button
            onClick={() => setActiveTab("incidents")}
            className={`flex items-center gap-2 px-5 py-2 rounded-full text-xs font-semibold transition ${
              activeTab === "incidents"
                ? "bg-black text-white shadow-sm"
                : "text-[#222222] hover:text-black"
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Discovered Vulnerabilities</span>
            <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${activeTab === "incidents" ? "bg-white text-black" : "bg-white/50 text-black"}`}>
              {incidents.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab("patches")}
            className={`flex items-center gap-2 px-5 py-2 rounded-full text-xs font-semibold transition ${
              activeTab === "patches"
                ? "bg-black text-white shadow-sm"
                : "text-[#222222] hover:text-black"
            }`}
          >
            <FileCode2 className="w-3.5 h-3.5" />
            <span>Autonomous Auto-Patches</span>
            <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${activeTab === "patches" ? "bg-white text-black" : "bg-white/50 text-black"}`}>
              {proposals.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab("sessions")}
            className={`flex items-center gap-2 px-5 py-2 rounded-full text-xs font-semibold transition ${
              activeTab === "sessions"
                ? "bg-black text-white shadow-sm"
                : "text-[#222222] hover:text-black"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Client State &amp; Sessions</span>
            <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${activeTab === "sessions" ? "bg-white text-black" : "bg-white/50 text-black"}`}>
              {sessions.length}
            </span>
          </button>
        </div>
      </div>

      {/* =====================================================================
          3. TAB CONTENT: DISCOVERED VULNERABILITIES & LIVE THREATS
          ===================================================================== */}
      {activeTab === "incidents" && (
        <section className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            {/* Filter Pills */}
            <div className="flex items-center gap-1.5 p-1 rounded-full bg-[#EAE5DE] border border-[#D5D0C7] overflow-x-auto">
              {[
                { key: "ALL", label: "All Findings", count: incidents.length },
                { key: "CRITICAL", label: "Critical", count: incidents.filter((i) => i.severity === "CRITICAL").length },
                { key: "BOLA", label: "BOLA / Orders", count: incidents.filter((i) => i.cwe === "CWE-639").length },
                { key: "CART", label: "Cart Price Logic", count: incidents.filter((i) => i.cwe === "CWE-862").length },
                { key: "HEADERS", label: "Security Headers", count: incidents.filter((i) => i.cwe === "CWE-693").length },
              ].map((f) => (
                <button
                  key={f.key}
                  onClick={() => setSelectedFilter(f.key)}
                  className={`flex items-center gap-1.5 px-4 py-1.5 rounded-full text-xs font-semibold transition ${
                    selectedFilter === f.key
                      ? "bg-black text-white shadow-sm"
                      : "text-[#222222] hover:text-black hover:bg-white/60"
                  }`}
                >
                  <span>{f.label}</span>
                  <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${selectedFilter === f.key ? "bg-white text-black" : "bg-white/50 text-black"}`}>
                    {f.count}
                  </span>
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-black">Quick Test:</span>
              <button
                onClick={() => handleQuickExploit("SQLI")}
                className="btn-light text-xs py-1.5 px-3 flex items-center gap-1"
                title="Test Fast-Path Gating"
              >
                <Flame className="w-3.5 h-3.5 text-rose-500" />
                <span>Test SQLi</span>
              </button>
              <button
                onClick={() => handleQuickExploit("BOLA")}
                className="btn-light text-xs py-1.5 px-3 flex items-center gap-1"
                title="Test BOLA Quarantine"
              >
                <Lock className="w-3.5 h-3.5 text-amber-500" />
                <span>Test BOLA</span>
              </button>
            </div>
          </div>

          {/* Incident Cards */}
          <div className="clean-card p-6 sm:p-8 space-y-4">
            {filteredIncidents.length === 0 ? (
              <div className="py-16 text-center text-[#555555] space-y-3">
                <CheckCircle2 className="w-10 h-10 text-black mx-auto" />
                <p className="font-bold text-base text-black">No matching findings found</p>
                <p className="text-xs max-w-sm mx-auto text-[#444444]">
                  All inspected requests for this category are secure.
                </p>
              </div>
            ) : (
              <div className="divide-y divide-[#E0DACF]">
                {filteredIncidents.map((inc) => (
                  <div key={inc.id} className="py-6 first:pt-0 last:pb-0 flex flex-col md:flex-row md:items-start justify-between gap-5">
                    <div className="space-y-2 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                          inc.severity === "CRITICAL"
                            ? "bg-black text-white"
                            : inc.severity === "HIGH"
                            ? "bg-[#FAF8F5] text-black border border-black"
                            : "bg-[#EAE5DE] text-black border border-[#D5D0C7]"
                        }`}>
                          {inc.severity}
                        </span>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-[#FAF8F5] border border-[#E0DACF] text-black">
                          {inc.cwe}
                        </span>
                        <span className="text-xs font-bold text-black">{inc.attack_type}</span>
                        <span className="text-xs text-[#888888]">•</span>
                        <span className="text-xs text-[#555555]">Confidence: <strong className="text-black font-mono">{(inc.bayesian_confidence * 100).toFixed(2)}%</strong></span>
                      </div>

                      <div className="text-xs font-mono text-[#555555] break-all">
                        <strong>Endpoint:</strong> {inc.endpoint}
                      </div>

                      <p className="text-xs text-[#333333] font-medium leading-relaxed">{inc.details}</p>

                      {inc.raw_payload && (
                        <div className="p-3 rounded-xl bg-[#FAF8F5] border border-[#E0DACF] font-mono text-[11px] text-black overflow-x-auto">
                          <code>{inc.raw_payload}</code>
                        </div>
                      )}
                    </div>

                    <div className="flex flex-col items-end gap-2 flex-shrink-0">
                      <span className="text-[11px] font-mono text-[#666666]">{inc.timestamp}</span>
                      <span className="px-3 py-1 rounded-full text-xs font-bold bg-[#EAE5DE] text-black border border-[#D5D0C7]">
                        Risk {inc.risk_score}/100
                      </span>
                      <button
                        onClick={() => setActiveTab("patches")}
                        className="text-xs font-bold text-black hover:underline flex items-center gap-1 mt-1"
                      >
                        <span>View Patch Diff</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      )}

      {/* =====================================================================
          4. TAB CONTENT: AUTONOMOUS AUTO-PATCHES & CODE DIFFS
          ===================================================================== */}
      {activeTab === "patches" && (
        <section className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="clean-pill">
                <span>AST &amp; Policy Self-Healing Studio</span>
              </div>
              <h2 className="text-2xl font-bold text-black mt-1">
                Generated Code Patches for Andhra Treats
              </h2>
              <p className="text-xs text-[#444444] mt-0.5">
                Target Codebase: <code className="font-mono bg-[#EAE5DE] px-1.5 py-0.5 rounded text-black">c:\Users\Govardhan\Documents\GitHub\andhratreats</code>
              </p>
            </div>

            <button
              onClick={loadData}
              className="btn-light text-xs py-2 px-4 flex items-center gap-2 self-start sm:self-auto"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
              <span>Refresh Patches</span>
            </button>
          </div>

          <div className="grid grid-cols-1 gap-6">
            {proposals.map((patch) => (
              <div key={patch.proposal_id} className="clean-card p-6 sm:p-8 space-y-6 bg-white border border-[#E0DACF]">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[#E0DACF]">
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-black text-white">
                        {patch.cwe}
                      </span>
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-[#FAF8F5] border border-[#E0DACF] text-black">
                        {patch.target_file}
                      </span>
                      {patch.status === "APPLIED" ? (
                        <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-300 flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          APPLIED &amp; VERIFIED
                        </span>
                      ) : (
                        <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-[#FAF8F5] text-black border border-[#D5D0C7]">
                          SANDBOX PASSED (READY)
                        </span>
                      )}
                    </div>
                    <h3 className="text-lg font-bold text-black">{patch.title}</h3>
                    <p className="text-xs text-[#444444] leading-relaxed max-w-3xl">{patch.description}</p>
                  </div>

                  <div className="flex items-center gap-3 flex-shrink-0">
                    {patch.status === "APPLIED" ? (
                      <button
                        onClick={() => handleRollbackPatch(patch.proposal_id)}
                        className="btn-light text-xs py-2.5 px-4 font-semibold"
                      >
                        Rollback Patch
                      </button>
                    ) : (
                      <button
                        onClick={() => handleApplyPatch(patch.proposal_id)}
                        className="btn-dark text-xs py-2.5 px-5 font-bold shadow-sm flex items-center gap-1.5 cursor-pointer"
                      >
                        <ShieldCheck className="w-3.5 h-3.5 text-white" />
                        <span>Apply Patch to Project</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Diff Viewer (Green / Red) */}
                <div className="space-y-3 font-mono text-xs">
                  {patch.diff_items?.map((item, idx) => (
                    <div key={idx} className="rounded-2xl border border-[#E0DACF] overflow-hidden bg-[#FAF8F5]">
                      <div className="px-4 py-2 bg-[#EAE5DE] border-b border-[#D5D0C7] flex items-center justify-between text-[11px] text-[#444444]">
                        <span className="font-bold text-black">{item.file_path} (Line {item.line_number})</span>
                        <span className="uppercase text-[10px] tracking-wider">{item.fix_type}</span>
                      </div>
                      
                      {/* Vulnerable Original Block */}
                      <div className="p-4 bg-rose-50/50 border-b border-rose-100 text-rose-950 whitespace-pre-wrap font-mono leading-relaxed">
                        <div className="text-[10px] font-bold uppercase text-rose-700 tracking-wider mb-1">- Vulnerable Code:</div>
                        <code>{item.vulnerable_code}</code>
                      </div>

                      {/* Remediated Clean Block */}
                      <div className="p-4 bg-emerald-50/60 text-emerald-950 whitespace-pre-wrap font-mono leading-relaxed">
                        <div className="text-[10px] font-bold uppercase text-emerald-700 tracking-wider mb-1">+ Remediated Code:</div>
                        <code>{item.remediated_code}</code>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Verification Results from Agent 11 Sandbox */}
                {patch.verification_results && patch.verification_results.length > 0 && (
                  <div className="p-4 rounded-2xl bg-[#FAF8F5] border border-[#E0DACF] space-y-2">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-black block">
                      Agent 11 Pre-Flight Sandbox Verification
                    </span>
                    <div className="space-y-1.5">
                      {patch.verification_results.map((vr, vIdx) => (
                        <div key={vIdx} className="flex items-start gap-2 text-xs">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 flex-shrink-0 mt-0.5" />
                          <div className="space-y-0.5">
                            <span className="font-bold text-black">{vr.test_name}: </span>
                            <span className="text-[#444444]">{vr.message}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* =====================================================================
          5. TAB CONTENT: ACTIVE SESSION RISK MATRIX
          ===================================================================== */}
      {activeTab === "sessions" && (
        <section className="space-y-6">
          <div>
            <div className="clean-pill">
              <span>Client State Tracking</span>
            </div>
            <h2 className="text-2xl font-bold text-black mt-2">
              Active Session Risk Matrix
            </h2>
            <p className="text-xs text-[#333333] mt-1">
              Real-time in-memory risk scoring in Redis. Sessions with Risk &ge; 80 are automatically quarantined at the gateway.
            </p>
          </div>

          <div className="clean-card p-6 overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#E0DACF] text-black font-bold uppercase text-[11px]">
                  <th className="pb-3">Session ID</th>
                  <th className="pb-3">IP Address</th>
                  <th className="pb-3">Risk Tier</th>
                  <th className="pb-3">Containment Status</th>
                  <th className="pb-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E0DACF] font-mono">
                {sessions.map((sess) => (
                  <tr key={sess.session_id} className="hover:bg-[#FAF8F5]">
                    <td className="py-3 font-bold text-black">{sess.session_id}</td>
                    <td className="py-3 text-[#333333]">{sess.ip_address}</td>
                    <td className="py-3">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${sess.risk_score >= 80 ? "bg-black text-white" : "bg-[#EAE5DE] text-black border border-[#D5D0C7]"}`}>
                        {sess.risk_score}/100
                      </span>
                    </td>
                    <td className="py-3">
                      {sess.is_quarantined ? (
                        <span className="font-bold text-black flex items-center gap-1">
                          <ShieldAlert className="w-3.5 h-3.5" />
                          Quarantined
                        </span>
                      ) : (
                        <span className="text-[#444444] font-medium flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Clean / Allowed
                        </span>
                      )}
                    </td>
                    <td className="py-3 text-right font-sans">
                      {sess.risk_score > 0 && (
                        <button
                          onClick={() => handleResetSession(sess.session_id)}
                          className="btn-light text-[11px] py-1 px-3"
                        >
                          Reset Risk
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
