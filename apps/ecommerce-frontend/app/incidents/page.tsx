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
  ArrowRight,
  ArrowLeft,
  Users,
} from "lucide-react";
import { api } from "../../lib/api";
import { SecurityIncident, SessionRiskProfile } from "../../lib/types";

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [sessions, setSessions] = useState<SessionRiskProfile[]>([]);
  const [selectedFilter, setSelectedFilter] = useState<string>("ALL");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  const loadData = async () => {
    setIsRefreshing(true);
    try {
      const [inc, sess] = await Promise.all([
        api.getIncidents(),
        api.getSessions(),
      ]);
      setIncidents(inc);
      setSessions(sess);
    } catch (err) {
      console.error("Failed to load incidents:", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

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
    return inc.attack_type.toUpperCase().includes(selectedFilter);
  });

  return (
    <div className="space-y-10">
      {/* Top Header Section */}
      <section className="text-center max-w-3xl mx-auto space-y-4 pt-4">
        <div className="flex justify-center">
          <div className="clean-pill">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Threat Intelligence &amp; Containment</span>
          </div>
        </div>

        <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-black leading-tight">
          Live threats caught &amp;{" "}
          <span className="italic-accent font-serif">contained</span>
        </h1>

        <p className="text-sm sm:text-base text-[#333333] leading-relaxed">
          Monitor intercepted payloads in real time. Every malicious request is dropped with an instant HTTP 403 response before reaching your core application.
        </p>

        {/* Quick Exploit Testing Bar */}
        <div className="pt-2 flex flex-wrap items-center justify-center gap-3">
          <span className="text-xs font-semibold text-black">Trigger Test Exploit:</span>
          
          <button
            onClick={() => handleQuickExploit("SQLI")}
            className="btn-light text-xs py-2 px-4"
          >
            <Flame className="w-3.5 h-3.5 text-rose-500 mr-1.5" />
            Test SQLi Block
          </button>

          <button
            onClick={() => handleQuickExploit("BOLA")}
            className="btn-light text-xs py-2 px-4"
          >
            <Lock className="w-3.5 h-3.5 text-amber-500 mr-1.5" />
            Test BOLA Block
          </button>

          <button
            onClick={() => handleQuickExploit("CART_TAMPER")}
            className="btn-light text-xs py-2 px-4"
          >
            <Zap className="w-3.5 h-3.5 text-blue-500 mr-1.5" />
            Test Cart Logic Block
          </button>
        </div>

        {notification && (
          <div className="max-w-md mx-auto p-3.5 rounded-2xl bg-white border border-[#E0DACF] shadow-md flex items-center justify-between text-xs text-black animate-in fade-in">
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

      {/* Main Threat Stream Container */}
      <section className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          {/* Category Filter Pills */}
          <div className="flex items-center gap-1.5 p-1 rounded-full bg-[#EAE5DE] border border-[#D5D0C7] overflow-x-auto">
            {[
              { key: "ALL", label: "All Threats", count: incidents.length },
              { key: "SQLI", label: "SQL Injection", count: incidents.filter((i) => i.attack_type.includes("SQL")).length },
              { key: "BOLA", label: "BOLA / IDOR", count: incidents.filter((i) => i.attack_type.includes("BOLA") || i.attack_type.includes("IDOR")).length },
              { key: "CART", label: "Cart Logic", count: incidents.filter((i) => i.attack_type.includes("CART") || i.attack_type.includes("PRICE")).length },
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

          <button
            onClick={loadData}
            className="btn-light text-xs py-2 px-4 flex items-center gap-2 self-start sm:self-auto"
          >
            <RotateCw className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
            <span>Refresh Incidents</span>
          </button>
        </div>

        {/* Incident List */}
        <div className="clean-card p-6 sm:p-8 space-y-4">
          {filteredIncidents.length === 0 ? (
            <div className="py-16 text-center text-[#555555] space-y-3">
              <CheckCircle2 className="w-10 h-10 text-black mx-auto" />
              <p className="font-bold text-base text-black">No matching incidents found</p>
              <p className="text-xs max-w-sm mx-auto text-[#444444]">
                All incoming requests matching this filter have passed inspection or zero attacks of this type have been recorded.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[#E0DACF]">
              {filteredIncidents.map((inc) => (
                <div key={inc.id} className="py-5 first:pt-0 last:pb-0 flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div className="space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-black text-white">
                        {inc.attack_type}
                      </span>
                      <span className="text-xs font-mono font-bold text-black">{inc.endpoint}</span>
                      <span className="text-xs text-[#888888]">•</span>
                      <span className="text-xs text-[#333333]">Risk Score: <strong className="text-black">{inc.risk_score}/100</strong></span>
                      <span className="text-xs text-[#888888]">•</span>
                      <span className="text-xs font-mono text-[#555555]">IP: {inc.ip_address}</span>
                    </div>
                    <p className="text-xs text-[#333333] font-medium leading-relaxed">{inc.details}</p>
                    {inc.raw_payload && (
                      <div className="p-2 rounded-xl bg-[#FAF8F5] border border-[#E0DACF] font-mono text-[11px] text-black overflow-x-auto max-w-2xl">
                        <code>{inc.raw_payload}</code>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-3 self-end md:self-center">
                    <span className="text-[11px] font-mono font-medium text-[#555555]">{inc.timestamp}</span>
                    <span className="px-3 py-1 rounded-full text-xs font-bold bg-[#EAE5DE] text-black border border-[#D5D0C7]">
                      Contained (HTTP 403)
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* Active Session Risk Matrix */}
      <section className="space-y-6 pt-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="clean-pill">
              <span>Client State Tracking</span>
            </div>
            <h2 className="text-2xl font-bold text-black mt-2">
              Active Session Risk Matrix
            </h2>
            <p className="text-xs text-[#333333] mt-1">
              Real-time in-memory risk scoring in Redis. Sessions with Risk &ge; 80 are automatically quarantined.
            </p>
          </div>
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
    </div>
  );
}
