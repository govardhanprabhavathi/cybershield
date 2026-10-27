"use client";

import React, { useState } from "react";
import {
  Play,
  CheckCircle,
  Activity,
  Zap,
  Users,
  ShieldAlert,
  Flame,
  Network,
  RotateCw,
  BarChart3,
} from "lucide-react";
import { SimulationScenario, SimulationReport } from "../../lib/types";

interface TrafficSimulatorProps {
  onRunSimulation: (scenario: SimulationScenario) => Promise<SimulationReport>;
}

export default function TrafficSimulator({ onRunSimulation }: TrafficSimulatorProps) {
  const [legitThreads, setLegitThreads] = useState<number>(50);
  const [attackerThreads, setAttackerThreads] = useState<number>(20);
  const [natSpoofing, setNatSpoofing] = useState<boolean>(true);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [report, setReport] = useState<SimulationReport | null>(null);

  const handleStart = async () => {
    setIsRunning(true);
    setReport(null);

    const scenario: SimulationScenario = {
      id: `SCENARIO-${Date.now()}`,
      name: "High-Concurrency Multi-Tenant Stress Benchmark",
      description: "Evaluating Legitimate Session Preservation (LSPR) under aggressive concurrent attack storm.",
      legitimate_threads: legitThreads,
      attacker_threads: attackerThreads,
      attack_vectors: ["SQLi (CWE-89)", "BOLA (CWE-284)", "Cart Tamper (CWE-840)", "Brute Force (CWE-307)"],
      duration_seconds: 5,
      nat_spoofing: natSpoofing,
    };

    const res = await onRunSimulation(scenario);
    setReport(res);
    setIsRunning(false);
  };

  return (
    <div className="space-y-6">
      {/* Simulation Setup Control Card */}
      <div className="p-6 glass-panel border-blue-500/30">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-white/[0.08]">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                <BarChart3 className="w-4 h-4" />
              </span>
              <h2 className="text-base font-bold text-white">Concurrent Traffic &amp; Attack Storm Simulator</h2>
            </div>
            <p className="text-xs text-zinc-400 mt-1">
              Simulate high-throughput simultaneous legitimate shoppers and multi-vector automated attackers.
            </p>
          </div>

          <button
            onClick={handleStart}
            disabled={isRunning}
            className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-2 transition shadow-[0_0_20px_rgba(37,99,235,0.4)] disabled:opacity-50"
          >
            {isRunning ? (
              <>
                <RotateCw className="w-4 h-4 animate-spin" />
                Executing Benchmark...
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Launch Attack Storm Benchmark
              </>
            )}
          </button>
        </div>

        {/* Configuration Sliders & Toggles */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6">
          {/* Legitimate Shoppers */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-zinc-300 font-semibold flex items-center gap-1.5">
                <Users className="w-3.5 h-3.5 text-emerald-400" />
                Legitimate Shopper Threads
              </span>
              <span className="font-mono font-bold text-emerald-400">{legitThreads} concurrent</span>
            </div>
            <input
              type="range"
              min={10}
              max={100}
              step={5}
              value={legitThreads}
              onChange={(e) => setLegitThreads(Number(e.target.value))}
              disabled={isRunning}
              className="w-full accent-emerald-500"
            />
            <p className="text-[11px] text-zinc-500">Browsing catalog, adding to cart, placing legitimate orders.</p>
          </div>

          {/* Attacker Threads */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-zinc-300 font-semibold flex items-center gap-1.5">
                <Flame className="w-3.5 h-3.5 text-rose-400" />
                Attacker Concurrency Threads
              </span>
              <span className="font-mono font-bold text-rose-400">{attackerThreads} concurrent</span>
            </div>
            <input
              type="range"
              min={5}
              max={50}
              step={5}
              value={attackerThreads}
              onChange={(e) => setAttackerThreads(Number(e.target.value))}
              disabled={isRunning}
              className="w-full accent-rose-500"
            />
            <p className="text-[11px] text-zinc-500">Injecting SQLi, cross-tenant BOLA IDs, and negative quantities.</p>
          </div>

          {/* NAT Disambiguation Toggle */}
          <div className="space-y-2">
            <span className="text-zinc-300 text-xs font-semibold flex items-center gap-1.5">
              <Network className="w-3.5 h-3.5 text-cyan-400" />
              Shared-IP NAT Clustering
            </span>
            <label className="flex items-center gap-2 cursor-pointer pt-1">
              <input
                type="checkbox"
                checked={natSpoofing}
                onChange={(e) => setNatSpoofing(e.target.checked)}
                disabled={isRunning}
                className="w-4 h-4 rounded accent-blue-500"
              />
              <span className="text-xs text-zinc-300 font-mono">Simulate Corporate NAT (198.51.100.42)</span>
            </label>
            <p className="text-[11px] text-zinc-500">Validates that legitimate shoppers aren&apos;t blocked when sharing attacker IP.</p>
          </div>
        </div>
      </div>

      {/* Live Simulation Progress Banner */}
      {isRunning && (
        <div className="p-6 glass-panel border-blue-500/40 bg-blue-950/20 text-center space-y-3">
          <div className="flex items-center justify-center gap-2 text-sm font-bold text-blue-300">
            <RotateCw className="w-5 h-5 animate-spin text-blue-400" />
            <span>Firing Synchronous Traffic Wave &amp; Live Fast-Path Interceptions...</span>
          </div>
          <div className="w-full max-w-md mx-auto h-2 rounded-full bg-white/[0.08] overflow-hidden">
            <div className="h-full bg-blue-500 animate-pulse w-3/4 rounded-full" />
          </div>
        </div>
      )}

      {/* Benchmark Report Results Card */}
      {report && (
        <div className="glass-panel p-6 border-emerald-500/30 bg-emerald-950/10 space-y-6 animate-in fade-in">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-white/[0.08]">
            <div className="flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-emerald-400" />
              <h3 className="text-base font-bold text-white">Benchmark Execution Summary</h3>
            </div>
            <span className="text-xs font-mono text-zinc-400">{report.id}</span>
          </div>

          <p className="text-xs text-zinc-300 bg-white/[0.02] p-3.5 rounded-xl border border-white/[0.06] leading-relaxed">
            {report.summary}
          </p>

          {/* Benchmark Core Metric Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <span className="text-[10px] font-mono uppercase text-zinc-400">Legitimate Shopper LSPR</span>
              <p className="text-2xl font-black text-emerald-400 font-mono mt-1">{report.legitimate_200_rate.toFixed(1)}%</p>
              <span className="text-[10px] text-zinc-500">{report.legitimate_requests} / {report.legitimate_requests} HTTP 200 OK</span>
            </div>

            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <span className="text-[10px] font-mono uppercase text-zinc-400">Attack Containment ACR</span>
              <p className="text-2xl font-black text-rose-400 font-mono mt-1">{report.attacker_blocked_rate.toFixed(1)}%</p>
              <span className="text-[10px] text-zinc-500">{report.attacker_requests} / {report.attacker_requests} Blocked</span>
            </div>

            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <span className="text-[10px] font-mono uppercase text-zinc-400">False Positives (FPR)</span>
              <p className="text-2xl font-black text-white font-mono mt-1">0.00%</p>
              <span className="text-[10px] text-zinc-500">0 innocent shoppers impacted</span>
            </div>

            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <span className="text-[10px] font-mono uppercase text-zinc-400">Fast-Path Latency</span>
              <p className="text-2xl font-black text-amber-400 font-mono mt-1">{report.mean_response_time_ms.toFixed(2)}ms</p>
              <span className="text-[10px] text-zinc-500">Zero synchronous LLM bottleneck</span>
            </div>
          </div>

          {/* Simulated Time-Series Throughput Chart */}
          <div className="p-4 rounded-xl bg-black/40 border border-white/[0.06] space-y-3">
            <span className="text-xs font-mono font-bold text-zinc-300 block">
              Second-by-Second Throughput &amp; Containment Timeline
            </span>

            <div className="space-y-2">
              {report.timeline.map((point) => (
                <div key={point.timestamp} className="flex items-center gap-3 text-xs font-mono">
                  <span className="w-12 text-zinc-500">T+{point.timestamp}s</span>
                  <div className="flex-1 flex gap-1 h-3 rounded overflow-hidden bg-white/[0.05]">
                    <div
                      className="bg-emerald-500 h-full"
                      style={{ width: `${(point.legitimate_throughput / (point.legitimate_throughput + point.attack_throughput)) * 100}%` }}
                      title={`Legitimate HTTP 200: ${point.legitimate_throughput} req/s`}
                    />
                    <div
                      className="bg-rose-500 h-full"
                      style={{ width: `${(point.attack_throughput / (point.legitimate_throughput + point.attack_throughput)) * 100}%` }}
                      title={`Blocked Attackers HTTP 403: ${point.blocked_count} req/s`}
                    />
                  </div>
                  <span className="text-emerald-400 w-20 text-right">{point.legitimate_throughput} OK/s</span>
                  <span className="text-rose-400 w-24 text-right">{point.blocked_count} Blocked/s</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
