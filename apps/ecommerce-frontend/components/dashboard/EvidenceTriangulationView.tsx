"use client";

import React, { useState } from "react";
import {
  Layers,
  FileCode,
  Globe,
  Activity,
  Calculator,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { TriangulatedDossier, PillarEvidence } from "../../lib/types";

interface EvidenceTriangulationViewProps {
  dossiers: TriangulatedDossier[];
}

export default function EvidenceTriangulationView({ dossiers }: EvidenceTriangulationViewProps) {
  const [selectedDossier, setSelectedDossier] = useState<TriangulatedDossier>(dossiers[0] || null);

  if (!selectedDossier) {
    return <div className="p-8 text-center text-zinc-500">No triangulated dossiers available.</div>;
  }

  return (
    <div className="space-y-6">
      {/* Dossier Selection Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {dossiers.map((dos) => {
          const isSelected = selectedDossier.dossier_id === dos.dossier_id;
          return (
            <div
              key={dos.dossier_id}
              onClick={() => setSelectedDossier(dos)}
              className={`p-4 rounded-2xl cursor-pointer transition-all duration-200 border ${
                isSelected
                  ? "bg-blue-600/15 border-blue-400/50 shadow-[0_0_25px_rgba(59,130,246,0.2)]"
                  : "bg-white/[0.02] border-white/[0.06] hover:bg-white/[0.04] hover:border-white/[0.12]"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono font-bold text-blue-400 px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20">
                  {dos.cwe}
                </span>
                <span className="text-xs font-mono font-bold text-emerald-400">
                  {(dos.composite_confidence * 100).toFixed(2)}%
                </span>
              </div>
              <h4 className="text-xs font-bold text-white mt-2 line-clamp-1">{dos.title}</h4>
              <p className="text-[11px] font-mono text-zinc-400 mt-0.5 truncate">{dos.normalized_route}</p>
            </div>
          );
        })}
      </div>

      {/* Selected Dossier Header & Bayesian Calculator Panel */}
      <div className="p-6 glass-panel border-blue-500/30">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-white/[0.08]">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-400/30">
                {selectedDossier.dossier_id}
              </span>
              <h2 className="text-lg font-bold text-white">{selectedDossier.title}</h2>
            </div>
            <p className="text-xs text-zinc-400 mt-1 flex items-center gap-2">
              <span>Normalized Route: <strong className="font-mono text-zinc-300">{selectedDossier.normalized_route}</strong></span>
              <span>•</span>
              <span className="text-emerald-400 flex items-center gap-1 font-semibold">
                <ShieldCheck className="w-3.5 h-3.5" />
                Cross-Pillar Consensus Reached
              </span>
            </p>
          </div>

          <div className="flex items-center gap-4 bg-white/[0.03] p-3 rounded-xl border border-white/[0.06]">
            <div>
              <span className="text-[10px] uppercase font-mono text-zinc-400 block">Bayesian Posterior</span>
              <span className="text-2xl font-black text-emerald-400 font-mono">
                {(selectedDossier.composite_confidence * 100).toFixed(4)}%
              </span>
            </div>
            <div className="text-right pl-4 border-l border-white/[0.08]">
              <span className="text-[10px] uppercase font-mono text-zinc-400 block">Status</span>
              <span className="text-xs font-bold text-blue-300 font-mono">{selectedDossier.status}</span>
            </div>
          </div>
        </div>

        {/* Bayesian Formula Computation Breakdown */}
        <div className="mt-6 p-4 rounded-xl bg-black/40 border border-white/[0.06] space-y-3">
          <div className="flex items-center gap-2 text-xs font-mono text-zinc-300">
            <Calculator className="w-4 h-4 text-blue-400" />
            <span className="font-bold">Agent 9 Composite Probability Triangulation Formula</span>
          </div>

          <div className="text-xs font-mono text-zinc-400 bg-white/[0.02] p-3 rounded-lg border border-white/[0.04] overflow-x-auto">
            <code>
              P(Vulnerability | SAST &cap; DAST &cap; Runtime) = [ P₀ &times; L_sast &times; L_dast &times; L_runtime ] /
              Denominator = <span className="text-emerald-400 font-bold">{(selectedDossier.composite_confidence * 100).toFixed(4)}%</span>
            </code>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
            <div className="p-2 rounded bg-white/[0.02] border border-white/[0.04]">
              <span className="text-zinc-500 block text-[10px]">Prior P₀:</span>
              <span className="text-zinc-300 font-bold">{selectedDossier.bayesian_details.prior}</span>
            </div>
            <div className="p-2 rounded bg-white/[0.02] border border-white/[0.04]">
              <span className="text-zinc-500 block text-[10px]">SAST Likelihood:</span>
              <span className="text-blue-400 font-bold">{selectedDossier.bayesian_details.likelihoods.sast}</span>
            </div>
            <div className="p-2 rounded bg-white/[0.02] border border-white/[0.04]">
              <span className="text-zinc-500 block text-[10px]">DAST Likelihood:</span>
              <span className="text-cyan-400 font-bold">{selectedDossier.bayesian_details.likelihoods.dast}</span>
            </div>
            <div className="p-2 rounded bg-white/[0.02] border border-white/[0.04]">
              <span className="text-zinc-500 block text-[10px]">Runtime Likelihood:</span>
              <span className="text-amber-400 font-bold">{selectedDossier.bayesian_details.likelihoods.runtime}</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3 Pillars of Evidence Side-by-Side Comparison */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Pillar 1: SAST Evidence */}
        <div className="glass-panel p-5 space-y-3 relative">
          <div className="flex items-center justify-between pb-3 border-b border-white/[0.08]">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                <FileCode className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white">Pillar 1: Static Code (SAST)</h4>
                <p className="text-[10px] text-zinc-400">Agent 1 AST Analysis</p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold text-blue-400">
              {((selectedDossier.sast_evidence?.confidence || 0) * 100).toFixed(0)}%
            </span>
          </div>

          <div className="text-xs space-y-2">
            <p className="text-zinc-300 text-[11px]">{selectedDossier.sast_evidence?.evidence_summary}</p>
            {selectedDossier.sast_evidence?.code_snippet && (
              <div className="mt-2">
                <span className="text-[10px] uppercase font-mono text-zinc-500 block mb-1">AST Finding Code:</span>
                <pre className="p-2.5 rounded-lg bg-black/50 border border-white/[0.06] text-[11px] font-mono text-rose-300 overflow-x-auto">
                  {selectedDossier.sast_evidence.code_snippet}
                </pre>
              </div>
            )}
            <div className="pt-2 text-[10px] font-mono text-zinc-500 flex justify-between">
              <span>Rule: {selectedDossier.sast_evidence?.rule_id}</span>
              <span>Finding: {selectedDossier.sast_evidence?.finding_id}</span>
            </div>
          </div>
        </div>

        {/* Pillar 2: DAST Evidence */}
        <div className="glass-panel p-5 space-y-3 relative">
          <div className="flex items-center justify-between pb-3 border-b border-white/[0.08]">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Globe className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white">Pillar 2: Dynamic Exploit (DAST)</h4>
                <p className="text-[10px] text-zinc-400">Agent 3 Black-Box Validator</p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold text-cyan-400">
              {((selectedDossier.dast_evidence?.confidence || 0) * 100).toFixed(0)}%
            </span>
          </div>

          <div className="text-xs space-y-2">
            <p className="text-zinc-300 text-[11px]">{selectedDossier.dast_evidence?.evidence_summary}</p>
            {selectedDossier.dast_evidence?.http_sample && (
              <div className="mt-2">
                <span className="text-[10px] uppercase font-mono text-zinc-500 block mb-1">HTTP Replay Sample:</span>
                <pre className="p-2.5 rounded-lg bg-black/50 border border-white/[0.06] text-[11px] font-mono text-amber-300 overflow-x-auto whitespace-pre-wrap">
                  {selectedDossier.dast_evidence.http_sample}
                </pre>
              </div>
            )}
            <div className="pt-2 text-[10px] font-mono text-zinc-500 flex justify-between">
              <span>Rule: {selectedDossier.dast_evidence?.rule_id}</span>
              <span>Finding: {selectedDossier.dast_evidence?.finding_id}</span>
            </div>
          </div>
        </div>

        {/* Pillar 3: Runtime OTel Evidence */}
        <div className="glass-panel p-5 space-y-3 relative">
          <div className="flex items-center justify-between pb-3 border-b border-white/[0.08]">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
                <Activity className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-white">Pillar 3: Live Telemetry (Runtime)</h4>
                <p className="text-[10px] text-zinc-400">Agent 7 OpenTelemetry Sensor</p>
              </div>
            </div>
            <span className="text-xs font-mono font-bold text-amber-400">
              {((selectedDossier.runtime_evidence?.confidence || 0) * 100).toFixed(0)}%
            </span>
          </div>

          <div className="text-xs space-y-2">
            <p className="text-zinc-300 text-[11px]">{selectedDossier.runtime_evidence?.evidence_summary}</p>
            {selectedDossier.runtime_evidence?.http_sample && (
              <div className="mt-2">
                <span className="text-[10px] uppercase font-mono text-zinc-500 block mb-1">OTel Span Capture:</span>
                <pre className="p-2.5 rounded-lg bg-black/50 border border-white/[0.06] text-[11px] font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                  {selectedDossier.runtime_evidence.http_sample}
                </pre>
              </div>
            )}
            <div className="pt-2 text-[10px] font-mono text-zinc-500 flex justify-between">
              <span>Rule: {selectedDossier.runtime_evidence?.rule_id}</span>
              <span>Finding: {selectedDossier.runtime_evidence?.finding_id}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
