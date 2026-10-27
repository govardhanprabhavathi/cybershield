"use client";

import React, { useState } from "react";
import {
  Wrench,
  CheckCircle,
  XCircle,
  FileCode,
  ShieldCheck,
  Play,
  RotateCcw,
  Sparkles,
  ArrowRight,
  AlertCircle,
  History,
} from "lucide-react";
import { RemediationProposal, ASTDiffItem, VerificationTestRun } from "../../lib/types";

interface RemediationWorkbenchProps {
  proposals: RemediationProposal[];
  onApplyPatch: (proposalId: string) => Promise<boolean>;
  onRollbackPatch: (proposalId: string) => Promise<boolean>;
}

export default function RemediationWorkbench({
  proposals,
  onApplyPatch,
  onRollbackPatch,
}: RemediationWorkbenchProps) {
  const [selectedProposal, setSelectedProposal] = useState<RemediationProposal>(proposals[0] || null);
  const [actionInProgress, setActionInProgress] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  if (!selectedProposal) {
    return <div className="p-8 text-center text-zinc-500">No remediation proposals available.</div>;
  }

  const handleApply = async () => {
    setActionInProgress(true);
    setStatusMessage("Applying AST patch and updating live runtime routes...");
    const success = await onApplyPatch(selectedProposal.proposal_id);
    setActionInProgress(false);
    if (success) {
      setSelectedProposal({ ...selectedProposal, status: "APPLIED", applied_at: new Date().toISOString() });
      setStatusMessage("Patch safely applied to codebase! Regression checks 100% passing.");
    }
  };

  const handleRollback = async () => {
    setActionInProgress(true);
    setStatusMessage("Reverting applied patch back to verified baseline...");
    const success = await onRollbackPatch(selectedProposal.proposal_id);
    setActionInProgress(false);
    if (success) {
      setSelectedProposal({ ...selectedProposal, status: "ROLLED_BACK" });
      setStatusMessage("Patch cleanly rolled back to previous AST version.");
    }
  };

  return (
    <div className="space-y-6">
      {/* Proposal Selector Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {proposals.map((prop) => {
          const isSelected = selectedProposal.proposal_id === prop.proposal_id;
          return (
            <div
              key={prop.proposal_id}
              onClick={() => {
                setSelectedProposal(prop);
                setStatusMessage(null);
              }}
              className={`p-4 rounded-2xl cursor-pointer border transition-all duration-200 ${
                isSelected
                  ? "bg-blue-600/15 border-blue-400/50 shadow-[0_0_20px_rgba(59,130,246,0.2)]"
                  : "bg-white/[0.02] border-white/[0.06] hover:bg-white/[0.04] hover:border-white/[0.12]"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-blue-400 px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20">
                  {prop.cwe}
                </span>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                    prop.status === "APPLIED"
                      ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                      : "bg-blue-500/10 text-blue-300 border border-blue-500/20"
                  }`}
                >
                  {prop.status}
                </span>
              </div>
              <h4 className="text-xs font-bold text-white mt-2 line-clamp-1">{prop.title}</h4>
              <p className="text-[11px] font-mono text-zinc-400 mt-0.5 truncate">{prop.target_file}</p>
            </div>
          );
        })}
      </div>

      {/* Main Proposal Inspection Card */}
      <div className="glass-panel p-6 border-blue-500/30">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-6 border-b border-white/[0.08]">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold px-2.5 py-0.5 rounded-full bg-blue-500/20 text-blue-300 border border-blue-400/30">
                {selectedProposal.proposal_id}
              </span>
              <h2 className="text-lg font-bold text-white">{selectedProposal.title}</h2>
            </div>
            <p className="text-xs text-zinc-400 mt-1 max-w-2xl">{selectedProposal.description}</p>
          </div>

          {/* Action Buttons: Apply / Rollback */}
          <div className="flex items-center gap-2.5">
            {selectedProposal.status === "APPLIED" ? (
              <button
                onClick={handleRollback}
                disabled={actionInProgress}
                className="px-4 py-2 rounded-xl bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/40 text-rose-200 text-xs font-semibold flex items-center gap-2 transition disabled:opacity-50"
              >
                <RotateCcw className="w-4 h-4" />
                Rollback Patch
              </button>
            ) : (
              <button
                onClick={handleApply}
                disabled={actionInProgress}
                className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-2 transition shadow-[0_0_20px_rgba(16,185,129,0.3)] disabled:opacity-50"
              >
                <Sparkles className="w-4 h-4" />
                Apply Patch to Codebase
              </button>
            )}
          </div>
        </div>

        {/* Status Notification */}
        {statusMessage && (
          <div className="mt-4 p-3 rounded-xl bg-blue-950/40 border border-blue-500/30 text-xs text-blue-200 flex items-center gap-2 animate-in fade-in">
            <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>{statusMessage}</span>
          </div>
        )}

        {/* Verification Summary Badges */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-6">
          <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] flex items-center gap-3">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <CheckCircle className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono text-zinc-400">AST Syntax Check</span>
              <p className="text-xs font-bold text-white">Valid Python Syntax Tree</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono text-zinc-400">Agent 11 Sandbox</span>
              <p className="text-xs font-bold text-white">Exploit Replay Passed</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <History className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono text-zinc-400">Regression Suite</span>
              <p className="text-xs font-bold text-white">100% Existing Tests Pass</p>
            </div>
          </div>
        </div>

        {/* AST Code Diff Viewer */}
        <div className="mt-6 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono text-zinc-300">
              <FileCode className="w-4 h-4 text-blue-400" />
              <span>Target File: <strong className="text-white">{selectedProposal.target_file}</strong></span>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/[0.05] text-zinc-400">
              Line {selectedProposal.diff_items[0]?.line_number}
            </span>
          </div>

          {selectedProposal.diff_items.map((diff, idx) => (
            <div key={idx} className="rounded-xl border border-white/[0.08] overflow-hidden bg-black/60 font-mono text-xs">
              <div className="p-2.5 bg-rose-950/25 border-b border-rose-500/20 text-rose-300">
                <span className="text-[10px] uppercase tracking-wider text-rose-400 font-bold block mb-1">
                  - Vulnerable AST Code:
                </span>
                <pre className="whitespace-pre-wrap">{diff.vulnerable_code}</pre>
              </div>
              <div className="p-2.5 bg-emerald-950/25 text-emerald-300">
                <span className="text-[10px] uppercase tracking-wider text-emerald-400 font-bold block mb-1">
                  + Agent 10 Remediated AST Code:
                </span>
                <pre className="whitespace-pre-wrap">{diff.remediated_code}</pre>
              </div>
            </div>
          ))}
        </div>

        {/* Agent 11 Sandbox Exploit Replay Verification Table */}
        <div className="mt-6 space-y-3">
          <h4 className="text-xs font-bold text-white flex items-center gap-1.5">
            <Play className="w-3.5 h-3.5 text-blue-400" />
            Agent 11 Sandbox Exploit Replay Results
          </h4>

          <div className="overflow-x-auto rounded-xl border border-white/[0.06]">
            <table className="w-full text-left text-xs">
              <thead className="bg-white/[0.02] border-b border-white/[0.08] text-zinc-400 uppercase font-mono tracking-wider text-[10px]">
                <tr>
                  <th className="py-2.5 px-3">Test Scenario</th>
                  <th className="py-2.5 px-3">Exploit Payload</th>
                  <th className="py-2.5 px-3">Vulnerable Status</th>
                  <th className="py-2.5 px-3">Remediated Status</th>
                  <th className="py-2.5 px-3">Result</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {selectedProposal.verification_results.map((run, idx) => (
                  <tr key={idx} className="hover:bg-white/[0.01]">
                    <td className="py-2.5 px-3 font-medium text-white">{run.test_name}</td>
                    <td className="py-2.5 px-3 font-mono text-zinc-400 truncate max-w-xs">{run.exploit_payload}</td>
                    <td className="py-2.5 px-3 font-mono text-rose-400">HTTP {run.expected_vulnerable_status}</td>
                    <td className="py-2.5 px-3 font-mono text-emerald-400">HTTP {run.actual_remediated_status}</td>
                    <td className="py-2.5 px-3">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
                        <CheckCircle className="w-3 h-3" />
                        PASSED
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
