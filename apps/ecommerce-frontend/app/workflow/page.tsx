"use client";

import React from "react";
import Link from "next/link";
import { ArrowLeft, ArrowRight, ShieldCheck, Zap, Layers, Wrench } from "lucide-react";
import InteractiveWorkflowCanvas from "../../components/dashboard/InteractiveWorkflowCanvas";

export default function WorkflowPage() {
  return (
    <div className="space-y-10">
      {/* Top Header Section */}
      <section className="text-center max-w-3xl mx-auto space-y-4 pt-4">
        <div className="flex justify-center">
          <div className="clean-pill">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Multi-Agent System Architecture</span>
          </div>
        </div>

        <h1 className="text-4xl sm:text-5xl font-bold tracking-tight text-black leading-tight">
          Visual flow from request to{" "}
          <span className="italic-accent font-serif">immunity</span>
        </h1>

        <p className="text-sm sm:text-base text-[#333333] leading-relaxed">
          Explore the dual-plane defense lifecycle. Client requests pass through our sub-2ms Fast-Path Gate, stream into Redis, and are verified by 12 specialized autonomous agents.
        </p>

        <div className="flex items-center justify-center gap-4 pt-2">
          <Link href="/" className="btn-light text-xs py-2 px-4 flex items-center gap-1.5">
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Overview</span>
          </Link>
          <Link href="/incidents" className="btn-dark text-xs py-2 px-5 flex items-center gap-1.5">
            <span>View Live Incidents</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </section>

      {/* Main Interactive Workflow Canvas */}
      <section>
        <InteractiveWorkflowCanvas />
      </section>

      {/* Architecture Explanatory Cards (Monochrome Minimalist) */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-6">
        <div className="clean-card p-8 space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-[#EAE5DE] flex items-center justify-center text-black font-bold">
            01
          </div>
          <h3 className="text-lg font-bold text-black">Fast-Path Synchronous Gate</h3>
          <p className="text-xs text-[#333333] leading-relaxed">
            Operating at &le; 1.4ms latency directly in HTTP middleware. Checks session risk in Redis hashes and instantly drops confirmed attack payloads (HTTP 403).
          </p>
        </div>

        <div className="clean-card p-8 space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-[#EAE5DE] flex items-center justify-center text-black font-bold">
            02
          </div>
          <h3 className="text-lg font-bold text-black">Asynchronous Multi-Agent Mesh</h3>
          <p className="text-xs text-[#333333] leading-relaxed">
            Redis Streams ingest telemetry without blocking client traffic. Agents 1-9 triangulate static AST findings, dynamic API probes, and live runtime events.
          </p>
        </div>

        <div className="clean-card p-8 space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-[#EAE5DE] flex items-center justify-center text-black font-bold">
            03
          </div>
          <h3 className="text-lg font-bold text-black">Automated AST Auto-Patching &amp; Orchestration</h3>
          <p className="text-xs text-[#333333] leading-relaxed">
            Agents 10, 11 &amp; 12 generate syntactically verified code diffs in a sandboxed runtime and orchestrate canary rollouts, permanently eliminating vulnerabilities with zero human intervention.
          </p>
        </div>
      </section>
    </div>
  );
}
