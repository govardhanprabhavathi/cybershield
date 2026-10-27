"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, ShieldAlert, ShoppingBag, Activity, Zap, Cpu } from "lucide-react";

export default function Header() {
  const pathname = usePathname();
  const isDashboard = pathname === "/" || pathname === "/dashboard";
  const isStore = pathname.startsWith("/store");

  return (
    <header className="sticky top-0 z-50 w-full border-b border-white/[0.08] bg-black/40 backdrop-blur-2xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand & System Status */}
        <div className="flex items-center gap-4">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-400/30 flex items-center justify-center text-blue-400 shadow-[0_0_15px_rgba(59,130,246,0.25)] group-hover:scale-105 transition-transform duration-300">
              <Shield className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base tracking-wider bg-gradient-to-r from-white via-zinc-200 to-blue-300 bg-clip-text text-transparent">
                  CYBERSHIELD
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-blue-500/10 border border-blue-400/30 text-blue-300 shadow-[0_0_10px_rgba(59,130,246,0.2)]">
                  v2.0
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 tracking-tight flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Autonomous Multi-Agent Defense Engine
              </p>
            </div>
          </Link>

          {/* Quick Metrics Ticker (Desktop) */}
          <div className="hidden xl:flex items-center gap-2 pl-6 border-l border-white/[0.08]">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.02] border border-white/[0.05] text-[11px] text-zinc-300 font-mono">
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span>Gate: <strong className="text-emerald-400">1.4ms</strong></span>
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.02] border border-white/[0.05] text-[11px] text-zinc-300 font-mono">
              <Cpu className="w-3.5 h-3.5 text-blue-400" />
              <span>Bayesian: <strong className="text-blue-300">P &ge; 0.99</strong></span>
            </div>
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/[0.02] border border-white/[0.05] text-[11px] text-zinc-300 font-mono">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>LSPR: <strong className="text-cyan-300">100%</strong></span>
            </div>
          </div>
        </div>

        {/* Surface Dual-Navigation Switcher */}
        <nav className="flex items-center gap-1.5 p-1 rounded-2xl bg-white/[0.04] border border-white/[0.08] backdrop-blur-xl">
          <Link
            href="/"
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all duration-200 ${
              isDashboard
                ? "bg-blue-600 text-white shadow-[0_0_20px_rgba(37,99,235,0.4)] border border-blue-400/40"
                : "text-zinc-400 hover:text-white hover:bg-white/[0.05]"
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Command Center</span>
          </Link>

          <Link
            href="/store"
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all duration-200 ${
              isStore
                ? "bg-blue-600 text-white shadow-[0_0_20px_rgba(37,99,235,0.4)] border border-blue-400/40"
                : "text-zinc-400 hover:text-white hover:bg-white/[0.05]"
            }`}
          >
            <ShoppingBag className="w-3.5 h-3.5" />
            <span>Storefront Demo</span>
          </Link>
        </nav>
      </div>
    </header>
  );
}
