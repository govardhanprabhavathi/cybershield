import type { Metadata } from "next";
import "./globals.css";
import Header from "../components/Header";

export const metadata: Metadata = {
  title: "CyberShield — Autonomous Multi-Agent Security Command Center",
  description:
    "Multi-Agent AI System for E-Commerce Application Security Analysis, Runtime Threat Detection, Graduated Containment, and Automated Remediation.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#050505] text-zinc-100 selection:bg-blue-500/30 selection:text-white">
        {/* Animated Background Flow from luxury-gradient-ui */}
        <div className="glow-container" aria-hidden="true">
          <div className="glow-orb orb-1" />
          <div className="glow-orb orb-2" />
          <div className="glow-orb orb-3" />
          <div className="glow-orb orb-4" />
        </div>

        {/* Global Navigation Header */}
        <Header />

        {/* Foreground Content */}
        <main className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 pb-20">
          {children}
        </main>

        {/* Bottom Technical Bar */}
        <footer className="relative z-10 border-t border-white/[0.06] bg-black/50 backdrop-blur-xl py-6 mt-12">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-4 text-xs text-zinc-500">
            <div className="flex items-center gap-3">
              <span className="font-semibold text-zinc-400">CyberShield Multi-Agent Framework</span>
              <span>•</span>
              <span>11 Autonomous Specialized Agents</span>
              <span>•</span>
              <span className="text-emerald-400 font-mono">0% False Positives (FPR)</span>
            </div>
            <div className="flex items-center gap-4 text-zinc-400">
              <span>FastAPI + Redis + OpenTelemetry</span>
              <span>•</span>
              <span>Next.js 15 App Router</span>
              <span>•</span>
              <span>Bayesian Triangulation Engine (Agent 9)</span>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
