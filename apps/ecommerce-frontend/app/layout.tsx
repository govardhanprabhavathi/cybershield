import type { Metadata } from "next";
import "./globals.css";
import Header from "../components/Header";

export const metadata: Metadata = {
  title: "CyberShield — Autonomous Security Engine",
  description:
    "Intelligent multi-agent defense system for e-commerce applications. Real-time sub-2ms fast-path containment with zero false positives.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[#F5F2EB] text-[#141414] antialiased selection:bg-black selection:text-white">
        {/* Minimalist Top Navigation Header */}
        <Header />

        {/* Main Content Workspace */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 pb-24">
          {children}
        </main>

        {/* Minimalist Clean Footer */}
        <footer className="border-t border-[#EBE6DE] bg-[#F5F2EB] py-8 mt-16">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-[#7A756D]">
            <div className="flex items-center gap-2.5">
              <span className="font-semibold text-[#141414]">cybershield</span>
              <span>•</span>
              <span>12 Autonomous Agents</span>
              <span>•</span>
              <span className="text-emerald-700 font-medium">0% False Positives</span>
            </div>
            <div className="flex items-center gap-4 text-[#8C877E]">
              <span>Sub-2ms Deterministic Gate</span>
              <span>•</span>
              <span>Bayesian Multi-Plane Verification</span>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
