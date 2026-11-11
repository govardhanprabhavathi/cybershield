"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield } from "lucide-react";

export default function Header() {
  const pathname = usePathname();

  const isOverview = pathname === "/";
  const isWorkflow = pathname === "/workflow";
  const isIncidents = pathname === "/incidents";

  return (
    <header className="sticky top-0 z-50 w-full bg-[#F5F2EB]/95 backdrop-blur-md border-b border-[#E0DACF]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-18 py-4 flex items-center justify-between">
        {/* Brand Logo */}
        <div className="flex items-center gap-3">
          <Link href="/" className="flex items-center gap-2.5 group">
            <div className="w-8 h-8 rounded-full bg-black text-white flex items-center justify-center transition-transform duration-300 group-hover:scale-105 shadow-sm">
              <Shield className="w-4 h-4 text-white fill-white" />
            </div>
            <span className="font-bold text-xl tracking-tight text-black">
              cybershield
            </span>
          </Link>
        </div>

        {/* Center Minimal Navigation Links */}
        <nav className="flex items-center gap-1.5 p-1 rounded-full bg-[#EAE5DE] border border-[#D5D0C7]">
          <Link
            href="/"
            className={`px-4 py-1.5 rounded-full text-xs font-semibold transition-all ${
              isOverview
                ? "bg-black text-white shadow-sm"
                : "text-[#222222] hover:text-black hover:bg-white/60"
            }`}
          >
            Overview
          </Link>

          <Link
            href="/workflow"
            className={`px-4 py-1.5 rounded-full text-xs font-semibold transition-all ${
              isWorkflow
                ? "bg-black text-white shadow-sm"
                : "text-[#222222] hover:text-black hover:bg-white/60"
            }`}
          >
            Visual Flow
          </Link>

          <Link
            href="/incidents"
            className={`px-4 py-1.5 rounded-full text-xs font-semibold transition-all ${
              isIncidents
                ? "bg-black text-white shadow-sm"
                : "text-[#222222] hover:text-black hover:bg-white/60"
            }`}
          >
            Live Incidents
          </Link>
        </nav>

        {/* Right Action Buttons */}
        <div className="hidden sm:flex items-center gap-3">
          <Link
            href="/workflow"
            className="btn-dark"
          >
            View Flow
          </Link>
        </div>
      </div>
    </header>
  );
}
