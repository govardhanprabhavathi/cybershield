"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowUpRight } from "lucide-react";

export default function Header() {
  const pathname = usePathname();
  const isDashboard = pathname === "/" || pathname === "/dashboard";
  const isStore = pathname.startsWith("/store");

  return (
    <header className="sticky top-0 z-50 w-full bg-[#F5F2EB]/90 backdrop-blur-md border-b border-[#EBE6DE]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-18 py-4 flex items-center justify-between">
        {/* Brand Logo matching reference screenshot */}
        <div className="flex items-center gap-3">
          <Link href="/" className="flex items-center gap-2.5 group">
            <div className="w-8 h-8 rounded-full bg-black text-white flex items-center justify-center font-bold text-sm tracking-tighter group-hover:rotate-45 transition-transform duration-300">
              ✻
            </div>
            <span className="font-bold text-xl tracking-tight text-[#141414]">
              cybershield
            </span>
          </Link>
        </div>

        {/* Center Minimal Navigation Links */}
        <nav className="hidden md:flex items-center gap-1.5 p-1 rounded-full bg-[#EAE5DE]/70 border border-[#DDD7CD]">
          <Link
            href="/?tab=overview"
            className={`px-4 py-1.5 rounded-full text-xs font-medium transition-all ${
              isDashboard
                ? "bg-white text-[#141414] shadow-sm"
                : "text-[#6B665E] hover:text-[#141414]"
            }`}
          >
            Overview
          </Link>

          <Link
            href="/?tab=workflow"
            className="px-4 py-1.5 rounded-full text-xs font-medium text-[#6B665E] hover:text-[#141414] transition-all"
          >
            Visual Flow
          </Link>

          <Link
            href="/?tab=incidents"
            className="px-4 py-1.5 rounded-full text-xs font-medium text-[#6B665E] hover:text-[#141414] transition-all"
          >
            Live Incidents
          </Link>

          <Link
            href="/store"
            className={`px-4 py-1.5 rounded-full text-xs font-medium transition-all ${
              isStore
                ? "bg-white text-[#141414] shadow-sm"
                : "text-[#6B665E] hover:text-[#141414]"
            }`}
          >
            Storefront
          </Link>
        </nav>

        {/* Right Action Button matching "Book a call" pill in screenshot */}
        <div className="flex items-center gap-3">
          <Link
            href="/store"
            className="hidden sm:inline-flex items-center gap-1.5 text-xs font-medium text-[#6B665E] hover:text-[#141414] transition"
          >
            <span>Live Store</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>

          <Link
            href="/?tab=workflow"
            className="btn-dark"
          >
            View Flow
          </Link>
        </div>
      </div>
    </header>
  );
}
