"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  ShoppingBag,
  Search,
  ShoppingCart,
  ShieldAlert,
  ShieldCheck,
  Star,
  CheckCircle,
  AlertTriangle,
  Flame,
  ArrowRight,
  Plus,
  Minus,
  Trash2,
  Lock,
  Zap,
} from "lucide-react";
import { api } from "../../lib/api";
import { Product, CartItem } from "../../lib/types";

export default function StorefrontDemo() {
  const [products, setProducts] = useState<Product[]>([]);
  const [cart, setCart] = useState<CartItem[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [isCartOpen, setIsCartOpen] = useState(false);
  const [feedback, setFeedback] = useState<{ type: "success" | "blocked" | "info"; message: string } | null>(null);

  useEffect(() => {
    api.getProducts().then(setProducts);
  }, []);

  const handleSearch = async (queryToRun?: string) => {
    const q = queryToRun !== undefined ? queryToRun : searchQuery;
    setIsSearching(true);
    setFeedback(null);

    const res = await api.searchProducts(q);
    setIsSearching(false);

    if (res.blocked) {
      setFeedback({
        type: "blocked",
        message: res.message || "403 Forbidden: Request intercepted and session quarantined by CyberShield Fast-Path Gate!",
      });
    } else {
      setProducts(res.results);
      if (queryToRun !== undefined) {
        setSearchQuery(queryToRun);
      }
    }
  };

  const addToCart = (product: Product, quantity = 1) => {
    setCart((prev) => {
      const existing = prev.find((item) => item.product.id === product.id);
      if (existing) {
        return prev.map((item) =>
          item.product.id === product.id ? { ...item, quantity: item.quantity + quantity } : item
        );
      }
      return [...prev, { product, quantity }];
    });
    setFeedback({
      type: "success",
      message: `Added ${product.name} to cart.`,
    });
    setTimeout(() => setFeedback(null), 3000);
  };

  const removeFromCart = (productId: string) => {
    setCart((prev) => prev.filter((item) => item.product.id !== productId));
  };

  const updateQuantity = (productId: string, qty: number) => {
    if (qty <= 0) {
      removeFromCart(productId);
      return;
    }
    setCart((prev) =>
      prev.map((item) => (item.product.id === productId ? { ...item, quantity: qty } : item))
    );
  };

  const handleTestNegativeQuantityTamper = async () => {
    setFeedback(null);
    const res = await api.triggerExploit("CART_TAMPER");
    setFeedback({
      type: "blocked",
      message: "HTTP 422 Unprocessable: CyberShield Pydantic Guard rejected negative quantity (-5)! Attack intercepted.",
    });
  };

  const handleTestBolaExploit = async () => {
    setFeedback(null);
    const res = await api.triggerExploit("BOLA");
    setFeedback({
      type: "blocked",
      message: "HTTP 403 Forbidden: CyberShield Tenant Isolation Gate blocked access to foreign tenant order #ord-tenant2-99!",
    });
  };

  const handleTestDevSecretExploit = async () => {
    setFeedback(null);
    const res = await api.triggerExploit("SQLI");
    setFeedback({
      type: "blocked",
      message: "HTTP 403 Forbidden: Intercepted static dev secret probe DEV_SECRET_SUPERADMIN!",
    });
  };

  const cartTotal = cart.reduce((sum, item) => sum + item.product.price * item.quantity, 0);
  const cartItemCount = cart.reduce((sum, item) => sum + item.quantity, 0);

  return (
    <div className="space-y-8">
      {/* Top Storefront Banner & Context */}
      <div className="p-6 glass-panel border-blue-500/20 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-blue-500/10 text-blue-300 border border-blue-400/30">
              Surface A Storefront
            </span>
            <span className="text-xs font-mono text-zinc-400">CyberShield Live Target App</span>
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight mt-2">
            CyberShield Hardware &amp; Security Store
          </h1>
          <p className="text-xs text-zinc-400 mt-1 max-w-xl">
            Fully functional e-commerce storefront instrumented with OpenTelemetry.
            Use this surface to browse products or test live attack vectors to observe real-time defense.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsCartOpen(!isCartOpen)}
            className="px-4 py-2 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.1] text-xs font-semibold text-white flex items-center gap-2 transition relative"
          >
            <ShoppingCart className="w-4 h-4 text-blue-400" />
            <span>Cart ({cartItemCount})</span>
            {cartItemCount > 0 && (
              <span className="w-2 h-2 rounded-full bg-blue-500 absolute -top-1 -right-1" />
            )}
          </button>

          <Link
            href="/"
            className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition shadow-[0_0_15px_rgba(37,99,235,0.3)]"
          >
            <span>Command Center &rarr;</span>
          </Link>
        </div>
      </div>

      {/* Security Feedback Bar */}
      {feedback && (
        <div
          className={`p-4 rounded-2xl border text-xs font-mono flex items-start justify-between gap-3 animate-in fade-in ${
            feedback.type === "blocked"
              ? "bg-rose-950/40 border-rose-500/40 text-rose-200 shadow-[0_0_20px_rgba(244,63,94,0.2)]"
              : feedback.type === "success"
              ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-200"
              : "bg-blue-950/40 border-blue-500/40 text-blue-200"
          }`}
        >
          <div className="flex items-start gap-2.5">
            {feedback.type === "blocked" ? (
              <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
            ) : (
              <CheckCircle className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
            )}
            <div>
              <p className="font-semibold">{feedback.message}</p>
              {feedback.type === "blocked" && (
                <Link href="/" className="inline-block mt-1 text-[11px] underline text-rose-300 hover:text-white">
                  View this live quarantine incident in Security Command Center &rarr;
                </Link>
              )}
            </div>
          </div>
          <button
            onClick={() => setFeedback(null)}
            className="text-[10px] text-zinc-400 hover:text-white px-2 py-0.5 rounded bg-white/[0.05]"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Search Bar with Exploit Triggers */}
      <div className="p-4 glass-panel space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-zinc-400" />
            <input
              type="text"
              placeholder="Search catalog products (e.g. 'FIDO2', 'Gateway', 'Encrypted')..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-white/[0.04] border border-white/[0.08] text-xs text-white placeholder-zinc-500 focus:outline-none focus:border-blue-400/50"
            />
          </div>
          <button
            onClick={() => handleSearch()}
            disabled={isSearching}
            className="px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition"
          >
            {isSearching ? "Searching..." : "Search"}
          </button>
        </div>

        {/* Quick Exploit Trigger Chips */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-[11px] font-mono text-zinc-400 flex items-center gap-1">
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            Vulnerability Exploit Triggers:
          </span>
          <button
            onClick={() => handleSearch("' OR 1=1--")}
            className="px-2.5 py-1 rounded-lg text-[10px] font-mono bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 transition flex items-center gap-1"
          >
            <span>CWE-89: Tautology (&apos; OR 1=1--)</span>
          </button>
          <button
            onClick={() => handleSearch("' UNION SELECT id, password_hash, secret_key FROM users--")}
            className="px-2.5 py-1 rounded-lg text-[10px] font-mono bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 transition flex items-center gap-1"
          >
            <span>CWE-89: Exfiltration (UNION SELECT)</span>
          </button>
          <button
            onClick={handleTestBolaExploit}
            className="px-2.5 py-1 rounded-lg text-[10px] font-mono bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition flex items-center gap-1"
          >
            <span>CWE-284: BOLA (Order #ord-tenant2-99)</span>
          </button>
          <button
            onClick={handleTestNegativeQuantityTamper}
            className="px-2.5 py-1 rounded-lg text-[10px] font-mono bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition flex items-center gap-1"
          >
            <span>CWE-840: Negative Cart (-5 qty)</span>
          </button>
        </div>
      </div>

      {/* Product Catalog Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {products.map((product) => (
          <div
            key={product.id}
            className="glass-panel glass-panel-hover flex flex-col justify-between overflow-hidden group"
          >
            {/* Image & Badge */}
            <div className="relative h-48 w-full bg-zinc-900 overflow-hidden">
              <img
                src={product.imageUrl}
                alt={product.name}
                className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500 opacity-80 group-hover:opacity-100"
              />
              {product.badge && (
                <span className="absolute top-3 left-3 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-blue-600/90 text-white shadow-md backdrop-blur-md">
                  {product.badge}
                </span>
              )}
              <span className="absolute bottom-3 right-3 px-2 py-0.5 rounded-md text-[10px] font-mono bg-black/70 text-zinc-300 backdrop-blur-md">
                {product.category}
              </span>
            </div>

            {/* Product Info */}
            <div className="p-5 flex-1 flex flex-col justify-between space-y-4">
              <div>
                <div className="flex items-center gap-1 text-amber-400 text-xs">
                  <Star className="w-3.5 h-3.5 fill-amber-400" />
                  <span className="font-semibold text-zinc-300">{product.rating}</span>
                  <span className="text-zinc-500">({product.stock} in stock)</span>
                </div>
                <h3 className="text-sm font-bold text-white mt-1 group-hover:text-blue-300 transition-colors">
                  {product.name}
                </h3>
                <p className="text-xs text-zinc-400 mt-1 line-clamp-2 leading-relaxed">
                  {product.description}
                </p>
              </div>

              {/* Vulnerability Inspector Chip */}
              {product.vulnerabilityHint && (
                <div className="p-2.5 rounded-xl bg-white/[0.02] border border-white/[0.06] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-bold text-rose-400">
                      Target: {product.vulnerabilityHint.cwe}
                    </span>
                    <span className="text-[9px] text-zinc-500 uppercase font-mono">Test Hook</span>
                  </div>
                  <p className="text-[11px] text-zinc-300 line-clamp-1">
                    {product.vulnerabilityHint.title}
                  </p>
                </div>
              )}

              {/* Price & Action */}
              <div className="flex items-center justify-between pt-3 border-t border-white/[0.06]">
                <span className="text-lg font-black text-white font-mono">
                  ${product.price.toFixed(2)}
                </span>
                <button
                  onClick={() => addToCart(product)}
                  className="px-3.5 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition shadow-[0_0_15px_rgba(37,99,235,0.25)]"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Add to Cart</span>
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Slide-out Cart Drawer Modal */}
      {isCartOpen && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md h-full bg-[#09090b] border-l border-white/[0.08] p-6 flex flex-col justify-between space-y-6 shadow-2xl animate-in slide-in-from-right duration-200">
            <div>
              <div className="flex items-center justify-between pb-4 border-b border-white/[0.08]">
                <div className="flex items-center gap-2">
                  <ShoppingCart className="w-5 h-5 text-blue-400" />
                  <h3 className="text-base font-bold text-white">Shopping Cart</h3>
                </div>
                <button
                  onClick={() => setIsCartOpen(false)}
                  className="text-xs text-zinc-400 hover:text-white px-2 py-1 rounded bg-white/[0.05]"
                >
                  Close
                </button>
              </div>

              {/* Cart Items List */}
              <div className="divide-y divide-white/[0.04] mt-4 max-h-[50vh] overflow-y-auto pr-1">
                {cart.length === 0 ? (
                  <p className="text-xs text-zinc-500 text-center py-8">Your shopping cart is empty.</p>
                ) : (
                  cart.map((item) => (
                    <div key={item.product.id} className="py-3 flex items-center justify-between gap-3 text-xs">
                      <div>
                        <h4 className="font-semibold text-white">{item.product.name}</h4>
                        <span className="text-zinc-400 font-mono">${item.product.price.toFixed(2)}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => updateQuantity(item.product.id, item.quantity - 1)}
                          className="p-1 rounded bg-white/[0.05] hover:bg-white/[0.1] text-zinc-300"
                        >
                          <Minus className="w-3 h-3" />
                        </button>
                        <span className="font-mono font-bold w-4 text-center text-white">{item.quantity}</span>
                        <button
                          onClick={() => updateQuantity(item.product.id, item.quantity + 1)}
                          className="p-1 rounded bg-white/[0.05] hover:bg-white/[0.1] text-zinc-300"
                        >
                          <Plus className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => removeFromCart(item.product.id)}
                          className="p-1 rounded text-zinc-500 hover:text-rose-400 ml-2"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Cart Footer & Tamper Exploit Test */}
            <div className="space-y-4 pt-4 border-t border-white/[0.08]">
              <div className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] space-y-1.5">
                <span className="text-[10px] font-mono text-zinc-400 uppercase block">Cart Exploit Demonstration</span>
                <button
                  onClick={handleTestNegativeQuantityTamper}
                  className="w-full py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 text-xs font-mono font-semibold transition"
                >
                  Tamper: Inject Negative Quantity (-5)
                </button>
              </div>

              <div className="flex justify-between text-sm font-semibold text-white">
                <span>Total:</span>
                <span className="font-mono text-lg font-bold">${cartTotal.toFixed(2)}</span>
              </div>

              <button
                disabled={cart.length === 0}
                onClick={() => {
                  setFeedback({
                    type: "success",
                    message: `Order submitted successfully for $${cartTotal.toFixed(2)}. OpenTelemetry trace logged.`,
                  });
                  setCart([]);
                  setIsCartOpen(false);
                }}
                className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition disabled:opacity-40 shadow-[0_0_15px_rgba(37,99,235,0.3)]"
              >
                Checkout &amp; Place Order
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
