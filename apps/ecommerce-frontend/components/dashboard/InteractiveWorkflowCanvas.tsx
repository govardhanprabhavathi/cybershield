"use client";

import React, { useState, useRef, useEffect, useMemo, useCallback } from "react";
import {
  Workflow,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Play,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Minimize2,
  PanelRightClose,
  PanelRightOpen,
  SlidersHorizontal,
  Filter,
  CheckCircle2,
  AlertTriangle,
  GitBranch,
  Wrench,
  Search,
  Layers,
  Database,
  Radio,
  Sliders,
  Cpu,
  ArrowRight,
  Terminal,
  Activity,
  Code,
  FileCode,
  Lock,
  Flame,
  UserCheck,
  X,
  ChevronRight,
  ChevronLeft,
  Sparkles,
  Info,
} from "lucide-react";

// ============================================================================
// Types & Data Contracts
// ============================================================================

export type NodeCategory =
  | "TRIGGER"
  | "GATEWAY"
  | "BRANCH"
  | "APP"
  | "TELEMETRY"
  | "SENSOR"
  | "EVALUATOR"
  | "TRIANGULATOR"
  | "ORCHESTRATOR"
  | "REMEDIATION"
  | "SANDBOX"
  | "ACTION";

export type NodeStatus = "idle" | "running" | "completed" | "quarantined" | "bypassed";

export interface NodeColorScheme {
  badgeBg: string;
  badgeText: string;
  iconBg: string;
  iconColor: string;
  activeBorder: string;
  activeGlow: string;
}

export interface WorkflowNode {
  id: string;
  title: string;
  subtitle: string;
  category: NodeCategory;
  agentLabel?: string;
  x: number;
  y: number;
  icon: string;
  hasInput?: boolean;
  outputs?: { id: string; label?: string; offsetPercent?: number }[];
  description: string;
  inputsDesc: string[];
  outputsDesc: string[];
  metrics: { label: string; value: string }[];
  codeSnippet?: string;
  colorScheme: NodeColorScheme;
}

export interface WorkflowEdge {
  id: string;
  from: string;
  to: string;
  fromPort?: string;
  label?: string;
  animated?: boolean;
  status?: "idle" | "active" | "completed";
}

export type ScenarioPreset = "FULL" | "SQLI_ATTACK" | "LEGIT_ALICE" | "TRIANGULATION" | "AST_REMEDIATION";

// ============================================================================
// Node Specifications for CyberShield 12-Agent Lifecycle
// ============================================================================



const SCHEME_BLUE: NodeColorScheme = {
  badgeBg: "bg-blue-50 border border-blue-200",
  badgeText: "text-blue-700",
  iconBg: "bg-blue-50 border border-blue-200",
  iconColor: "text-blue-600",
  activeBorder: "border-black",
  activeGlow: "shadow-[0_4px_25px_rgba(37,99,235,0.2)]",
};

const SCHEME_CYAN: NodeColorScheme = {
  badgeBg: "bg-cyan-50 border border-cyan-200",
  badgeText: "text-cyan-700",
  iconBg: "bg-cyan-50 border border-cyan-200",
  iconColor: "text-cyan-600",
  activeBorder: "border-black",
  activeGlow: "shadow-[0_4px_25px_rgba(6,182,212,0.2)]",
};

const SCHEME_PURPLE: NodeColorScheme = {
  badgeBg: "bg-purple-50 border border-purple-200",
  badgeText: "text-purple-700",
  iconBg: "bg-purple-50 border border-purple-200",
  iconColor: "text-purple-600",
  activeBorder: "border-black",
  activeGlow: "shadow-[0_4px_25px_rgba(147,51,234,0.2)]",
};

const SCHEME_ROSE: NodeColorScheme = {
  badgeBg: "bg-rose-50 border border-rose-200",
  badgeText: "text-rose-700",
  iconBg: "bg-rose-50 border border-rose-200",
  iconColor: "text-rose-600",
  activeBorder: "border-black",
  activeGlow: "shadow-[0_4px_25px_rgba(225,29,72,0.25)]",
};

const SCHEME_EMERALD: NodeColorScheme = {
  badgeBg: "bg-emerald-50 border border-emerald-200",
  badgeText: "text-emerald-700",
  iconBg: "bg-emerald-50 border border-emerald-200",
  iconColor: "text-emerald-600",
  activeBorder: "border-black",
  activeGlow: "shadow-[0_4px_25px_rgba(5,150,105,0.2)]",
};

const SCHEME_AMBER: NodeColorScheme = {
  badgeBg: "bg-amber-50 border border-amber-200",
  badgeText: "text-amber-700",
  iconBg: "bg-amber-50 border border-amber-200",
  iconColor: "text-amber-600",
  activeBorder: "border-black",
  activeGlow: "shadow-[0_4px_25px_rgba(217,119,6,0.2)]",
};

const SCHEME_TEAL: NodeColorScheme = {
  badgeBg: "bg-teal-50 border border-teal-200",
  badgeText: "text-teal-700",
  iconBg: "bg-teal-50 border border-teal-200",
  iconColor: "text-teal-600",
  activeBorder: "border-black",
  activeGlow: "shadow-[0_4px_25px_rgba(13,148,136,0.2)]",
};


const WORKFLOW_NODES: WorkflowNode[] = [
  // ROW 1: Fast-Path Synchronous Enforcement Plane (<= 2.0ms)
  {
    id: "node_inbound",
    title: "Inbound HTTP Request",
    subtitle: "Public Egress Gateway • Port 443",
    category: "TRIGGER",
    x: 30,
    y: 120,
    icon: "Radio",
    hasInput: false,
    outputs: [{ id: "out" }],
    description: "Inbound client request received from customer browser or adversary botnet over HTTPS.",
    inputsDesc: ["Client TLS Connection", "HTTP Verb + Route Query", "Session Cookie / Bearer Token"],
    outputsDesc: ["Normalized HTTP Request context", "Client IP (e.g., 198.51.100.42)", "JWT Auth Headers"],
    metrics: [
      { label: "Target Route", value: "GET /api/v1/products/search" },
      { label: "Client IP", value: "198.51.100.42 (Corporate NAT)" },
      { label: "Protocol", value: "HTTP/2 TLS 1.3" },
    ],
    codeSnippet: `GET /api/v1/products/search?search=' UNION SELECT id, password_hash, email FROM users-- HTTP/1.1\nHost: store.cybershield.internal\nUser-Agent: Mozilla/5.0 (AdversarialBot/2.4)\nX-Forwarded-For: 198.51.100.42`,
    colorScheme: SCHEME_BLUE,
  },
  {
    id: "node_fastpath",
    title: "Fast-Path Risk Gate",
    subtitle: "Redis In-Memory State • O(1) Hash",
    category: "GATEWAY",
    agentLabel: "FAST-PATH GATE",
    x: 310,
    y: 120,
    icon: "Zap",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Ultra-low-latency deterministic request gate running directly inside synchronous FastAPI middleware.",
    inputsDesc: ["Session ID claim from JWT", "In-memory Redis hash lookup"],
    outputsDesc: ["Immediate Allow / Drop decision", "Session Risk Tier (0-100)"],
    metrics: [
      { label: "Lookup Latency", value: "1.25 ms (SLO <= 2.0ms)" },
      { label: "Redis Key", value: "session:risk:{session_id}" },
      { label: "JTI Blacklist Check", value: "revoked:jti:{jti}" },
    ],
    codeSnippet: `async def verify_session_fastpath(session_id: str, redis: Redis) -> bool:\n    # Sub-2ms fast-path lookup\n    state = await redis.hget(f"session:risk:{session_id}", "state")\n    if state == "CONTAIN":\n        raise HTTPException(status_code=403, detail="Session quarantined")\n    return True`,
    colorScheme: SCHEME_CYAN,
  },
  {
    id: "node_branch_risk",
    title: "Session Risk Branch",
    subtitle: "Decision: Is Risk Score >= 80?",
    category: "BRANCH",
    x: 600,
    y: 120,
    icon: "GitBranch",
    hasInput: true,
    outputs: [
      { id: "high_risk", label: "High Risk (>=80)", offsetPercent: 28 },
      { id: "low_risk", label: "Safe (<80)", offsetPercent: 72 },
    ],
    description: "Evaluates the current composite risk score against the graduated response threshold matrix.",
    inputsDesc: ["Risk Score from Agent 8", "Confidence Score"],
    outputsDesc: ["True -> Route to Immediate 403 Quarantine", "False -> Permit passage to Application Storefront"],
    metrics: [
      { label: "Evaluation Latency", value: "0.05 ms" },
      { label: "Containment Floor", value: "Risk >= 80 & Conf >= 0.75" },
    ],
    codeSnippet: `if risk_score >= 80 and confidence >= 0.75:\n    # Route to containment quarantine branch\n    return "CONTAIN"\nreturn "ALLOW"`,
    colorScheme: SCHEME_PURPLE,
  },
  {
    id: "node_containment",
    title: "Immediate 403 Quarantine",
    subtitle: "Session Token Revoked in Redis",
    category: "ACTION",
    x: 1000,
    y: 40,
    icon: "ShieldAlert",
    hasInput: true,
    outputs: [],
    description: "Immediate session termination and token revocation. Requests dropped at gateway without server overhead.",
    inputsDesc: ["High-risk session ID token", "Egress NAT IP (Preserved for legitimate users)"],
    outputsDesc: ["HTTP 403 Forbidden payload", "JTI Blacklist recorded in Redis"],
    metrics: [
      { label: "Enforcement Action", value: "Token Revoked / 403 Dropped" },
      { label: "Legitimate User Impact", value: "0.0% Collateral Block (FPR = 0%)" },
      { label: "Total Intercept Time", value: "1.25 ms" },
    ],
    codeSnippet: `await redis.setex(f"revoked:jti:{jti}", 86400, "quarantined")\nawait redis.hset(f"session:risk:{session_id}", "state", "CONTAIN")\nreturn Response(status_code=403, content={"error": "Session quarantined"})`,
    colorScheme: SCHEME_ROSE,
  },
  {
    id: "node_storefront",
    title: "Target E-Commerce Core",
    subtitle: "External API & Route Handlers",
    category: "APP",
    x: 1000,
    y: 200,
    icon: "Database",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "External target e-commerce application handling catalog browsing, cart operations, and order placement under CyberShield protection.",
    inputsDesc: ["Authorized request payload", "Target application session"],
    outputsDesc: ["HTTP 200/201 JSON response", "Order record in target DB"],
    metrics: [
      { label: "Execution Time", value: "8.2 ms" },
      { label: "Target Status", value: "HTTP 200 OK" },
    ],
    codeSnippet: `@router.get("/products/search")\nasync def search(search: str, db: AsyncSession = Depends(get_db)):\n    # Executes query and returns active catalog items\n    return await product_service.search_products(db, search)`,
    colorScheme: SCHEME_EMERALD,
  },
  {
    id: "node_otel",
    title: "OTel Telemetry Middleware",
    subtitle: "W3C Spans • Distributed Tracing",
    category: "TELEMETRY",
    x: 1310,
    y: 200,
    icon: "Activity",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Non-blocking telemetry collector emitting full HTTP trace context to the asynchronous ingestion pipeline.",
    inputsDesc: ["FastAPI request/response lifecycle hooks", "W3C traceparent headers"],
    outputsDesc: ["Structured JSON Telemetry Event", "Latency timings and query signatures"],
    metrics: [
      { label: "Middleware Overhead", value: "0.18 ms (Non-blocking)" },
      { label: "Trace Context", value: "W3C traceparent trace_id" },
    ],
    codeSnippet: `trace_event = TelemetryEvent(\n    trace_id=trace_id,\n    session_id=session_id,\n    route=request.url.path,\n    status_code=response.status_code,\n    duration_ms=latency\n)`,
    colorScheme: SCHEME_CYAN,
  },
  {
    id: "node_redis_stream",
    title: "Redis Event Stream",
    subtitle: "stream:telemetry • Decoupled Queue",
    category: "TELEMETRY",
    x: 1620,
    y: 200,
    icon: "Layers",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Decouples synchronous web servers from heavy AI security analysis via an append-only event stream.",
    inputsDesc: ["Async XADD command", "Telemetry event payload"],
    outputsDesc: ["Distributed worker queue entries", "Consumer group stream read"],
    metrics: [
      { label: "Throughput", value: "100,000+ events/sec" },
      { label: "Stream Key", value: "stream:telemetry" },
    ],
    codeSnippet: `await redis.xadd("stream:telemetry", {\n    "session_id": event.session_id,\n    "payload": json.dumps(event.dict())\n})`,
    colorScheme: SCHEME_ROSE,
  },

  // ROW 2: Pre-Deployment & Runtime Detection Agents (Intelligence Plane)
  {
    id: "node_static_scan",
    title: "Pre-Deployment Static Suite",
    subtitle: "Agents 1, 2, 4, 5, 6 • AST Analysis",
    category: "SENSOR",
    agentLabel: "AGENTS 1, 2, 4, 5, 6",
    x: 310,
    y: 390,
    icon: "Code",
    hasInput: false,
    outputs: [{ id: "out" }],
    description: "Pre-deployment static analysis uncovering SQLi, BOLA, dependencies, secrets, and configuration flaws.",
    inputsDesc: ["Python source tree", "FastAPI router definitions", "pyproject.toml SBOM"],
    outputsDesc: ["Static SecurityFinding records", "Application Route & Auth Map"],
    metrics: [
      { label: "Routes Scanned", value: "21 Endpoints" },
      { label: "CWE Weaknesses", value: "CWE-89, CWE-284, CWE-798" },
      { label: "SAST Confidence", value: "c_1 = 0.95" },
    ],
    codeSnippet: `class CodeSecurityVisitor(ast.NodeVisitor):\n    def visit_JoinedStr(self, node):\n        # Flags raw f-string inside SQLAlchemy text() call\n        self.findings.append(SecurityFinding(cwe_id="CWE-89", confidence=0.95))`,
    colorScheme: SCHEME_PURPLE,
  },
  {
    id: "node_dast_prober",
    title: "Agent 3: API Security DAST",
    subtitle: "Dynamic Probing • Exploit Replay",
    category: "SENSOR",
    agentLabel: "AGENT 3 DAST",
    x: 650,
    y: 390,
    icon: "Search",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Active dynamic black-box probe agent verifying exploitability of discovered API endpoints.",
    inputsDesc: ["OpenAPI schema", "Candidate injection payloads", "Isolated test credentials"],
    outputsDesc: ["Reproduced exploit traces", "DAST Confidence Score"],
    metrics: [
      { label: "DAST Confidence", value: "c_2 = 0.92" },
      { label: "Exploitation Status", value: "Confirmed Exploit Response 500" },
    ],
    codeSnippet: `res = await client.get("/api/v1/products/search?search=' UNION SELECT id...")\nif res.status_code == 500 and "Database execution error" in res.text:\n    # DAST confirms active vulnerability\n    return DASTFinding(cwe_id="CWE-89", confidence=0.92)`,
    colorScheme: SCHEME_CYAN,
  },
  {
    id: "node_runtime_sensor",
    title: "Agent 7: Runtime Sensor",
    subtitle: "Live Telemetry Pattern Matcher",
    category: "SENSOR",
    agentLabel: "AGENT 7 SENSOR",
    x: 1620,
    y: 390,
    icon: "Shield",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Monitors Redis telemetry streams in real time, detecting SQLi, XSS, and brute-force indicators.",
    inputsDesc: ["Event Stream entries", "Deterministic detection rules"],
    outputsDesc: ["Structured RuntimeIncident records", "Runtime confidence score"],
    metrics: [
      { label: "Runtime Confidence", value: "c_3 = 0.98" },
      { label: "Processing Latency", value: "0.45 ms" },
      { label: "Pattern Matched", value: "SQL_INJECTION (UNION / quote)" },
    ],
    codeSnippet: `if any(p.search(query) for p in SQLI_PATTERNS):\n    return RuntimeIncident(\n        attack_type="SQL_INJECTION",\n        cwe_id="CWE-89",\n        confidence=0.98\n    )`,
    colorScheme: SCHEME_ROSE,
  },
  {
    id: "node_risk_engine",
    title: "Agent 8: Session Risk Engine",
    subtitle: "Explainable Risk Scoring (0-100)",
    category: "EVALUATOR",
    agentLabel: "AGENT 8 RISK",
    x: 1930,
    y: 390,
    icon: "Sliders",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Compounds multiple security incidents into an explainable 0-100 session risk score.",
    inputsDesc: ["Session RuntimeIncidents", "Attack severity weights", "Multi-vector multiplier"],
    outputsDesc: ["Updated Risk Score (0-100)", "Compounded Confidence (0.0-1.0)"],
    metrics: [
      { label: "Computed Risk", value: "90 / 100" },
      { label: "Multi-Vector Multiplier", value: "1.2x (Cross-vector attack)" },
      { label: "Compounded Conf", value: "0.96" },
    ],
    codeSnippet: `base_score = sum(WEIGHTS[i.attack_type] for i in incidents)\nif len(attack_types) >= 2:\n    base_score = int(base_score * 1.2)  # Multi-vector compounding\nfinal_risk = min(100, base_score)`,
    colorScheme: SCHEME_AMBER,
  },
  {
    id: "node_graduated_policy",
    title: "Graduated Defense Policy",
    subtitle: "ALLOW • MONITOR • CONTAIN",
    category: "EVALUATOR",
    x: 2240,
    y: 390,
    icon: "ShieldCheck",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Maps (Risk, Confidence) tuples deterministically to graduated containment tiers.",
    inputsDesc: ["Session Risk Score", "Bayesian Confidence"],
    outputsDesc: ["Tier Action: ALLOW | MONITOR | THROTTLE | CHALLENGE | CONTAIN", "Redis Fast-Path Update"],
    metrics: [
      { label: "Assigned Tier", value: "CONTAIN (Quarantine)" },
      { label: "State Sync Latency", value: "0.85 ms to Redis" },
    ],
    codeSnippet: `if risk_score >= 90 and confidence >= 0.85:\n    return "CONTAIN"  # Immediate gateway drop\nelif risk_score >= 60:\n    return "THROTTLE" # Adaptive latency injection`,
    colorScheme: SCHEME_BLUE,
  },

  // ROW 3: Triangulation, Orchestration & AST Remediation
  {
    id: "node_triangulator",
    title: "Agent 9: Evidence Triangulator",
    subtitle: "Bayesian 3-Pillar Fusion • P >= 0.99",
    category: "TRIANGULATOR",
    agentLabel: "AGENT 9 TRIANGULATOR",
    x: 650,
    y: 580,
    icon: "Cpu",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Fuses SAST, DAST, and Runtime telemetry into a single mathematical Bayesian confidence score.",
    inputsDesc: ["SAST AST finding (c_1=0.95)", "DAST probe trace (c_2=0.92)", "Runtime sensor span (c_3=0.98)"],
    outputsDesc: ["Composite Confidence P(V) = 0.9996", "Zero-False-Positive Verified Dossier"],
    metrics: [
      { label: "Bayesian P(V)", value: "0.9996 (Threshold >= 0.99)" },
      { label: "False Positive Rate", value: "0.00% Verified" },
      { label: "Triangulation Tier", value: "FULL_TRIANGULATION" },
    ],
    codeSnippet: `# P(V) = 1.0 - (1 - c_sast) * (1 - c_dast) * (1 - c_runtime)\nproduct_failure = (1.0 - 0.95) * (1.0 - 0.92) * (1.0 - 0.98)\ncomposite_p = 1.0 - product_failure  # 0.9996`,
    colorScheme: SCHEME_TEAL,
  },
  {
    id: "node_dossier",
    title: "Triangulated Dossier DB",
    subtitle: "Dossier #DOS-CWE-89 • Confirmed",
    category: "EVALUATOR",
    x: 1000,
    y: 580,
    icon: "Database",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Persistent cryptographic evidence ledger containing correlated code snippets and HTTP traces.",
    inputsDesc: ["Triangulated finding package", "Root cause context"],
    outputsDesc: ["Immutable Dossier Record", "Workflow dispatch trigger"],
    metrics: [
      { label: "Dossier ID", value: "DOS-CWE-89-SQLI" },
      { label: "Exploit Status", value: "ACTIVELY_EXPLOITED" },
    ],
    codeSnippet: `dossier = TriangulatedDossier(\n    cwe_id="CWE-89",\n    status="ACTIVELY_EXPLOITED",\n    composite_confidence=0.9996\n)`,
    colorScheme: SCHEME_BLUE,
  },
  {
    id: "node_orchestrator",
    title: "Agent 12: Master AI Orchestrator",
    subtitle: "FSM Incident Workflow Lifecycle",
    category: "ORCHESTRATOR",
    agentLabel: "AGENT 12 ORCHESTRATOR",
    x: 1310,
    y: 580,
    icon: "Workflow",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Finite State Machine coordinator managing incident state transitions, playbooks, and governance.",
    inputsDesc: ["Triangulated Dossier", "Governance policy mode"],
    outputsDesc: ["FSM State: DRAFTING_PATCH", "Playbook Execution Plan"],
    metrics: [
      { label: "FSM State", value: "TRIANGULATING -> DRAFTING" },
      { label: "Governance Mode", value: "FULLY_AUTONOMOUS" },
    ],
    codeSnippet: `fsm = IncidentStateMachine(current_state="TRIANGULATING")\nnext_state = fsm.transition_to("DRAFTING_PATCH")\nawait playbook_runner.execute("SQLI_CONTAINMENT_PLAYBOOK")`,
    colorScheme: SCHEME_PURPLE,
  },
  {
    id: "node_ast_patcher",
    title: "Agent 10: AST Patch Generator",
    subtitle: "Deterministic Parameterized Queries",
    category: "REMEDIATION",
    agentLabel: "AGENT 10 PATCHER",
    x: 1620,
    y: 580,
    icon: "Wrench",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Synthesizes minimal, deterministic AST code modifications eliminating vulnerable constructs.",
    inputsDesc: ["Vulnerable source code", "CWE classification (CWE-89)"],
    outputsDesc: ["Unified Git diff", "Patch Strategy: PARAMETERIZATION"],
    metrics: [
      { label: "Patch Generation", value: "0.35 ms" },
      { label: "Strategy", value: "SQLAlchemy Parameterization (:term)" },
    ],
    codeSnippet: `# Unified AST Diff Generated:\n- raw_sql = f"SELECT * FROM products WHERE name LIKE '%{search}%'"\n+ safe_sql = text("SELECT * FROM products WHERE name LIKE :term")\n+ result = await db.execute(safe_sql, {"term": f"%{search}%"})`,
    colorScheme: SCHEME_PURPLE,
  },
  {
    id: "node_sandbox",
    title: "Agent 11: Remediation Sandbox",
    subtitle: "Syntax • Safety • Non-Regression",
    category: "SANDBOX",
    agentLabel: "AGENT 11 SANDBOX",
    x: 1930,
    y: 580,
    icon: "Lock",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Validates candidate code patches inside an isolated sandbox before applying to production disk.",
    inputsDesc: ["Candidate AST Diff", "Original file source code"],
    outputsDesc: ["Verification Report: 3 / 3 Checks Passed", "Regression Rate: 0.0%"],
    metrics: [
      { label: "Gate 1: Syntax Valid", value: "100.0% (ast.parse True)" },
      { label: "Gate 2: Exploit Neutralized", value: "100.0% (Zero f-strings in text())" },
      { label: "Gate 3: Functional Regression", value: "0.0% (Signatures Preserved)" },
    ],
    codeSnippet: `passed, checks, ms = RemediationSandbox.run_sandbox_checks(diff, original)\nassert passed == True\nassert all(c.passed for c in checks)`,
    colorScheme: SCHEME_BLUE,
  },
  {
    id: "node_branch_sandbox",
    title: "Pre-Commit Gate",
    subtitle: "Decision: Did All 3 Checks Pass?",
    category: "BRANCH",
    x: 2240,
    y: 580,
    icon: "GitBranch",
    hasInput: true,
    outputs: [
      { id: "passed", label: "Passed (100%)", offsetPercent: 28 },
      { id: "failed", label: "Failed", offsetPercent: 72 },
    ],
    description: "Enforces zero-tolerance safety barrier before code modifications can touch live services.",
    inputsDesc: ["Agent 11 Verification Report", "Governance Mode"],
    outputsDesc: ["True -> Autonomous Hot Deployment", "False -> Human-in-the-Loop Escalation"],
    metrics: [
      { label: "Checks Passed", value: "3 of 3 (100%)" },
      { label: "Route Selection", value: "Autonomous Apply" },
    ],
    codeSnippet: `if verification_report.all_passed:\n    return "AUTO_DEPLOYING"\nreturn "ESCALATED_HUMAN"`,
    colorScheme: SCHEME_AMBER,
  },
  {
    id: "node_auto_deploy",
    title: "Autonomous Zero-Downtime Deploy",
    subtitle: "Hot-Patch Applied • Service Live",
    category: "ACTION",
    x: 2640,
    y: 500,
    icon: "CheckCircle2",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Applies verified patch with rollback snapshot. Application vulnerability permanently neutralized.",
    inputsDesc: ["Verified patch diff", "Target file path"],
    outputsDesc: ["Neutralized vulnerability state", "Rollback checkpoint snapshot"],
    metrics: [
      { label: "Deployment Method", value: "Atomic File Replacement" },
      { label: "Service Downtime", value: "0.00 ms (Zero Interruption)" },
      { label: "Rollback Ready", value: "True" },
    ],
    codeSnippet: `await remediation_service.apply_proposal(proposal_id=p.id, dry_run=False)\nfsm.transition_to("RESOLVED")`,
    colorScheme: SCHEME_EMERALD,
  },
  {
    id: "node_hitl",
    title: "Operator Review (HITL)",
    subtitle: "Awaiting Security Analyst Sign-off",
    category: "ACTION",
    x: 2640,
    y: 660,
    icon: "UserCheck",
    hasInput: true,
    outputs: [{ id: "out" }],
    description: "Pauses execution for operator approval when governance mode requires human confirmation.",
    inputsDesc: ["Drafted unified diff", "Sandbox failure reason"],
    outputsDesc: ["Analyst Approval / Rejection event"],
    metrics: [
      { label: "Current State", value: "AWAITING_APPROVAL" },
      { label: "Operator Role", value: "SecOps Lead" },
    ],
    codeSnippet: `fsm.transition_to("AWAITING_APPROVAL")\nnotify_security_analyst(workflow_id=wf.id)`,
    colorScheme: SCHEME_AMBER,
  },
  {
    id: "node_resolution",
    title: "Incident Verified & Resolved",
    subtitle: "Audit Ledger Closed • 0% Regr",
    category: "ACTION",
    x: 3000,
    y: 580,
    icon: "ShieldCheck",
    hasInput: true,
    outputs: [],
    description: "Incident marked RESOLVED in audit logs. Continues telemetry sampling to ensure zero regression.",
    inputsDesc: ["Applied patch verification", "Re-scan report"],
    outputsDesc: ["Cryptographic Audit Entry in DB", "Closed Incident Ticket"],
    metrics: [
      { label: "Workflow State", value: "RESOLVED" },
      { label: "Cycle Time", value: "< 40 ms Total" },
      { label: "Exploit Neutralized", value: "100.0%" },
    ],
    codeSnippet: `await workflow_service.record_audit_log(\n    action="WORKFLOW_RESOLVED",\n    status="SUCCESS",\n    details="Exploit neutralized, zero regressions."\n)`,
    colorScheme: SCHEME_EMERALD,
  },
];

// ============================================================================
// Workflow Edges (Connecting Lines with Directional Routing)
// ============================================================================

const WORKFLOW_EDGES: WorkflowEdge[] = [
  // Fast-Path Row
  { id: "e1", from: "node_inbound", to: "node_fastpath" },
  { id: "e2", from: "node_fastpath", to: "node_branch_risk" },
  { id: "e3", from: "node_branch_risk", to: "node_containment", fromPort: "high_risk", label: "Risk >= 80" },
  { id: "e4", from: "node_branch_risk", to: "node_storefront", fromPort: "low_risk", label: "Risk < 80 (Allow)" },
  { id: "e5", from: "node_storefront", to: "node_otel" },
  { id: "e6", from: "node_otel", to: "node_redis_stream" },

  // Telemetry to Runtime Sensor & Risk
  { id: "e7", from: "node_redis_stream", to: "node_runtime_sensor" },
  { id: "e8", from: "node_runtime_sensor", to: "node_risk_engine" },
  { id: "e9", from: "node_risk_engine", to: "node_graduated_policy" },
  { id: "e10", from: "node_graduated_policy", to: "node_containment", label: "CONTAIN Tier Update" },

  // Pre-Deployment & Triangulation
  { id: "e11", from: "node_static_scan", to: "node_dast_prober" },
  { id: "e12", from: "node_static_scan", to: "node_triangulator", label: "c_1 (SAST)" },
  { id: "e13", from: "node_dast_prober", to: "node_triangulator", label: "c_2 (DAST)" },
  { id: "e14", from: "node_runtime_sensor", to: "node_triangulator", label: "c_3 (Runtime)" },

  // Triangulation to Orchestration & Remediation
  { id: "e15", from: "node_triangulator", to: "node_dossier", label: "P >= 0.99" },
  { id: "e16", from: "node_dossier", to: "node_orchestrator" },
  { id: "e17", from: "node_orchestrator", to: "node_ast_patcher" },
  { id: "e18", from: "node_ast_patcher", to: "node_sandbox" },
  { id: "e19", from: "node_sandbox", to: "node_branch_sandbox" },
  { id: "e20", from: "node_branch_sandbox", to: "node_auto_deploy", fromPort: "passed", label: "All Passed (100%)" },
  { id: "e21", from: "node_branch_sandbox", to: "node_hitl", fromPort: "failed", label: "Failed / HITL" },
  { id: "e22", from: "node_auto_deploy", to: "node_resolution" },
  { id: "e23", from: "node_hitl", to: "node_resolution" },
];

// ============================================================================
// Simulation Scenarios & Step Sequences
// ============================================================================

interface SimulationStep {
  nodeId: string;
  edgeId?: string;
  edgeIds?: string[];
  logMessage: string;
  durationMs: number;
  highlightStatus?: NodeStatus;
}

const SCENARIOS: Record<ScenarioPreset, { name: string; description: string; steps: SimulationStep[] }> = {
  FULL: {
    name: "Master Full-Lifecycle Defense Flow",
    description: "Simulates an adversarial attack that triggers sub-2ms quarantine, Bayesian triangulation, and autonomous AST repair.",
    steps: [
      { nodeId: "node_inbound", edgeId: "e1", logMessage: "HTTP GET /products/search?search=' OR 1=1-- from 198.51.100.42", durationMs: 400 },
      { nodeId: "node_fastpath", edgeId: "e2", logMessage: "Fast-Path Gate: Redis lookup executed in 1.25ms (Sub-2ms verified)", durationMs: 500 },
      { nodeId: "node_branch_risk", edgeIds: ["e3", "e4"], logMessage: "Risk Evaluation: Dual-path routing — Attacker quarantined while clean tenant traffic passes", durationMs: 500 },
      { nodeId: "node_containment", logMessage: "Enforcement: Attacker token blacklisted in Redis. 403 Dropped (LSPR = 100% on shared NAT)", durationMs: 500, highlightStatus: "quarantined" },
      { nodeId: "node_storefront", edgeId: "e5", logMessage: "Target E-Commerce Core: Catalog & Cart route executed safely for benign traffic", durationMs: 500, highlightStatus: "completed" },
      { nodeId: "node_otel", edgeId: "e6", logMessage: "OTel Middleware: Asynchronous telemetry span emitted with W3C tracecontext", durationMs: 400 },
      { nodeId: "node_redis_stream", edgeId: "e7", logMessage: "Redis Stream: Event queued to 'stream:telemetry' for worker pool", durationMs: 400 },
      { nodeId: "node_runtime_sensor", edgeIds: ["e8", "e14"], logMessage: "Agent 7 Runtime Sensor: Pattern matched SQL_INJECTION error (c_3 = 0.98 emitted to Triangulator)", durationMs: 500 },
      { nodeId: "node_risk_engine", edgeId: "e9", logMessage: "Agent 8 Risk Engine: Compounded risk 90/100 (1.2x cross-vector boost applied)", durationMs: 500 },
      { nodeId: "node_graduated_policy", edgeId: "e10", logMessage: "Graduated Policy: Confirmed CONTAIN state. Fast-path sync complete.", durationMs: 500 },
      { nodeId: "node_static_scan", edgeIds: ["e11", "e12"], logMessage: "Agent 2 Code AST: Correlated pre-deployment finding CWE-89 (c_1 = 0.95)", durationMs: 500 },
      { nodeId: "node_dast_prober", edgeId: "e13", logMessage: "Agent 3 DAST Prober: Correlated dynamic exploit confirmation (c_2 = 0.92)", durationMs: 500 },
      { nodeId: "node_triangulator", edgeId: "e15", logMessage: "Agent 9 Triangulator: Fused c_1, c_2, c_3 -> Computed P(V) = 0.9996 (FPR = 0.0%)", durationMs: 600, highlightStatus: "completed" },
      { nodeId: "node_dossier", edgeId: "e16", logMessage: "Triangulated Dossier: Stored in DB with status ACTIVELY_EXPLOITED", durationMs: 400 },
      { nodeId: "node_orchestrator", edgeId: "e17", logMessage: "Agent 12 Master Orchestrator: FSM transitioned to DRAFTING_PATCH", durationMs: 500 },
      { nodeId: "node_ast_patcher", edgeId: "e18", logMessage: "Agent 10 AST Patcher: Synthesized parameterized SQLAlchemy query diff", durationMs: 500 },
      { nodeId: "node_sandbox", edgeId: "e19", logMessage: "Agent 11 Sandbox: Verified Syntax OK, Safety OK, Regression Rate = 0.0%", durationMs: 600 },
      { nodeId: "node_branch_sandbox", edgeId: "e20", logMessage: "Pre-Commit Gate: All 3 verification gates passed (100.0%)", durationMs: 400 },
      { nodeId: "node_auto_deploy", edgeId: "e22", logMessage: "Autonomous Deploy: Hot patch committed without service downtime", durationMs: 500, highlightStatus: "completed" },
      { nodeId: "node_resolution", logMessage: "Incident Workflow: RESOLVED in < 40ms total cycle time. Audit ledger closed.", durationMs: 600, highlightStatus: "completed" },
    ],
  },
  SQLI_ATTACK: {
    name: "Live Threat Gating & Quarantine",
    description: "Simulates an inbound SQL injection exploit intercepted at the sub-2ms fast-path gate.",
    steps: [
      { nodeId: "node_inbound", edgeId: "e1", logMessage: "Adversary: Inbound UNION injection on /api/v1/products/search", durationMs: 500 },
      { nodeId: "node_fastpath", edgeId: "e2", logMessage: "Fast-Path Gate: Evaluated in 1.25ms (Sub-2ms verified)", durationMs: 500 },
      { nodeId: "node_branch_risk", edgeId: "e3", logMessage: "Branch: High Risk (>= 80) confirmed", durationMs: 500 },
      { nodeId: "node_containment", logMessage: "Session Quarantined: Attacker token revoked. Follow-up requests dropped at gateway.", durationMs: 800, highlightStatus: "quarantined" },
    ],
  },
  LEGIT_ALICE: {
    name: "Legitimate Shopper (Alice on Shared NAT IP)",
    description: "Proves zero collateral damage: Alice shops cleanly on the same IP 198.51.100.42 while the attacker is contained.",
    steps: [
      { nodeId: "node_inbound", edgeId: "e1", logMessage: "Shopper Alice: Searches for 'FIDO2 Hardware Key' from 198.51.100.42", durationMs: 500 },
      { nodeId: "node_fastpath", edgeId: "e2", logMessage: "Fast-Path Gate: Alice's session token clean (Risk = 0, Lookup: 1.25ms)", durationMs: 500 },
      { nodeId: "node_branch_risk", edgeId: "e4", logMessage: "Branch: Risk < 80 -> Route allowed to Target E-Commerce Core", durationMs: 500 },
      { nodeId: "node_storefront", edgeId: "e5", logMessage: "Target E-Commerce Backend: Item added to cart, Order #1003 placed (HTTP 200 OK)", durationMs: 600, highlightStatus: "completed" },
      { nodeId: "node_otel", edgeId: "e6", logMessage: "LSPR = 100.0%: Alice completely unaffected by co-located botnet on identical IP", durationMs: 600, highlightStatus: "completed" },
    ],
  },
  TRIANGULATION: {
    name: "Multi-Pillar Evidence Triangulation",
    description: "Demonstrates 3-pillar Bayesian evidence fusion (SAST + DAST + Runtime OTel) achieving P(V) >= 0.99 and FPR = 0.00%.",
    steps: [
      { nodeId: "node_static_scan", edgeId: "e12", logMessage: "Pillar 1 (SAST): Agent 2 AST parse flags unparameterized query (c_1 = 0.95)", durationMs: 600 },
      { nodeId: "node_dast_prober", edgeId: "e13", logMessage: "Pillar 2 (DAST): Agent 3 dynamic fuzz probe reproduces 500 error (c_2 = 0.92)", durationMs: 600 },
      { nodeId: "node_runtime_sensor", edgeId: "e14", logMessage: "Pillar 3 (Runtime OTel): Agent 7 captures live SQL error span (c_3 = 0.98)", durationMs: 600 },
      { nodeId: "node_triangulator", edgeId: "e15", logMessage: "Agent 9: P(V) = 1.0 - (1-0.95)*(1-0.92)*(1-0.98) = 0.9996 (FPR = 0.00%)", durationMs: 800, highlightStatus: "completed" },
      { nodeId: "node_dossier", logMessage: "Vulnerability Dossier elevated to ACTIVELY_EXPLOITED status with 100% confidence", durationMs: 600, highlightStatus: "completed" },
    ],
  },
  AST_REMEDIATION: {
    name: "Deterministic AST Remediation & Verification",
    description: "Evaluates Agent 10 patch generation, Agent 11 3-stage sandbox testing, and zero functional regression.",
    steps: [
      { nodeId: "node_orchestrator", edgeId: "e17", logMessage: "Agent 12 Orchestrator: Dispatches remediation for CWE-89 SQL Injection", durationMs: 500 },
      { nodeId: "node_ast_patcher", edgeId: "e18", logMessage: "Agent 10 AST Patcher: Synthesizes SQLAlchemy parameterized bindings (:term)", durationMs: 600 },
      { nodeId: "node_sandbox", edgeId: "e19", logMessage: "Agent 11 Sandbox: Syntax check passed, Safety verified, 0.0% regression", durationMs: 700 },
      { nodeId: "node_branch_sandbox", edgeId: "e20", logMessage: "Pre-Commit Gate: All 3 verification gates passed with 100% success", durationMs: 400 },
      { nodeId: "node_auto_deploy", edgeId: "e22", logMessage: "Autonomous Safe Apply: Hot-reloaded cleanly without server restart", durationMs: 500, highlightStatus: "completed" },
      { nodeId: "node_resolution", logMessage: "Incident Workflow RESOLVED in < 40ms total cycle time", durationMs: 600, highlightStatus: "completed" },
    ],
  },
};

// ============================================================================
// Helper Component: Node Icon Renderer
// ============================================================================

function NodeIcon({ name, className }: { name: string; className?: string }) {
  switch (name) {
    case "Radio":
      return <Radio className={className} />;
    case "Zap":
      return <Zap className={className} />;
    case "GitBranch":
      return <GitBranch className={className} />;
    case "ShieldAlert":
      return <ShieldAlert className={className} />;
    case "Database":
      return <Database className={className} />;
    case "Activity":
      return <Activity className={className} />;
    case "Layers":
      return <Layers className={className} />;
    case "Code":
      return <Code className={className} />;
    case "Search":
      return <Search className={className} />;
    case "Shield":
      return <Shield className={className} />;
    case "Sliders":
      return <Sliders className={className} />;
    case "ShieldCheck":
      return <ShieldCheck className={className} />;
    case "Cpu":
      return <Cpu className={className} />;
    case "Workflow":
      return <Workflow className={className} />;
    case "Wrench":
      return <Wrench className={className} />;
    case "Lock":
      return <Lock className={className} />;
    case "CheckCircle2":
      return <CheckCircle2 className={className} />;
    case "UserCheck":
      return <UserCheck className={className} />;
    default:
      return <Workflow className={className} />;
  }
}

// ============================================================================
// Main Component: Interactive Workflow Canvas
// ============================================================================

export default function InteractiveWorkflowCanvas() {
  const [selectedScenario, setSelectedScenario] = useState<ScenarioPreset>("FULL");
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(-1);
  const [selectedNodeId, setSelectedNodeId] = useState<string>("node_fastpath");
  const [activeNodeIds, setActiveNodeIds] = useState<Set<string>>(new Set());
  const [activeEdgeIds, setActiveEdgeIds] = useState<Set<string>>(new Set());
  const [nodeStatuses, setNodeStatuses] = useState<Record<string, NodeStatus>>({});
  const [logs, setLogs] = useState<{ id: string; time: string; message: string; type: "info" | "alert" | "success" }[]>([]);

  // Full-Screen & Side Panel View States
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);
  const [isSidePanelOpen, setIsSidePanelOpen] = useState<boolean>(true);
  const [sidePanelTab, setSidePanelTab] = useState<"inspector" | "scenarios" | "logs">("inspector");
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);

  // Canvas Pan & Zoom State
  const [scale, setScale] = useState<number>(0.72);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 30, y: 40 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  const containerRef = useRef<HTMLDivElement>(null);
  const touchDistanceRef = useRef<number | null>(null);
  const initialTouchScaleRef = useRef<number>(0.72);

  // Active Selected Node Data
  const selectedNode = useMemo(() => {
    return WORKFLOW_NODES.find((n) => n.id === selectedNodeId) || WORKFLOW_NODES[1];
  }, [selectedNodeId]);

  // Compute node map for easy coordinate lookups
  const nodeMap = useMemo(() => {
    const map = new Map<string, WorkflowNode>();
    for (const node of WORKFLOW_NODES) {
      map.set(node.id, node);
    }
    return map;
  }, []);

  // Reset simulation state
  const handleReset = useCallback(() => {
    setIsPlaying(false);
    setCurrentStepIndex(-1);
    setActiveNodeIds(new Set());
    setActiveEdgeIds(new Set());
    setNodeStatuses({});
    setLogs([]);
  }, []);

  // When scenario changes, reset
  const handleSelectScenario = (key: ScenarioPreset) => {
    handleReset();
    setSelectedScenario(key);
  };

  // Full-Screen Toggle with Browser Fullscreen API and State sync
  const handleToggleFullscreen = () => {
    setIsFullscreen((prev) => {
      const next = !prev;
      if (next) {
        setIsSidePanelOpen(true);
        setTimeout(() => {
          handleFitView();
        }, 150);
        try {
          if (!document.fullscreenElement && document.documentElement.requestFullscreen) {
            document.documentElement.requestFullscreen().catch(() => {});
          }
        } catch {}
      } else {
        try {
          if (document.fullscreenElement && document.exitFullscreen) {
            document.exitFullscreen().catch(() => {});
          }
        } catch {}
        setTimeout(() => {
          handleFitView();
        }, 150);
      }
      return next;
    });
  };

  // Step-by-Step Interactive Navigation (Next & Previous Step)
  const handleNextStep = useCallback(() => {
    setIsPlaying(false);
    const scenario = SCENARIOS[selectedScenario];
    const nextIdx = currentStepIndex < 0 ? 0 : currentStepIndex + 1;
    if (nextIdx >= scenario.steps.length) return;

    const step = scenario.steps[nextIdx];
    if (!step) return;

    setActiveNodeIds((prev) => new Set([...prev, step.nodeId]));
    if (step.edgeId) setActiveEdgeIds((prev) => new Set([...prev, step.edgeId!]));
    if (step.edgeIds) setActiveEdgeIds((prev) => new Set([...prev, ...step.edgeIds!]));
    setNodeStatuses((prev) => ({
      ...prev,
      [step.nodeId]: step.highlightStatus || "completed",
    }));

    setSelectedNodeId(step.nodeId);
    if (isFullscreen) {
      setIsSidePanelOpen(true);
      setSidePanelTab("inspector");
    }

    const now = new Date();
    const timeStr = `${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}.${String(
      Math.floor(now.getMilliseconds() / 10)
    ).padStart(2, "0")}`;

    const logType: "info" | "alert" | "success" = step.highlightStatus === "quarantined"
      ? "alert"
      : step.highlightStatus === "completed"
      ? "success"
      : "info";

    setLogs((prev) => [
      {
        id: `log-${Date.now()}-${Math.random()}`,
        time: timeStr,
        message: step.logMessage,
        type: logType,
      },
      ...prev.slice(0, 49),
    ]);

    setCurrentStepIndex(nextIdx);
  }, [selectedScenario, currentStepIndex, isFullscreen]);

  const handlePrevStep = useCallback(() => {
    setIsPlaying(false);
    if (currentStepIndex <= 0) {
      handleReset();
      return;
    }
    const targetIdx = currentStepIndex - 1;
    const scenario = SCENARIOS[selectedScenario];

    const newActiveNodes = new Set<string>();
    const newActiveEdges = new Set<string>();
    const newStatuses: Record<string, NodeStatus> = {};
    const newLogs: { id: string; time: string; message: string; type: "info" | "alert" | "success" }[] = [];

    for (let i = 0; i <= targetIdx; i++) {
      const step = scenario.steps[i];
      if (!step) continue;
      newActiveNodes.add(step.nodeId);
      if (step.edgeId) newActiveEdges.add(step.edgeId);
      if (step.edgeIds) {
        for (const eId of step.edgeIds) newActiveEdges.add(eId);
      }
      newStatuses[step.nodeId] = step.highlightStatus || "completed";

      const logType: "info" | "alert" | "success" = step.highlightStatus === "quarantined"
        ? "alert"
        : step.highlightStatus === "completed"
        ? "success"
        : "info";

      newLogs.unshift({
        id: `log-step-${i}`,
        time: `00:${String(i * 2).padStart(2, "0")}.00`,
        message: step.logMessage,
        type: logType,
      });
    }

    setActiveNodeIds(newActiveNodes);
    setActiveEdgeIds(newActiveEdges);
    setNodeStatuses(newStatuses);
    setSelectedNodeId(scenario.steps[targetIdx].nodeId);
    setLogs(newLogs);
    setCurrentStepIndex(targetIdx);
  }, [selectedScenario, currentStepIndex, handleReset]);

  // ESC key and fullscreen navigation listeners (Arrows Left/Right)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isFullscreen) {
        setIsFullscreen(false);
        try {
          if (document.fullscreenElement && document.exitFullscreen) {
            document.exitFullscreen().catch(() => {});
          }
        } catch {}
      } else if (isFullscreen) {
        if (e.key === "ArrowRight") {
          e.preventDefault();
          handleNextStep();
        } else if (e.key === "ArrowLeft") {
          e.preventDefault();
          handlePrevStep();
        }
      }
    };

    const handleFullscreenChange = () => {
      if (!document.fullscreenElement && isFullscreen) {
        setIsFullscreen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    document.addEventListener("fullscreenchange", handleFullscreenChange);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("fullscreenchange", handleFullscreenChange);
    };
  }, [isFullscreen, handleNextStep, handlePrevStep]);

  // Simulation execution loop
  useEffect(() => {
    if (!isPlaying) return;

    const scenario = SCENARIOS[selectedScenario];
    if (currentStepIndex >= scenario.steps.length) {
      setIsPlaying(false);
      return;
    }

    const currentStep = scenario.steps[currentStepIndex];
    if (!currentStep) return;

    // Activate node & edge
    setActiveNodeIds((prev) => new Set([...prev, currentStep.nodeId]));
    if (currentStep.edgeId) {
      setActiveEdgeIds((prev) => new Set([...prev, currentStep.edgeId!]));
    }
    if (currentStep.edgeIds) {
      setActiveEdgeIds((prev) => new Set([...prev, ...currentStep.edgeIds!]));
    }

    // Update node status
    setNodeStatuses((prev) => ({
      ...prev,
      [currentStep.nodeId]: currentStep.highlightStatus || "completed",
    }));

    // Auto-select active node in inspector
    setSelectedNodeId(currentStep.nodeId);

    // Append log
    const now = new Date();
    const timeStr = `${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}.${String(
      Math.floor(now.getMilliseconds() / 10)
    ).padStart(2, "0")}`;

    const logType: "info" | "alert" | "success" = currentStep.highlightStatus === "quarantined"
      ? "alert"
      : currentStep.highlightStatus === "completed"
      ? "success"
      : "info";

    setLogs((prev) => [
      {
        id: `log-${Date.now()}-${Math.random()}`,
        time: timeStr,
        message: currentStep.logMessage,
        type: logType,
      },
      ...prev.slice(0, 49),
    ]);

    // Timer to advance to next step
    const timer = setTimeout(() => {
      setCurrentStepIndex((prev) => prev + 1);
    }, currentStep.durationMs);

    return () => clearTimeout(timer);
  }, [isPlaying, currentStepIndex, selectedScenario]);

  // Start / Play Simulation
  const handlePlay = () => {
    if (currentStepIndex === -1 || currentStepIndex >= SCENARIOS[selectedScenario].steps.length) {
      handleReset();
      setCurrentStepIndex(0);
    }
    setIsPlaying(true);
  };

  const handlePause = () => {
    setIsPlaying(false);
  };

  // Zoom helpers
  const handleZoomIn = () => setScale((s) => Math.min(s + 0.1, 1.4));
  const handleZoomOut = () => setScale((s) => Math.max(s - 0.1, 0.4));
  const handleFitView = () => {
    setScale(0.68);
    setPan({ x: 20, y: 30 });
  };

  // Mouse pan handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    // Only drag on canvas background
    if ((e.target as HTMLElement).closest(".workflow-card")) return;
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  };

  const handleMouseUp = () => setIsDragging(false);

  // Zoom gestures: Two-finger expanding (pinch-to-zoom) or Ctrl/Cmd + wheel
  // Standard two-finger vertical/horizontal scrolling will NOT zoom the canvas, allowing natural page scroll.
  const handleWheel = (e: React.WheelEvent) => {
    if (e.defaultPrevented) return;
    if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      const clampedDelta = Math.max(Math.min(e.deltaY, 60), -60);
      const factor = 1 - clampedDelta * 0.003;
      setScale((prev) => Math.min(Math.max(Number((prev * factor).toFixed(3)), 0.35), 1.5));
    }
  };

  const handleTouchStart = (e: React.TouchEvent) => {
    if (e.touches.length === 2) {
      const t1 = e.touches[0];
      const t2 = e.touches[1];
      touchDistanceRef.current = Math.hypot(t2.clientX - t1.clientX, t2.clientY - t1.clientY);
      initialTouchScaleRef.current = scale;
    }
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    if (e.touches.length === 2 && touchDistanceRef.current !== null && touchDistanceRef.current > 0) {
      const t1 = e.touches[0];
      const t2 = e.touches[1];
      const currentDist = Math.hypot(t2.clientX - t1.clientX, t2.clientY - t1.clientY);
      const ratio = currentDist / touchDistanceRef.current;
      const newScale = Math.min(Math.max(Number((initialTouchScaleRef.current * ratio).toFixed(3)), 0.35), 1.5);
      setScale(newScale);
    }
  };

  const handleTouchEnd = (e: React.TouchEvent) => {
    if (e.touches.length < 2) {
      touchDistanceRef.current = null;
    }
  };

  // Attach non-passive wheel and touch listeners to allow preventDefault during intentional zoom
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    const onNativeWheel = (e: WheelEvent) => {
      // Only zoom if ctrl/meta is active (pinch-to-zoom on trackpad or ctrl + wheel)
      if (e.ctrlKey || e.metaKey) {
        e.preventDefault();
        const clampedDelta = Math.max(Math.min(e.deltaY, 60), -60);
        const factor = 1 - clampedDelta * 0.003;
        setScale((prev) => Math.min(Math.max(Number((prev * factor).toFixed(3)), 0.35), 1.5));
      }
      // If ctrlKey is false: do NOT preventDefault! Let page scroll naturally without disturbing zoom.
    };

    const onNativeTouchMove = (e: TouchEvent) => {
      if (e.touches.length === 2 && touchDistanceRef.current !== null && touchDistanceRef.current > 0) {
        e.preventDefault(); // Prevent native browser page zoom while expanding two fingers over canvas
        const t1 = e.touches[0];
        const t2 = e.touches[1];
        const currentDist = Math.hypot(t2.clientX - t1.clientX, t2.clientY - t1.clientY);
        const ratio = currentDist / touchDistanceRef.current;
        const newScale = Math.min(Math.max(Number((initialTouchScaleRef.current * ratio).toFixed(3)), 0.35), 1.5);
        setScale(newScale);
      }
    };

    el.addEventListener("wheel", onNativeWheel, { passive: false });
    el.addEventListener("touchmove", onNativeTouchMove, { passive: false });

    return () => {
      el.removeEventListener("wheel", onNativeWheel);
      el.removeEventListener("touchmove", onNativeTouchMove);
    };
  }, [isFullscreen]);

  const CARD_WIDTH = 240;
  const CARD_HEIGHT = 92;

  // Compute Direction-Aware Bezier Curve for an Edge
  const calculateEdgePath = (edge: WorkflowEdge) => {
    const fromNode = WORKFLOW_NODES.find((n) => n.id === edge.from);
    const toNode = WORKFLOW_NODES.find((n) => n.id === edge.to);

    if (!fromNode || !toNode) {
      return { path: "", midX: 0, midY: 0, startX: 0, startY: 0, endX: 0, endY: 0, length: 0 };
    }

    const fromCenter = { x: fromNode.x + CARD_WIDTH / 2, y: fromNode.y + CARD_HEIGHT / 2 };
    const toCenter = { x: toNode.x + CARD_WIDTH / 2, y: toNode.y + CARD_HEIGHT / 2 };

    let startX = fromNode.x;
    let startY = fromCenter.y;
    let endX = toNode.x;
    let endY = toCenter.y;

    let path = "";
    let midX = 0;
    let midY = 0;

    // Specific deterministic edge routes for crisp, intentional topology:
    if (edge.id === "e13") {
      // Agent 3 DAST (650, 390) -> Triangulator (650, 580): Clean vertical drop
      startX = fromNode.x + CARD_WIDTH / 2;
      startY = fromNode.y + CARD_HEIGHT;
      endX = toNode.x + CARD_WIDTH / 2;
      endY = toNode.y;
      path = `M ${startX} ${startY} L ${endX} ${endY}`;
      midX = startX;
      midY = (startY + endY) / 2;
    } else if (edge.id === "e7") {
      // Redis Stream (1620, 200) -> Runtime Sensor (1620, 390): Clean vertical drop
      startX = fromNode.x + CARD_WIDTH / 2;
      startY = fromNode.y + CARD_HEIGHT;
      endX = toNode.x + CARD_WIDTH / 2;
      endY = toNode.y;
      path = `M ${startX} ${startY} L ${endX} ${endY}`;
      midX = startX;
      midY = (startY + endY) / 2;
    } else if (edge.id === "e10") {
      // Graduated Policy (2240, 390) -> Containment (1000, 40): Arches across the top margin above all cards
      startX = fromNode.x + CARD_WIDTH / 2;
      startY = fromNode.y;
      endX = toNode.x + CARD_WIDTH;
      endY = toNode.y + CARD_HEIGHT / 2;
      path = `M ${startX} ${startY} C ${startX} 15, ${endX} 15, ${endX} ${endY}`;
      midX = (startX + endX) / 2;
      midY = 16;
    } else if (edge.id === "e14") {
      // Runtime Sensor (1620, 390) -> Triangulator (650, 580): Smooth under-curve through corridor
      startX = fromNode.x;
      startY = fromNode.y + CARD_HEIGHT * 0.75;
      endX = toNode.x + CARD_WIDTH;
      endY = toNode.y + CARD_HEIGHT * 0.45;
      const spanX = startX - endX;
      const cp1x = startX - spanX * 0.4;
      const cp1y = startY + 65;
      const cp2x = endX + spanX * 0.4;
      const cp2y = endY + 15;
      path = `M ${startX} ${startY} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${endX} ${endY}`;
      midX = (startX + endX) / 2;
      midY = (startY + endY) / 2 + 35;
    } else {
      // Standard Left-to-Right
      startX = fromNode.x + CARD_WIDTH;
      startY = fromCenter.y;
      if (fromNode.outputs && fromNode.outputs.length > 1 && edge.fromPort) {
        const port = fromNode.outputs.find((p) => p.id === edge.fromPort);
        if (port && port.offsetPercent !== undefined) {
          startY = fromNode.y + (CARD_HEIGHT * port.offsetPercent) / 100;
        }
      }

      endX = toNode.x;
      endY = toCenter.y;

      const diffY = endY - startY;
      if (Math.abs(diffY) <= 4) {
        // Pure horizontal line: laser straight, zero wave, zero jiggle
        path = `M ${startX} ${startY} L ${endX} ${endY}`;
        midX = (startX + endX) / 2;
        midY = startY;
      } else {
        // Monotonic cubic Bézier curve, curvature strictly bounded by spanX * 0.45 so control points never cross
        const spanX = Math.max(endX - startX, 20);
        const curvature = spanX * 0.45;
        const cp1x = startX + curvature;
        const cp1y = startY;
        const cp2x = endX - curvature;
        const cp2y = endY;
        path = `M ${startX} ${startY} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${endX} ${endY}`;
        midX = (startX + endX) / 2;
        midY = (startY + endY) / 2;
      }
    }

    const approxLength = Math.sqrt((endX - startX) ** 2 + (endY - startY) ** 2);
    return { path, midX, midY, startX, startY, endX, endY, length: Math.max(approxLength, 60) };
  };

  // =========================================================================
  // Canvas Render Helper (Used in both Standard and Fullscreen Modes)
  // =========================================================================
  const renderCanvasElement = (isFull: boolean) => (
    <div
      ref={containerRef}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      onWheel={handleWheel}
      onTouchStart={handleTouchStart}
      onTouchMove={handleTouchMove}
      onTouchEnd={handleTouchEnd}
      onTouchCancel={handleTouchEnd}
      title="Drag to Pan | Expand two fingers or Ctrl + Scroll to Zoom"
      className={
        isFull
          ? "relative w-full h-full overflow-hidden cursor-grab active:cursor-grabbing bg-[#F5F2EB] select-none"
          : "relative w-full h-[680px] rounded-3xl overflow-hidden cursor-grab active:cursor-grabbing border border-[#E0DACF] bg-[#F5F2EB] select-none shadow-sm"
      }
      style={{
        backgroundImage: "radial-gradient(circle, rgba(0, 0, 0, 0.12) 1.5px, transparent 1.5px)",
        backgroundSize: "26px 26px",
      }}
    >
      {/* Canvas Transformation Wrapper */}
      <div
        className="absolute top-0 left-0 origin-top-left transition-transform duration-75 ease-out"
        style={{
          transform: `translate(${pan.x}px, ${pan.y}px) scale(${scale})`,
          width: "3350px",
          height: "850px",
        }}
      >
        {/* SVG Connecting Edges Layer */}
        <svg className="absolute top-0 left-0 w-full h-full pointer-events-none z-0">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M 0 1 L 9 5 L 0 9 z" fill="#111111" />
            </marker>
            <marker id="arrow-active" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto">
              <path d="M 0 1 L 9 5 L 0 9 z" fill="#000000" />
            </marker>
          </defs>

          {WORKFLOW_EDGES.map((edge) => {
            const { path, midX, midY, length } = calculateEdgePath(edge);
            if (!path) return null;

            const isActive = activeEdgeIds.has(edge.id);
            // Constant visual pace across all edge lengths: ~180 px/sec
            const particleDuration = Math.max(1.2, Math.min(length / 180, 4.0));

            return (
              <g key={edge.id} className="transition-all duration-300">
                {/* Background Wire (Static) */}
                <path
                  d={path}
                  fill="none"
                  stroke={isActive ? "#000000" : "#D0CAC0"}
                  strokeWidth={isActive ? 2.8 : 2}
                  markerEnd="url(#arrow)"
                />

                {/* Active Animated Laser Wire */}
                {isActive && (
                  <path
                    d={path}
                    fill="none"
                    stroke="#000000"
                    strokeWidth={3}
                    strokeDasharray="8 6"
                  >
                    <animate
                      attributeName="stroke-dashoffset"
                      values="28;0"
                      dur="0.8s"
                      repeatCount="indefinite"
                    />
                  </path>
                )}

                {/* Moving Energy Particle during Active Play */}
                {isActive && (
                  <circle r="4.5" fill="#000000">
                    <animateMotion path={path} dur={`${particleDuration.toFixed(2)}s`} repeatCount="indefinite" />
                  </circle>
                )}

                {/* Edge Label (e.g. Risk >= 80, P >= 0.99) */}
                {edge.label && (() => {
                  const labelWidth = Math.max(edge.label.length * 7.5 + 22, 85);
                  // Vertical offset to ensure labels never overlap branching wires
                  const yOffset =
                    edge.id === "e20"
                      ? -18
                      : edge.id === "e21"
                      ? 18
                      : edge.id === "e3"
                      ? -16
                      : edge.id === "e4"
                      ? 16
                      : edge.id === "e10"
                      ? -12
                      : -12;
                  return (
                    <g transform={`translate(${midX}, ${midY + yOffset})`}>
                      <rect
                        x={-labelWidth / 2}
                        y="-10"
                        width={labelWidth}
                        height="20"
                        rx="10"
                        fill="#FFFFFF"
                        stroke="#D5D0C7"
                        strokeWidth="1"
                        className="shadow-sm"
                      />
                      <text
                        x="0"
                        y="3.5"
                        textAnchor="middle"
                        fill="#111111"
                        fontSize="10"
                        fontFamily="monospace"
                        fontWeight="bold"
                      >
                        {edge.label}
                      </text>
                    </g>
                  );
                })()}
              </g>
            );
          })}
        </svg>

        {/* Node Cards Layer */}
        <div className="absolute top-0 left-0 w-full h-full z-10 pointer-events-auto">
          {WORKFLOW_NODES.map((node) => {
            const isSelected = selectedNodeId === node.id;
            const isActive = activeNodeIds.has(node.id);
            const status = nodeStatuses[node.id] || "idle";

            return (
              <div
                key={node.id}
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedNodeId(node.id);
                  if (isFullscreen) {
                    setIsSidePanelOpen(true);
                    setSidePanelTab("inspector");
                  }
                }}
                className={`workflow-card absolute w-[240px] rounded-2xl p-3.5 transition-all duration-200 select-none cursor-pointer bg-white ${
                  isSelected
                    ? "border-2 border-black shadow-xl ring-4 ring-black/10"
                    : isActive
                    ? "border-2 border-black shadow-lg"
                    : "border border-[#D5D0C7] hover:border-black shadow-sm"
                }`}
                style={{
                  left: `${node.x}px`,
                  top: `${node.y}px`,
                }}
              >
                {/* Left Input Port Handle */}
                {node.hasInput !== false && (
                  <div
                    className="absolute -left-2 top-1/2 -translate-y-1/2 w-4 h-4 rounded-full bg-white border-2 border-black flex items-center justify-center transition group-hover:scale-110 shadow-sm"
                    title="Input Connection Port"
                  >
                    <div className="w-1.5 h-1.5 rounded-full bg-black" />
                  </div>
                )}

                {/* Right Output Port Handles */}
                {node.outputs &&
                  node.outputs.map((out) => {
                    const topPercent = out.offsetPercent !== undefined ? out.offsetPercent : 50;
                    return (
                      <div
                        key={out.id}
                        className="absolute -right-2 w-4 h-4 rounded-full bg-white border-2 border-black flex items-center justify-center transition hover:scale-110 shadow-sm"
                        style={{ top: `${topPercent}%`, transform: "translateY(-50%)" }}
                        title={out.label || "Output Connection Port"}
                      >
                        <div className="w-1.5 h-1.5 rounded-full bg-black" />
                      </div>
                    );
                  })}

                {/* Top Vertical Port Handle */}
                {["node_runtime_sensor", "node_triangulator", "node_graduated_policy"].includes(node.id) && (
                  <div
                    className="absolute -top-2 left-1/2 -translate-x-1/2 w-4 h-4 rounded-full bg-white border-2 border-black flex items-center justify-center shadow-sm"
                    title="Vertical Connection Port"
                  >
                    <div className="w-1.5 h-1.5 rounded-full bg-black" />
                  </div>
                )}

                {/* Bottom Vertical Port Handle */}
                {["node_redis_stream", "node_dast_prober"].includes(node.id) && (
                  <div
                    className="absolute -bottom-2 left-1/2 -translate-x-1/2 w-4 h-4 rounded-full bg-white border-2 border-black flex items-center justify-center shadow-sm"
                    title="Vertical Connection Port"
                  >
                    <div className="w-1.5 h-1.5 rounded-full bg-black" />
                  </div>
                )}

                {/* Right Feedback Port for Quarantine */}
                {node.id === "node_containment" && (
                  <div
                    className="absolute -right-2 top-1/2 -translate-y-1/2 w-4 h-4 rounded-full bg-white border-2 border-black flex items-center justify-center shadow-sm"
                    title="Policy Update Port"
                  >
                    <div className="w-1.5 h-1.5 rounded-full bg-black" />
                  </div>
                )}

                {/* Card Content Header */}
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span
                    className={`px-2 py-0.5 rounded-full text-[9px] font-mono font-bold uppercase tracking-wider ${node.colorScheme.badgeBg} ${node.colorScheme.badgeText} border border-[#D5D0C7]`}
                  >
                    {node.agentLabel || node.category}
                  </span>

                  {/* Status Indicator */}
                  {status === "completed" && (
                    <span className="flex items-center gap-1 text-[10px] font-mono font-bold text-black">
                      <CheckCircle2 className="w-3 h-3 text-black" />
                      <span>Done</span>
                    </span>
                  )}
                  {status === "quarantined" && (
                    <span className="flex items-center gap-1 text-[10px] font-mono font-bold text-white bg-black px-1.5 py-0.2 rounded-full">
                      <ShieldAlert className="w-3 h-3 text-white" />
                      <span>Dropped</span>
                    </span>
                  )}
                  {status === "idle" && (
                    <span className="w-2 h-2 rounded-full bg-[#CCCCCC]" />
                  )}
                </div>

                {/* Node Title & Subtitle */}
                <div className="flex items-start gap-2.5">
                  <div
                    className={`p-2 rounded-xl flex-shrink-0 border ${node.colorScheme.iconBg} ${node.colorScheme.iconColor}`}
                  >
                    <NodeIcon name={node.icon} className="w-4 h-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h4 className="text-xs font-bold text-black truncate leading-tight">
                      {node.title}
                    </h4>
                    <p className="text-[10px] text-[#555555] font-mono truncate mt-0.5">
                      {node.subtitle}
                    </p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Floating Canvas Legend */}
      <div className="absolute bottom-4 left-4 z-20 pointer-events-none">
        <div className="flex items-center gap-3 px-3 py-1.5 rounded-full bg-white/95 border border-[#E0DACF] shadow-sm text-[11px] font-mono text-black font-semibold">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            Fast-Path &lt; 2ms
          </span>
          <span className="w-px h-3 bg-[#E0DACF]" />
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#888888]" />
            Multi-Agent Stream (12 Agents)
          </span>
          <span className="w-px h-3 bg-[#E0DACF]" />
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-white border border-black" />
            Verified Resolution
          </span>
        </div>
      </div>

      {/* Floating Gesture Hint */}
      <div className="absolute bottom-4 right-4 z-20 pointer-events-none hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-white/95 border border-[#E0DACF] shadow-sm text-[11px] font-mono text-[#555555] font-medium">
        <span>Expand 2 fingers or Ctrl + Scroll to zoom</span>
      </div>
    </div>
  );

  // =========================================================================
  // Full-Screen Side Panel Component
  // =========================================================================
  const renderFullScreenSidePanel = () => (
    <div className="w-[420px] max-w-[90vw] bg-white border-l border-[#E0DACF] flex flex-col h-full shadow-2xl z-20 flex-shrink-0">
      {/* Side Panel Header */}
      <div className="p-3.5 border-b border-[#E0DACF] flex items-center justify-between bg-[#FAF8F5]">
        <div className="flex items-center gap-2">
          <SlidersHorizontal className="w-4 h-4 text-black" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-black">
            Workflow Options &amp; Inspector
          </h3>
        </div>
        <button
          onClick={() => setIsSidePanelOpen(false)}
          className="p-1.5 rounded-xl hover:bg-black/10 text-black transition"
          title="Close Side Panel"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Side Panel Tab Switcher */}
      <div className="flex border-b border-[#E0DACF] bg-white text-xs font-bold flex-shrink-0">
        <button
          onClick={() => setSidePanelTab("inspector")}
          className={`flex-1 py-2.5 px-2 flex items-center justify-center gap-1.5 border-b-2 transition ${
            sidePanelTab === "inspector"
              ? "border-black text-black bg-[#FAF8F5]"
              : "border-transparent text-[#666666] hover:text-black"
          }`}
        >
          <Info className="w-3.5 h-3.5" />
          <span>Inspector</span>
        </button>

        <button
          onClick={() => setSidePanelTab("scenarios")}
          className={`flex-1 py-2.5 px-2 flex items-center justify-center gap-1.5 border-b-2 transition ${
            sidePanelTab === "scenarios"
              ? "border-black text-black bg-[#FAF8F5]"
              : "border-transparent text-[#666666] hover:text-black"
          }`}
        >
          <SlidersHorizontal className="w-3.5 h-3.5" />
          <span>Options</span>
        </button>

        <button
          onClick={() => setSidePanelTab("logs")}
          className={`flex-1 py-2.5 px-2 flex items-center justify-center gap-1.5 border-b-2 transition ${
            sidePanelTab === "logs"
              ? "border-black text-black bg-[#FAF8F5]"
              : "border-transparent text-[#666666] hover:text-black"
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>Live Logs</span>
          {logs.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full text-[9px] bg-black text-white font-mono">
              {logs.length}
            </span>
          )}
        </button>
      </div>

      {/* Tab 1: Inspector Tab Content */}
      {sidePanelTab === "inspector" && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div className="flex items-start gap-3 pb-3 border-b border-[#E0DACF]">
            <div
              className={`p-2.5 rounded-2xl border ${selectedNode.colorScheme.iconBg} ${selectedNode.colorScheme.iconColor} flex-shrink-0`}
            >
              <NodeIcon name={selectedNode.icon} className="w-5 h-5" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-1.5 mb-1">
                <span className="text-[9px] font-bold uppercase tracking-wider text-[#666666]">
                  {selectedNode.agentLabel ? "Agent & Node" : "Pipeline Node"}
                </span>
                <span className="text-[9px] font-mono px-2 py-0.5 rounded-full bg-[#EAE5DE] text-black border border-[#D5D0C7] font-bold">
                  {selectedNode.category}
                </span>
              </div>
              <h4 className="text-sm font-bold text-black leading-tight">
                {selectedNode.title}
              </h4>
              <p className="text-[11px] text-[#555555] font-mono mt-0.5">
                {selectedNode.subtitle}
              </p>
            </div>
          </div>

          <button
            onClick={() => {
              setSelectedScenario("FULL");
              handlePlay();
            }}
            className="w-full btn-dark py-2 px-3 text-xs font-bold flex items-center justify-center gap-2 shadow-sm rounded-xl"
          >
            <Play className="w-3.5 h-3.5 fill-white" />
            <span>Simulate Flow Through This Node</span>
          </button>

          <div>
            <h5 className="text-[10px] font-bold uppercase text-[#666666] tracking-wider mb-1">
              Description
            </h5>
            <p className="text-xs text-[#333333] leading-relaxed">
              {selectedNode.description}
            </p>
          </div>

          {/* Operational Metrics & SLOs */}
          <div className="space-y-2">
            <h5 className="text-[10px] font-bold uppercase text-black tracking-wider">
              Operational Metrics &amp; SLOs
            </h5>
            <div className="space-y-1.5">
              {selectedNode.metrics.map((m, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded-xl bg-[#FAF8F5] border border-[#E0DACF] flex items-center justify-between text-xs"
                >
                  <span className="text-[#444444] font-medium text-[11px]">{m.label}</span>
                  <span className="font-bold font-mono text-black">{m.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Incoming & Outgoing Specifications */}
          <div className="space-y-3">
            <div className="p-3 rounded-xl bg-[#FAF8F5] border border-[#E0DACF]">
              <span className="text-[10px] font-bold uppercase text-black block mb-2 tracking-wider">
                Incoming Context (Inputs)
              </span>
              <ul className="space-y-1.5">
                {selectedNode.inputsDesc.map((item, i) => (
                  <li key={i} className="text-[11px] text-[#222222] font-mono flex items-center gap-2">
                    <ArrowRight className="w-3 h-3 text-black flex-shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="p-3 rounded-xl bg-[#FAF8F5] border border-[#E0DACF]">
              <span className="text-[10px] font-bold uppercase text-black block mb-2 tracking-wider">
                Outgoing Artifacts (Outputs)
              </span>
              <ul className="space-y-1.5">
                {selectedNode.outputsDesc.map((item, i) => (
                  <li key={i} className="text-[11px] text-[#222222] font-mono flex items-center gap-2">
                    <ArrowRight className="w-3 h-3 text-black flex-shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Python Code Snippet */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold uppercase text-black tracking-wider">
                Technical Implementation
              </span>
              <Terminal className="w-3.5 h-3.5 text-black" />
            </div>
            {selectedNode.codeSnippet ? (
              <pre className="p-3 rounded-xl bg-[#FAF8F5] border border-[#E0DACF] text-[10px] font-mono text-black overflow-x-auto whitespace-pre leading-relaxed max-h-[220px] overflow-y-auto">
                <code>{selectedNode.codeSnippet}</code>
              </pre>
            ) : (
              <div className="p-3 rounded-xl bg-[#FAF8F5] border border-[#E0DACF] text-xs text-[#666666] font-mono">
                No custom logic snippet required for this node.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Scenario Options Content */}
      {sidePanelTab === "scenarios" && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div>
            <h5 className="text-[10px] font-bold uppercase text-black tracking-wider mb-2">
              Playback Speed
            </h5>
            <div className="grid grid-cols-3 gap-2">
              {[0.5, 1, 2].map((spd) => (
                <button
                  key={spd}
                  onClick={() => setPlaybackSpeed(spd)}
                  className={`py-1.5 text-xs font-mono font-bold rounded-xl border transition ${
                    playbackSpeed === spd
                      ? "bg-black text-white border-black shadow-sm"
                      : "bg-[#FAF8F5] text-black border-[#E0DACF] hover:bg-white"
                  }`}
                >
                  {spd}x Speed
                </button>
              ))}
            </div>
          </div>

          <div>
            <h5 className="text-[10px] font-bold uppercase text-black tracking-wider mb-2">
              Simulation Scenario Presets
            </h5>
            <div className="space-y-2.5">
              {(
                [
                  { key: "FULL", label: "Master Defense Flow", icon: <Sparkles className="w-4 h-4 text-amber-500" /> },
                  { key: "SQLI_ATTACK", label: "SQLi Attack Gate", icon: <Flame className="w-4 h-4 text-rose-500" /> },
                  { key: "LEGIT_ALICE", label: "Legitimate (Alice NAT)", icon: <UserCheck className="w-4 h-4 text-emerald-500" /> },
                  { key: "TRIANGULATION", label: "Bayesian Triangulation", icon: <Cpu className="w-4 h-4 text-cyan-500" /> },
                  { key: "AST_REMEDIATION", label: "AST Auto-Remediation", icon: <Wrench className="w-4 h-4 text-purple-500" /> },
                ] as const
              ).map((item) => {
                const active = selectedScenario === item.key;
                const scenario = SCENARIOS[item.key];
                return (
                  <div
                    key={item.key}
                    onClick={() => handleSelectScenario(item.key)}
                    className={`p-3.5 rounded-2xl border cursor-pointer transition select-none ${
                      active
                        ? "border-black bg-[#FAF8F5] shadow-md ring-2 ring-black/10"
                        : "border-[#E0DACF] bg-white hover:border-black shadow-sm"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2">
                        {item.icon}
                        <h6 className="text-xs font-bold text-black">{scenario.name}</h6>
                      </div>
                      {active && (
                        <span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-black text-white">
                          Active
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-[#555555] leading-relaxed line-clamp-2 mt-1">
                      {scenario.description}
                    </p>
                    <div className="mt-2.5 pt-2 border-t border-[#E0DACF]/60 flex items-center justify-between text-[10px] font-mono">
                      <span className="text-[#666666]">{scenario.steps.length} sequential steps</span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleSelectScenario(item.key);
                          handlePlay();
                        }}
                        className="px-2.5 py-1 rounded-lg bg-black text-white font-bold flex items-center gap-1 hover:bg-[#333333] transition"
                      >
                        <Play className="w-2.5 h-2.5 fill-white" />
                        <span>Run Now</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Live Logs Content */}
      {sidePanelTab === "logs" && (
        <div className="flex-1 overflow-y-auto p-4 flex flex-col justify-between">
          <div className="space-y-2">
            <div className="flex items-center justify-between pb-2 border-b border-[#E0DACF]">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#666666]">
                Trace Events Stream
              </span>
              <button
                onClick={() => setLogs([])}
                className="text-[10px] font-mono text-[#666666] hover:text-black font-bold"
              >
                Clear Stream
              </button>
            </div>

            {logs.length === 0 ? (
              <div className="py-12 text-center text-[#666666] text-xs font-mono">
                <span>No active events. Click "Simulate" to stream live data.</span>
              </div>
            ) : (
              logs.map((log) => (
                <div
                  key={log.id}
                  className={`p-2.5 rounded-xl border text-xs font-mono ${
                    log.type === "alert"
                      ? "bg-black text-white border-black font-bold"
                      : log.type === "success"
                      ? "bg-[#FAF8F5] border-black text-black font-semibold"
                      : "bg-[#FAF8F5] border-[#E0DACF] text-[#222222]"
                  }`}
                >
                  <div className="flex items-center justify-between text-[10px] opacity-70 mb-1">
                    <span>{log.time}</span>
                    <span className="uppercase">{log.type}</span>
                  </div>
                  <div>{log.message}</div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );

  // =========================================================================
  // Primary Return: Fullscreen Overlay vs Standard Responsive Layout
  // =========================================================================
  if (isFullscreen) {
    return (
      <div className="fixed inset-0 z-50 bg-[#F5F2EB] flex flex-col w-screen h-screen overflow-hidden select-none">
        {/* Full-Screen Top Navigation Bar */}
        <div className="h-14 bg-white border-b border-[#E0DACF] px-4 flex items-center justify-between shadow-sm z-30 flex-shrink-0">
          {/* Left: Branding & Active Scenario */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 pr-3 border-r border-[#E0DACF]">
              <div className="p-1.5 rounded-xl bg-black text-white">
                <Workflow className="w-4 h-4" />
              </div>
              <div>
                <span className="text-xs font-bold text-black uppercase tracking-wider block leading-tight">
                  CyberShield Workflow
                </span>
                <span className="text-[10px] text-[#666666] font-mono leading-tight">
                  Full Screen Interactive Canvas
                </span>
              </div>
            </div>
            <div className="hidden lg:flex items-center gap-2">
              <span className="text-[11px] font-mono font-bold text-black px-2.5 py-1 rounded-full bg-[#FAF8F5] border border-[#E0DACF] flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <span>{SCENARIOS[selectedScenario].name}</span>
              </span>
            </div>
          </div>

          {/* Center: Play, Reset, Zoom [- % +] */}
          <div className="flex items-center gap-2 flex-shrink-0">
            {isPlaying ? (
              <button
                onClick={handlePause}
                className="h-9 px-4 rounded-full bg-black text-white hover:bg-[#222222] text-xs font-bold flex items-center gap-1.5 shadow-sm whitespace-nowrap flex-shrink-0 cursor-pointer"
              >
                <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                <span>Pause Flow</span>
              </button>
            ) : (
              <button
                onClick={handlePlay}
                className="h-9 px-4 rounded-full bg-black text-white hover:bg-[#222222] text-xs font-bold flex items-center gap-1.5 shadow-sm whitespace-nowrap flex-shrink-0 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-white" />
                <span>Simulate Flow</span>
              </button>
            )}

            <button
              onClick={handleReset}
              className="w-9 h-9 rounded-full bg-[#EAE5DE] hover:bg-white text-black border border-[#D5D0C7] transition flex items-center justify-center flex-shrink-0"
              title="Reset Canvas"
            >
              <RotateCcw className="w-3.5 h-3.5 text-black" />
            </button>

            {/* Step-by-Step Interactive Navigation (Exclusive to Fullscreen Mode) */}
            <div className="flex items-center gap-1 bg-[#FAF8F5] border border-[#E0DACF] rounded-full p-0.5 h-9 flex-shrink-0">
              <button
                onClick={handlePrevStep}
                disabled={currentStepIndex <= 0}
                className="w-7 h-7 rounded-full hover:bg-white text-black transition flex items-center justify-center disabled:opacity-25 disabled:hover:bg-transparent flex-shrink-0 cursor-pointer disabled:cursor-not-allowed"
                title="Previous Step (Left Arrow)"
              >
                <ChevronLeft className="w-3.5 h-3.5 text-black" />
              </button>

              <span className="text-[11px] font-mono font-bold text-black px-2 select-none whitespace-nowrap">
                Step {currentStepIndex < 0 ? 0 : currentStepIndex + 1} / {SCENARIOS[selectedScenario].steps.length}
              </span>

              <button
                onClick={handleNextStep}
                disabled={currentStepIndex >= SCENARIOS[selectedScenario].steps.length - 1}
                className="h-7 px-3 rounded-full bg-black text-white hover:bg-[#222222] transition flex items-center gap-1 text-[11px] font-bold disabled:opacity-40 disabled:hover:bg-black flex-shrink-0 cursor-pointer disabled:cursor-not-allowed shadow-xs"
                title="Next Step (Right Arrow)"
              >
                <span>Next</span>
                <ChevronRight className="w-3 h-3 text-white" />
              </button>
            </div>

            {/* Zoom Controls: [- % +] */}
            <div className="flex items-center gap-0.5 bg-[#FAF8F5] border border-[#E0DACF] rounded-full p-0.5 h-9 flex-shrink-0">
              <button
                onClick={handleZoomOut}
                className="w-7 h-7 rounded-full hover:bg-white text-black transition flex items-center justify-center flex-shrink-0"
                title="Zoom Out"
              >
                <ZoomOut className="w-3 h-3 text-black" />
              </button>
              <span className="text-xs font-mono font-bold text-black px-1.5 min-w-[38px] text-center select-none">
                {Math.round(scale * 100)}%
              </span>
              <button
                onClick={handleZoomIn}
                className="w-7 h-7 rounded-full hover:bg-white text-black transition flex items-center justify-center flex-shrink-0"
                title="Zoom In"
              >
                <ZoomIn className="w-3 h-3 text-black" />
              </button>
            </div>
          </div>

          {/* Right: Side Panel Toggle & Exit Full Screen */}
          <div className="flex items-center gap-2 flex-shrink-0">
            <button
              onClick={() => setIsSidePanelOpen(!isSidePanelOpen)}
              className={`h-9 px-4 rounded-full border text-xs font-bold flex items-center gap-1.5 transition whitespace-nowrap flex-shrink-0 cursor-pointer ${
                isSidePanelOpen
                  ? "bg-black text-white border-black shadow-sm"
                  : "bg-[#EAE5DE] hover:bg-white text-black border-[#D5D0C7]"
              }`}
              title={isSidePanelOpen ? "Hide Side Panel" : "Show Side Panel"}
            >
              {isSidePanelOpen ? <PanelRightClose className="w-3.5 h-3.5" /> : <PanelRightOpen className="w-3.5 h-3.5" />}
              <span className="hidden sm:inline">Options &amp; Inspector</span>
            </button>

            <button
              onClick={handleToggleFullscreen}
              className="h-9 px-4 rounded-full bg-black text-white hover:bg-[#222222] text-xs font-bold flex items-center gap-1.5 shadow-sm whitespace-nowrap flex-shrink-0 cursor-pointer"
              title="Exit Full Screen View (Esc)"
            >
              <Minimize2 className="w-3.5 h-3.5" />
              <span>Exit Full Screen</span>
              <kbd className="hidden sm:inline text-[9px] font-mono bg-white/20 px-1 py-0.5 rounded text-white/90 ml-1">
                Esc
              </kbd>
            </button>
          </div>
        </div>

        {/* Full-Screen Main Workspace: Canvas + Side Panel */}
        <div className="flex-1 flex overflow-hidden relative">
          <div className="flex-1 h-full relative overflow-hidden bg-[#F5F2EB]">
            {renderCanvasElement(true)}

            {/* Floating button to open panel if closed */}
            {!isSidePanelOpen && (
              <button
                onClick={() => setIsSidePanelOpen(true)}
                className="absolute top-4 right-4 z-20 btn-dark px-3 py-2 text-xs font-bold flex items-center gap-2 shadow-lg rounded-xl"
                title="Open Workflow Options & Inspector Panel"
              >
                <PanelRightOpen className="w-4 h-4" />
                <span>Options &amp; Inspector</span>
              </button>
            )}
          </div>

          {/* Collapsible Full-Screen Side Panel */}
          {isSidePanelOpen && renderFullScreenSidePanel()}
        </div>
      </div>
    );
  }

  // =========================================================================
  // Standard Normal Page View (Canvas with Inspector Below)
  // =========================================================================
  return (
    <div className="space-y-4">
      {/* Top Controls & Scenario Selection Toolbar */}
      <div className="clean-card p-4 sm:p-5 border border-[#E0DACF] bg-white flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        {/* Left Section: Branding & Scenario Presets */}
        <div className="flex flex-col lg:flex-row lg:items-center gap-3 xl:gap-4 min-w-0">
          <div className="flex items-center gap-2.5 pr-0 lg:pr-3 lg:border-r border-[#E0DACF] flex-shrink-0">
            <span className="p-2 rounded-xl bg-[#EAE5DE] border border-[#D5D0C7] text-black flex-shrink-0">
              <Workflow className="w-5 h-5 text-black" />
            </span>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <h2 className="text-sm sm:text-base font-bold text-black tracking-tight whitespace-nowrap">
                  Interactive Workflow Pipeline
                </h2>
                <span className="clean-pill text-[10px] py-0.5 px-2 font-mono flex-shrink-0">
                  Node Canvas
                </span>
              </div>
              <p className="text-[11px] sm:text-xs text-[#555555] truncate mt-0.5">
                Visual workflow demonstrating multi-agent defense lifecycle and sub-2ms request gating.
              </p>
            </div>
          </div>

          {/* Scenario Preset Selector (Responsive horizontally scrollable pill container) */}
          <div className="flex items-center gap-1.5 p-1 rounded-2xl bg-[#FAF8F5] border border-[#E0DACF] overflow-x-auto max-w-full scrollbar-none py-1">
            {(
              [
                { key: "FULL", label: "Master Flow", icon: <Sparkles className="w-3.5 h-3.5 text-amber-500" /> },
                { key: "SQLI_ATTACK", label: "SQLi Attack Gate", icon: <Flame className="w-3.5 h-3.5 text-rose-500" /> },
                { key: "LEGIT_ALICE", label: "Legitimate (NAT)", icon: <UserCheck className="w-3.5 h-3.5 text-emerald-500" /> },
                { key: "TRIANGULATION", label: "Bayesian P(V)", icon: <Cpu className="w-3.5 h-3.5 text-cyan-500" /> },
                { key: "AST_REMEDIATION", label: "AST Repair", icon: <Wrench className="w-3.5 h-3.5 text-purple-500" /> },
              ] as const
            ).map((item) => {
              const active = selectedScenario === item.key;
              return (
                <button
                  key={item.key}
                  onClick={() => handleSelectScenario(item.key)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold whitespace-nowrap transition flex-shrink-0 cursor-pointer ${
                    active
                      ? "bg-black text-white shadow-sm"
                      : "text-[#222222] hover:text-black hover:bg-white/60"
                  }`}
                >
                  {item.icon}
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right Section: Action Buttons (Simulate Flow, Reset, Zoom [- % +], Full Screen) */}
        <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap justify-start xl:justify-end flex-shrink-0">
          {/* Simulate Flow Button */}
          {isPlaying ? (
            <button
              onClick={handlePause}
              className="h-10 px-5 rounded-full bg-black text-white hover:bg-[#222222] transition text-xs font-bold flex items-center justify-center gap-2 shadow-sm whitespace-nowrap flex-shrink-0 cursor-pointer"
            >
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
              <span>Pause Flow</span>
            </button>
          ) : (
            <button
              onClick={handlePlay}
              className="h-10 px-5 rounded-full bg-black text-white hover:bg-[#222222] transition text-xs font-bold flex items-center justify-center gap-2 shadow-sm whitespace-nowrap flex-shrink-0 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              <span>Simulate Flow</span>
            </button>
          )}

          {/* Reset Button */}
          <button
            onClick={handleReset}
            className="w-10 h-10 rounded-full bg-[#EAE5DE] hover:bg-white text-black border border-[#D5D0C7] transition flex items-center justify-center flex-shrink-0 shadow-sm cursor-pointer"
            title="Reset Canvas and Simulation"
          >
            <RotateCcw className="w-4 h-4 text-black" />
          </button>

          {/* Zoom Controls: [- % +] (Removed the redundant/marked Fit button) */}
          <div className="flex items-center gap-0.5 bg-[#FAF8F5] border border-[#E0DACF] rounded-full p-1 h-10 flex-shrink-0">
            <button
              onClick={handleZoomOut}
              className="w-8 h-8 rounded-full hover:bg-white text-black transition flex items-center justify-center flex-shrink-0"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5 text-black" />
            </button>
            <span className="text-xs font-mono font-bold text-black px-1.5 min-w-[42px] text-center select-none">
              {Math.round(scale * 100)}%
            </span>
            <button
              onClick={handleZoomIn}
              className="w-8 h-8 rounded-full hover:bg-white text-black transition flex items-center justify-center flex-shrink-0"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5 text-black" />
            </button>
          </div>

          {/* Full Screen Button */}
          <button
            onClick={handleToggleFullscreen}
            className="h-10 px-5 rounded-full bg-black text-white hover:bg-[#222222] transition text-xs font-bold flex items-center justify-center gap-2 shadow-sm whitespace-nowrap flex-shrink-0 cursor-pointer"
            title="Open Workflow in Full Screen View"
          >
            <Maximize2 className="w-3.5 h-3.5 text-white" />
            <span>Full Screen</span>
          </button>
        </div>
      </div>

      {/* Main Workflow Workspace (Full-Width Canvas) */}
      <div className="relative w-full">
        {renderCanvasElement(false)}
      </div>

      {/* AGENT & NODE INSPECTOR (PLACED BELOW WORKFLOW CANVAS) */}
      <div className="clean-card p-5 sm:p-6 border border-[#E0DACF] bg-white shadow-sm space-y-4">
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-[#E0DACF] gap-3">
          <div className="flex items-start sm:items-center gap-3.5">
            <div
              className={`p-2.5 rounded-2xl border ${selectedNode.colorScheme.iconBg} ${selectedNode.colorScheme.iconColor} flex-shrink-0`}
            >
              <NodeIcon name={selectedNode.icon} className="w-5 h-5" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <span className="text-[10px] font-bold uppercase tracking-wider text-[#666666]">
                  {selectedNode.agentLabel ? "Agent & Node Inspector" : "Node Inspector"}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#EAE5DE] text-black border border-[#D5D0C7] font-bold">
                  {selectedNode.category}
                </span>
                {selectedNode.agentLabel && (
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${selectedNode.colorScheme.badgeBg} ${selectedNode.colorScheme.badgeText}`}>
                    {selectedNode.agentLabel}
                  </span>
                )}
              </div>
              <h3 className="text-base sm:text-lg font-bold text-black leading-tight">
                {selectedNode.title}
              </h3>
              <p className="text-xs text-[#555555] font-medium mt-0.5">
                {selectedNode.subtitle}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-shrink-0">
            <button
              onClick={() => {
                setSelectedScenario("FULL");
                handlePlay();
              }}
              className="btn-dark py-2 px-4 text-xs font-bold flex items-center justify-center gap-2 shadow-sm"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              <span>Simulate Flow Through This Node</span>
            </button>
          </div>
        </div>

        {/* Description */}
        <p className="text-xs sm:text-sm text-[#333333] leading-relaxed">
          {selectedNode.description}
        </p>

        {/* 3-Column Responsive Grid for Details */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pt-1">
          {/* Column 1: Operational Metrics & SLOs */}
          <div className="space-y-2.5">
            <h4 className="text-[11px] font-bold uppercase text-black tracking-wider">
              Operational Metrics &amp; SLOs
            </h4>
            <div className="grid grid-cols-1 gap-2">
              {selectedNode.metrics.map((m, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-xl bg-[#FAF8F5] border border-[#E0DACF] flex items-center justify-between text-xs"
                >
                  <span className="text-[#444444] font-medium text-[11px]">{m.label}</span>
                  <span className="font-bold font-mono text-black">{m.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Column 2: Context Specifications (Inputs & Outputs) */}
          <div className="space-y-3">
            <div className="p-3.5 rounded-2xl bg-[#FAF8F5] border border-[#E0DACF]">
              <span className="text-[10px] font-bold uppercase text-black block mb-2 tracking-wider">
                Incoming Context (Inputs)
              </span>
              <ul className="space-y-1.5">
                {selectedNode.inputsDesc.map((item, i) => (
                  <li key={i} className="text-[11px] text-[#222222] font-mono flex items-center gap-2">
                    <ArrowRight className="w-3 h-3 text-black flex-shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="p-3.5 rounded-2xl bg-[#FAF8F5] border border-[#E0DACF]">
              <span className="text-[10px] font-bold uppercase text-black block mb-2 tracking-wider">
                Outgoing Artifacts (Outputs)
              </span>
              <ul className="space-y-1.5">
                {selectedNode.outputsDesc.map((item, i) => (
                  <li key={i} className="text-[11px] text-[#222222] font-mono flex items-center gap-2">
                    <ArrowRight className="w-3 h-3 text-black flex-shrink-0" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Column 3: Technical Implementation (Code snippet) */}
          <div className="md:col-span-2 lg:col-span-1 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold uppercase text-black tracking-wider">
                Technical Implementation
              </span>
              <Terminal className="w-3.5 h-3.5 text-black" />
            </div>
            {selectedNode.codeSnippet ? (
              <pre className="p-3.5 rounded-xl bg-[#FAF8F5] border border-[#E0DACF] text-[11px] font-mono text-black overflow-x-auto whitespace-pre leading-relaxed max-h-[220px] overflow-y-auto">
                <code>{selectedNode.codeSnippet}</code>
              </pre>
            ) : (
              <div className="p-4 rounded-xl bg-[#FAF8F5] border border-[#E0DACF] text-xs text-[#666666] font-mono">
                No custom logic snippet required for this node.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* BOTTOM LIVE LOG TICKER (REAL-TIME PIPELINE TRACE STREAM) */}
      <div className="clean-card p-4 border border-[#E0DACF] bg-white">
        <div className="flex items-center justify-between pb-2 border-b border-[#E0DACF] mb-2">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-black animate-pulse" />
            <h3 className="text-xs font-bold text-black font-mono uppercase tracking-wider">
              Real-Time Workflow Event Ticker
            </h3>
          </div>
          <span className="text-[11px] font-mono font-bold text-[#555555]">
            {logs.length} trace events recorded
          </span>
        </div>

        <div className="h-28 overflow-y-auto space-y-1.5 font-mono text-xs">
          {logs.length === 0 ? (
            <div className="h-full flex items-center justify-center text-[#555555] text-xs">
              <span>Click "Simulate Flow" above to stream live data through the node pipeline.</span>
            </div>
          ) : (
            logs.map((log) => (
              <div
                key={log.id}
                className={`p-2 rounded-xl flex items-start gap-2.5 border text-xs ${
                  log.type === "alert"
                    ? "bg-black text-white border-black font-bold"
                    : log.type === "success"
                    ? "bg-[#FAF8F5] border-black text-black font-semibold"
                    : "bg-[#FAF8F5] border-[#E0DACF] text-[#222222]"
                }`}
              >
                <span className="text-[10px] opacity-70 flex-shrink-0 mt-0.5">{log.time}</span>
                <span className="flex-1">{log.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );

}
