import {
  Product,
  Order,
  TelemetryStats,
  SecurityIncident,
  SessionRiskProfile,
  TriangulatedDossier,
  RemediationProposal,
  SimulationScenario,
  SimulationReport,
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// Mock Products Catalog with Built-in Security Vulnerability Indicators
export const MOCK_PRODUCTS: Product[] = [
  {
    id: "prod-001",
    name: "CyberShield Hardware FIDO2 Security Key",
    description: "Hardware-isolated cryptographic security key with biometric touch verification and tamper resistance.",
    price: 65.0,
    category: "Hardware Security",
    stock: 42,
    rating: 4.9,
    badge: "Bestseller",
    imageUrl: "https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=500&auto=format&fit=crop&q=80",
    vulnerabilityHint: {
      cwe: "CWE-89",
      title: "SQL Injection Susceptibility in Catalog Search",
      description: "Unparameterized raw text search concatenates user input directly into query strings without bound parameters.",
      exploitHint: "Search with query: ' OR '1'='1 --",
      remediationSummary: "Parameterize text query with SQLAlchemy :query binding.",
    },
  },
  {
    id: "prod-002",
    name: "Aegis Zero-Trust WireGuard Gateway",
    description: "Enterprise micro-segmentation router with automated key rotation and kernel-accelerated packet inspection.",
    price: 349.99,
    category: "Network Defenses",
    stock: 18,
    rating: 4.8,
    badge: "Enterprise",
    imageUrl: "https://images.unsplash.com/photo-1544197150-b99a580bb7a8?w=500&auto=format&fit=crop&q=80",
    vulnerabilityHint: {
      cwe: "CWE-284",
      title: "BOLA / IDOR in Tenant Order History Endpoint",
      description: "Direct object reference on `/api/v1/orders/{order_id}` does not verify session tenant isolation.",
      exploitHint: "Query order ID for another tenant (e.g., ord-tenant2-99)",
      remediationSummary: "Enforce `WHERE tenant_id = session.tenant_id` gate.",
    },
  },
  {
    id: "prod-003",
    name: "Valkyrie AES-256 Encrypted NVMe SSD 2TB",
    description: "Self-encrypting storage with physical auto-destruct fuse and military-grade hardware key escrow.",
    price: 219.5,
    category: "Data Protection",
    stock: 56,
    rating: 4.7,
    badge: "Hardware Encrypted",
    imageUrl: "https://images.unsplash.com/photo-1591799264318-7e6ef8ddb7ea?w=500&auto=format&fit=crop&q=80",
    vulnerabilityHint: {
      cwe: "CWE-840",
      title: "Negative Quantity Cart Logic Flaw",
      description: "Checkout endpoint accepts negative cart quantities, computing a negative credit balance.",
      exploitHint: "Submit checkout item with quantity: -5",
      remediationSummary: "Add Pydantic `Field(gt=0)` quantity constraint check.",
    },
  },
  {
    id: "prod-004",
    name: "Sentry Privacy Lens Guard Webcam",
    description: "4K AI HDR video streaming camera featuring physical mechanical shutter and dedicated LED hardware bypass prevention.",
    price: 129.0,
    category: "Peripherals",
    stock: 94,
    rating: 4.6,
    imageUrl: "https://images.unsplash.com/photo-1588508065123-287b28e013da?w=500&auto=format&fit=crop&q=80",
  },
  {
    id: "prod-005",
    name: "Quantum-Resistant HSM Backup Vault",
    description: "Kyber-1024 post-quantum key backup cold-storage vault with Faraday aluminum chassis.",
    price: 799.0,
    category: "Crypto Storage",
    stock: 12,
    rating: 5.0,
    badge: "Post-Quantum",
    imageUrl: "https://images.unsplash.com/photo-1629654297299-c8506221ca97?w=500&auto=format&fit=crop&q=80",
    vulnerabilityHint: {
      cwe: "CWE-798",
      title: "Hardcoded Development API Fallback Token",
      description: "Internal diagnostic bridge references default fallback secret token `DEV_SECRET_SUPERADMIN`.",
      exploitHint: "Send header X-Admin-Token: DEV_SECRET_SUPERADMIN",
      remediationSummary: "Enforce dynamic environment secret retrieval with `hmac.compare_digest`.",
    },
  },
  {
    id: "prod-006",
    name: "Tamper-Evident RFID Security Seals (50-pack)",
    description: "Serialized holographic destructible seals with NFC validation for supply chain integrity.",
    price: 39.99,
    category: "Physical Security",
    stock: 310,
    rating: 4.5,
    imageUrl: "https://images.unsplash.com/photo-1563770660941-20978e870e26?w=500&auto=format&fit=crop&q=80",
  },
];

// Mock Telemetry Stats (Research Evaluation Metrics)
export const MOCK_TELEMETRY_STATS: TelemetryStats = {
  total_requests: 18452,
  blocked_attacks: 618,
  active_sessions: 92,
  mean_detection_latency_ms: 1.42,
  fpr_percentage: 0.0,
  lspr_percentage: 100.0,
  acr_percentage: 100.0,
  active_quarantines: 12,
  high_confidence_dossiers: 4,
};

// Initial Mock Live Incidents Stream
export const MOCK_INCIDENTS: SecurityIncident[] = [
  {
    id: "inc-9821",
    timestamp: new Date(Date.now() - 1000 * 25).toISOString(),
    session_id: "sess_bot_sqli_482",
    ip_address: "198.51.100.42",
    endpoint: "/api/v1/products/search",
    method: "GET",
    attack_type: "SQL Injection (CWE-89)",
    cwe: "CWE-89",
    severity: "CRITICAL",
    risk_score: 98,
    containment_action: "QUARANTINE_BLOCK",
    bayesian_confidence: 0.9992,
    trace_id: "otel_span_a89bc2138e9",
    raw_payload: "q=' UNION SELECT id, password_hash, secret_key FROM users--",
    response_status: 403,
    details: "AST parse pattern detected UNION injection in search query; matched SAST rule SQLI-01 and DAST scan signature.",
  },
  {
    id: "inc-9820",
    timestamp: new Date(Date.now() - 1000 * 75).toISOString(),
    session_id: "sess_attacker_bola_99",
    ip_address: "203.0.113.88",
    endpoint: "/api/v1/orders/ord-tenant2-99",
    method: "GET",
    attack_type: "BOLA / IDOR Violation (CWE-284)",
    cwe: "CWE-284",
    severity: "HIGH",
    risk_score: 86,
    containment_action: "ISOLATE_CONTAIN",
    bayesian_confidence: 0.9941,
    trace_id: "otel_span_b77ef9921c4",
    raw_payload: "GET /api/v1/orders/ord-tenant2-99 HTTP/1.1 (Cookie: session=sess_attacker_bola_99; tenant=tenant1)",
    response_status: 403,
    details: "Cross-tenant resource access attempt: Session assigned to Tenant-A requested Tenant-B order record.",
  },
  {
    id: "inc-9819",
    timestamp: new Date(Date.now() - 1000 * 180).toISOString(),
    session_id: "sess_logic_exploit_12",
    ip_address: "198.51.100.42",
    endpoint: "/api/v1/cart/checkout",
    method: "POST",
    attack_type: "Negative Balance Cart Tampering (CWE-840)",
    cwe: "CWE-840",
    severity: "HIGH",
    risk_score: 82,
    containment_action: "ISOLATE_CONTAIN",
    bayesian_confidence: 0.9912,
    trace_id: "otel_span_c441aa2901b",
    raw_payload: JSON.stringify({ items: [{ product_id: "prod-003", quantity: -10 }] }),
    response_status: 422,
    details: "Negative quantity parameter received in checkout schema resulting in unauthorized credit balance attempt.",
  },
  {
    id: "inc-9818",
    timestamp: new Date(Date.now() - 1000 * 320).toISOString(),
    session_id: "sess_scanner_bf_55",
    ip_address: "192.0.2.14",
    endpoint: "/api/v1/auth/token",
    method: "POST",
    attack_type: "Credential Stuffing & Timing Probe (CWE-307)",
    cwe: "CWE-307",
    severity: "MEDIUM",
    risk_score: 64,
    containment_action: "RATE_LIMIT",
    bayesian_confidence: 0.887,
    trace_id: "otel_span_d11099ff33a",
    raw_payload: "username=admin&password=*** (rate: 42 req/sec)",
    response_status: 429,
    details: "Burst login anomaly exceeding normal user interaction threshold; rate-limiting applied via Redis token bucket.",
  },
  {
    id: "inc-9817",
    timestamp: new Date(Date.now() - 1000 * 490).toISOString(),
    session_id: "sess_probe_header_33",
    ip_address: "198.51.100.199",
    endpoint: "/api/v1/internal/diagnostics",
    method: "GET",
    attack_type: "Hardcoded Credential Probe (CWE-798)",
    cwe: "CWE-798",
    severity: "CRITICAL",
    risk_score: 95,
    containment_action: "QUARANTINE_BLOCK",
    bayesian_confidence: 0.9995,
    trace_id: "otel_span_e5544211ba9",
    raw_payload: "Headers: X-Admin-Token: DEV_SECRET_SUPERADMIN",
    response_status: 403,
    details: "Leaked development credential probe intercepted; matching SAST static hardcoded secret finding.",
  },
];

// Mock Session Risk Profiles (Illustrating Shared-IP NAT Disambiguation)
export const MOCK_SESSIONS: SessionRiskProfile[] = [
  {
    session_id: "sess_bot_sqli_482",
    user_id: "usr_attacker_shadow",
    ip_address: "198.51.100.42",
    user_agent: "Mozilla/5.0 (Kali Linux; sqlmap/1.7.2)",
    risk_score: 98,
    containment_level: "QUARANTINE_BLOCK",
    attack_history: ["SQLi: q=' OR 1=1--", "Schema probe: /schema", "Union injection attempt"],
    total_requests: 142,
    last_activity: "25s ago",
    is_quarantined: true,
    nat_cluster: "Corp NAT Gateway (198.51.100.42)",
  },
  {
    session_id: "sess_legit_shopper_88",
    user_id: "usr_alice_corp",
    ip_address: "198.51.100.42",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/129.0.0.0",
    risk_score: 4,
    containment_level: "MONITOR",
    attack_history: [],
    total_requests: 38,
    last_activity: "12s ago",
    is_quarantined: false,
    nat_cluster: "Corp NAT Gateway (198.51.100.42)",
  },
  {
    session_id: "sess_legit_shopper_91",
    user_id: "usr_bob_finance",
    ip_address: "198.51.100.42",
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/128.0.0.0",
    risk_score: 2,
    containment_level: "MONITOR",
    attack_history: [],
    total_requests: 56,
    last_activity: "4s ago",
    is_quarantined: false,
    nat_cluster: "Corp NAT Gateway (198.51.100.42)",
  },
  {
    session_id: "sess_attacker_bola_99",
    user_id: "usr_recon_actor",
    ip_address: "203.0.113.88",
    user_agent: "curl/8.4.0",
    risk_score: 86,
    containment_level: "ISOLATE_CONTAIN",
    attack_history: ["BOLA IDOR /orders/ord-tenant2-99", "BOLA IDOR /orders/ord-tenant3-01"],
    total_requests: 64,
    last_activity: "75s ago",
    is_quarantined: true,
  },
  {
    session_id: "sess_logic_exploit_12",
    user_id: "usr_cart_tamperer",
    ip_address: "198.51.100.42",
    user_agent: "PostmanRuntime/7.39.0",
    risk_score: 82,
    containment_level: "ISOLATE_CONTAIN",
    attack_history: ["Negative cart quantity payload (-10)", "Zero-price tampering attempt"],
    total_requests: 29,
    last_activity: "3m ago",
    is_quarantined: false,
    nat_cluster: "Corp NAT Gateway (198.51.100.42)",
  },
  {
    session_id: "sess_scanner_bf_55",
    user_id: "usr_anonymous",
    ip_address: "192.0.2.14",
    user_agent: "Python-urllib/3.11",
    risk_score: 64,
    containment_level: "RATE_LIMIT",
    attack_history: ["High-frequency token endpoint probe", "Malformed auth header probe"],
    total_requests: 312,
    last_activity: "5m ago",
    is_quarantined: false,
  },
];

// Mock Multi-Pillar Evidence Triangulated Dossiers (Agent 9)
export const MOCK_DOSSIERS: TriangulatedDossier[] = [
  {
    dossier_id: "DOS-CWE-89-01",
    cwe: "CWE-89",
    title: "SQL Injection in Product Search Filtering",
    normalized_route: "/api/v1/products/search",
    composite_confidence: 0.9992,
    bayesian_details: {
      prior: 0.15,
      likelihoods: {
        sast: 0.95,
        dast: 0.92,
        runtime: 0.98,
      },
      posterior: 0.9992,
      all_three_agree: true,
    },
    sast_evidence: {
      pillar: "SAST",
      agent_name: "Agent 1 (SAST Scanner)",
      finding_id: "SAST-SQLI-001",
      rule_id: "RULE_RAW_SQL_CONCAT",
      cwe: "CWE-89",
      endpoint: "/api/v1/products/search",
      confidence: 0.95,
      evidence_summary: "AST syntax analysis detected raw f-string concatenation `SELECT * FROM products WHERE name LIKE '%{q}%'`.",
      code_snippet: "cursor.execute(f\"SELECT * FROM products WHERE name LIKE '%{search_term}%'\")",
      timestamp: "2026-10-06T14:10:00Z",
    },
    dast_evidence: {
      pillar: "DAST",
      agent_name: "Agent 3 (DAST Validator)",
      finding_id: "DAST-EXPLOIT-089",
      rule_id: "PAYLOAD_SQL_TAUTOLOGY",
      cwe: "CWE-89",
      endpoint: "/api/v1/products/search",
      confidence: 0.92,
      evidence_summary: "Tautology payload `' OR '1'='1 --` elicited abnormal database return with 100% catalog disclosure.",
      http_sample: "GET /api/v1/products/search?q='%20OR%20'1'='1-- HTTP/1.1 -> 200 OK (returned all 6 hidden products)",
      timestamp: "2026-10-06T14:18:22Z",
    },
    runtime_evidence: {
      pillar: "RUNTIME",
      agent_name: "Agent 7 (Runtime OTel Sensor)",
      finding_id: "RUNTIME-OTEL-894",
      rule_id: "SPAN_SQL_SYNTAX_ANOMALY",
      cwe: "CWE-89",
      endpoint: "/api/v1/products/search",
      confidence: 0.98,
      evidence_summary: "OpenTelemetry db.statement span recorded unexpected boolean operator inject from live user traffic.",
      http_sample: "Span ID: 8fa921db -> db.statement: SELECT * FROM products WHERE name LIKE '' OR '1'='1 --'",
      timestamp: "2026-10-06T14:24:41Z",
    },
    first_seen: "2026-10-06T14:10:00Z",
    last_seen: "2026-10-06T14:24:41Z",
    status: "PATCH_VERIFIED",
    remediation_id: "REM-CWE89-P01",
  },
  {
    dossier_id: "DOS-CWE-284-02",
    cwe: "CWE-284",
    title: "Broken Object Level Authorization (BOLA) in Order Lookup",
    normalized_route: "/api/v1/orders/{order_id}",
    composite_confidence: 0.9941,
    bayesian_details: {
      prior: 0.12,
      likelihoods: {
        sast: 0.91,
        dast: 0.89,
        runtime: 0.96,
      },
      posterior: 0.9941,
      all_three_agree: true,
    },
    sast_evidence: {
      pillar: "SAST",
      agent_name: "Agent 1 (SAST Scanner)",
      finding_id: "SAST-AUTH-004",
      rule_id: "RULE_MISSING_TENANT_FILTER",
      cwe: "CWE-284",
      endpoint: "/api/v1/orders/{order_id}",
      confidence: 0.91,
      evidence_summary: "Order lookup database query lacks `WHERE tenant_id = :tenant_id` predicate.",
      code_snippet: "order = db.query(Order).filter(Order.id == order_id).first()",
      timestamp: "2026-10-06T14:12:00Z",
    },
    dast_evidence: {
      pillar: "DAST",
      agent_name: "Agent 3 (DAST Validator)",
      finding_id: "DAST-BOLA-012",
      rule_id: "PAYLOAD_CROSS_TENANT_ID",
      cwe: "CWE-284",
      endpoint: "/api/v1/orders/{order_id}",
      confidence: 0.89,
      evidence_summary: "User authenticated in Tenant-1 retrieved Order details belonging to Tenant-2 without authorization check.",
      http_sample: "GET /api/v1/orders/ord-tenant2-99 -> 200 OK (Exposed PII of foreign customer)",
      timestamp: "2026-10-06T14:20:10Z",
    },
    runtime_evidence: {
      pillar: "RUNTIME",
      agent_name: "Agent 7 (Runtime OTel Sensor)",
      finding_id: "RUNTIME-OTEL-284",
      rule_id: "SPAN_TENANT_ID_MISMATCH",
      cwe: "CWE-284",
      endpoint: "/api/v1/orders/{order_id}",
      confidence: 0.96,
      evidence_summary: "Active request context `ctx.tenant_id` did not match record owner in DB span result.",
      timestamp: "2026-10-06T14:25:05Z",
    },
    first_seen: "2026-10-06T14:12:00Z",
    last_seen: "2026-10-06T14:25:05Z",
    status: "PATCH_VERIFIED",
    remediation_id: "REM-CWE284-P02",
  },
  {
    dossier_id: "DOS-CWE-840-03",
    cwe: "CWE-840",
    title: "Negative Quantity Cart Checkout Business Logic Error",
    normalized_route: "/api/v1/cart/checkout",
    composite_confidence: 0.9912,
    bayesian_details: {
      prior: 0.1,
      likelihoods: {
        sast: 0.88,
        dast: 0.94,
        runtime: 0.95,
      },
      posterior: 0.9912,
      all_three_agree: true,
    },
    sast_evidence: {
      pillar: "SAST",
      agent_name: "Agent 2 (Schema Auditor)",
      finding_id: "SAST-LOGIC-009",
      rule_id: "RULE_UNCONSTRAINED_INTEGER",
      cwe: "CWE-840",
      endpoint: "/api/v1/cart/checkout",
      confidence: 0.88,
      evidence_summary: "Pydantic request model lacks positive integer lower bound validation `Field(gt=0)` on quantity.",
      code_snippet: "class CartItemRequest(BaseModel):\n    product_id: str\n    quantity: int",
      timestamp: "2026-10-06T14:15:00Z",
    },
    dast_evidence: {
      pillar: "DAST",
      agent_name: "Agent 3 (DAST Validator)",
      finding_id: "DAST-LOGIC-045",
      rule_id: "PAYLOAD_NEGATIVE_NUMERIC",
      cwe: "CWE-840",
      endpoint: "/api/v1/cart/checkout",
      confidence: 0.94,
      evidence_summary: "Submitting negative quantity returned total price credit with HTTP 200 OK.",
      http_sample: "POST /api/v1/cart/checkout {\"items\": [{\"quantity\": -5}]} -> 200 OK, total: -$1097.50",
      timestamp: "2026-10-06T14:21:40Z",
    },
    runtime_evidence: {
      pillar: "RUNTIME",
      agent_name: "Agent 7 (Runtime OTel Sensor)",
      finding_id: "RUNTIME-OTEL-840",
      rule_id: "SPAN_NEGATIVE_CALCULATION",
      cwe: "CWE-840",
      endpoint: "/api/v1/cart/checkout",
      confidence: 0.95,
      evidence_summary: "Order computation span executed with negative total price value.",
      timestamp: "2026-10-06T14:26:12Z",
    },
    first_seen: "2026-10-06T14:15:00Z",
    last_seen: "2026-10-06T14:26:12Z",
    status: "PATCH_VERIFIED",
    remediation_id: "REM-CWE840-P03",
  },
  {
    dossier_id: "DOS-CWE-798-04",
    cwe: "CWE-798",
    title: "Hardcoded Development API Secret Fallback Key",
    normalized_route: "/api/v1/internal/*",
    composite_confidence: 0.9995,
    bayesian_details: {
      prior: 0.2,
      likelihoods: {
        sast: 0.98,
        dast: 0.95,
        runtime: 0.97,
      },
      posterior: 0.9995,
      all_three_agree: true,
    },
    sast_evidence: {
      pillar: "SAST",
      agent_name: "Agent 1 (SAST Scanner)",
      finding_id: "SAST-CRED-002",
      rule_id: "RULE_HARDCODED_SECRET",
      cwe: "CWE-798",
      endpoint: "/api/v1/internal/*",
      confidence: 0.98,
      evidence_summary: "String constant `DEV_SECRET_SUPERADMIN` embedded as default authentication fallback.",
      code_snippet: "ADMIN_TOKEN = os.getenv(\"ADMIN_TOKEN\", \"DEV_SECRET_SUPERADMIN\")",
      timestamp: "2026-10-06T14:11:00Z",
    },
    dast_evidence: {
      pillar: "DAST",
      agent_name: "Agent 3 (DAST Validator)",
      finding_id: "DAST-AUTH-099",
      rule_id: "PAYLOAD_DEFAULT_TOKEN",
      cwe: "CWE-798",
      endpoint: "/api/v1/internal/diagnostics",
      confidence: 0.95,
      evidence_summary: "Authorization header with hardcoded secret successfully authenticated privileged diagnostic endpoint.",
      timestamp: "2026-10-06T14:22:00Z",
    },
    runtime_evidence: {
      pillar: "RUNTIME",
      agent_name: "Agent 7 (Runtime OTel Sensor)",
      finding_id: "RUNTIME-OTEL-798",
      rule_id: "SPAN_STATIC_TOKEN_MATCH",
      cwe: "CWE-798",
      endpoint: "/api/v1/internal/diagnostics",
      confidence: 0.97,
      evidence_summary: "Runtime token validation executed against static fallback fallback value.",
      timestamp: "2026-10-06T14:27:30Z",
    },
    first_seen: "2026-10-06T14:11:00Z",
    last_seen: "2026-10-06T14:27:30Z",
    status: "PATCH_VERIFIED",
    remediation_id: "REM-CWE798-P04",
  },
];

// Mock Remediation Proposals (Agent 10 AST Patch Generator & Agent 11 Sandbox Verification)
export const MOCK_REMEDIATIONS: RemediationProposal[] = [
  {
    proposal_id: "REM-CWE89-P01",
    dossier_id: "DOS-CWE-89-01",
    cwe: "CWE-89",
    title: "Automated Parameterization of Search Query (CWE-89)",
    target_file: "apps/ecommerce-service/routers/products.py",
    description: "Replaces raw Python string formatting with parameterized query binding `:search_term`, preventing SQL statement injection.",
    diff_items: [
      {
        file_path: "apps/ecommerce-service/routers/products.py",
        line_number: 44,
        vulnerable_code: "query = f\"SELECT * FROM products WHERE name LIKE '%{q}%'\"\nresult = await db.execute(text(query))",
        remediated_code: "query = \"SELECT * FROM products WHERE name LIKE :search_term\"\nresult = await db.execute(text(query), {\"search_term\": f\"%{q}%\"})",
        cwe: "CWE-89",
        fix_type: "PARAMETERIZATION",
      },
    ],
    syntax_valid: true,
    sandbox_verified: true,
    verification_results: [
      {
        test_name: "Replay SQL Tautology Exploit (' OR 1=1--)",
        exploit_payload: "q=' OR 1=1--",
        expected_vulnerable_status: 200,
        actual_remediated_status: 200,
        passed: true,
        message: "Payload safely escaped as literal search string; returned 0 false-positive results instead of entire DB.",
      },
      {
        test_name: "Replay UNION SELECT Injected Exfiltration",
        exploit_payload: "q=' UNION SELECT id, password_hash, secret_key FROM users--",
        expected_vulnerable_status: 200,
        actual_remediated_status: 200,
        passed: true,
        message: "No database syntax error triggered; parameter passed safely into text clause without structural query alteration.",
      },
      {
        test_name: "Legitimate User Query Verification (FIDO2)",
        exploit_payload: "q=FIDO2",
        expected_vulnerable_status: 200,
        actual_remediated_status: 200,
        passed: true,
        message: "Legitimate user functionality completely preserved; matching product returned.",
      },
    ],
    status: "SANDBOX_PASSED",
    created_at: "2026-10-06T14:35:10Z",
  },
  {
    proposal_id: "REM-CWE284-P02",
    dossier_id: "DOS-CWE-284-02",
    cwe: "CWE-284",
    title: "Multi-Tenant Ownership Verification Gate (CWE-284)",
    target_file: "apps/ecommerce-service/routers/orders.py",
    description: "Inserts strict tenant isolation clause `Order.tenant_id == current_tenant.id` into order lookup query.",
    diff_items: [
      {
        file_path: "apps/ecommerce-service/routers/orders.py",
        line_number: 78,
        vulnerable_code: "order = await db.scalar(select(Order).where(Order.id == order_id))\nif not order:\n    raise HTTPException(status_code=404)",
        remediated_code: "order = await db.scalar(\n    select(Order).where(\n        Order.id == order_id,\n        Order.tenant_id == current_user.tenant_id,\n    )\n)\nif not order:\n    raise HTTPException(status_code=404, detail=\"Order not found or access denied\")",
        cwe: "CWE-284",
        fix_type: "TENANT_AUTH_GATE",
      },
    ],
    syntax_valid: true,
    sandbox_verified: true,
    verification_results: [
      {
        test_name: "Replay Cross-Tenant BOLA Access (Tenant-A querying Tenant-B)",
        exploit_payload: "order_id=ord-tenant2-99 with Tenant-1 auth token",
        expected_vulnerable_status: 200,
        actual_remediated_status: 404,
        passed: true,
        message: "Foreign tenant access blocked; returned HTTP 404 access denied.",
      },
      {
        test_name: "Legitimate Tenant Order Retrieval",
        exploit_payload: "order_id=ord-tenant1-01 with Tenant-1 auth token",
        expected_vulnerable_status: 200,
        actual_remediated_status: 200,
        passed: true,
        message: "Legitimate order query succeeded.",
      },
    ],
    status: "SANDBOX_PASSED",
    created_at: "2026-10-06T14:36:00Z",
  },
  {
    proposal_id: "REM-CWE840-P03",
    dossier_id: "DOS-CWE-840-03",
    cwe: "CWE-840",
    title: "Pydantic Schema Quantity Validation Guard (CWE-840)",
    target_file: "apps/ecommerce-service/schemas/cart.py",
    description: "Adds `Field(..., gt=0, le=100)` constraint to prevent negative or zero quantity business logic abuse.",
    diff_items: [
      {
        file_path: "apps/ecommerce-service/schemas/cart.py",
        line_number: 16,
        vulnerable_code: "class CartItemCreate(BaseModel):\n    product_id: str\n    quantity: int",
        remediated_code: "class CartItemCreate(BaseModel):\n    product_id: str\n    quantity: int = Field(..., gt=0, le=100, description=\"Must be a positive integer between 1 and 100\")",
        cwe: "CWE-840",
        fix_type: "SCHEMA_VALIDATION",
      },
    ],
    syntax_valid: true,
    sandbox_verified: true,
    verification_results: [
      {
        test_name: "Replay Negative Quantity Payload (quantity: -10)",
        exploit_payload: "{\"product_id\": \"prod-003\", \"quantity\": -10}",
        expected_vulnerable_status: 200,
        actual_remediated_status: 422,
        passed: true,
        message: "Pydantic validation rejected negative value before business logic execution with HTTP 422.",
      },
    ],
    status: "SANDBOX_PASSED",
    created_at: "2026-10-06T14:36:45Z",
  },
];

// Interactive Client-Side Storage & API Service
class CyberShieldApiClient {
  private products: Product[] = [...MOCK_PRODUCTS];
  private incidents: SecurityIncident[] = [...MOCK_INCIDENTS];
  private sessions: SessionRiskProfile[] = [...MOCK_SESSIONS];
  private dossiers: TriangulatedDossier[] = [...MOCK_DOSSIERS];
  private remediations: RemediationProposal[] = [...MOCK_REMEDIATIONS];
  private stats: TelemetryStats = { ...MOCK_TELEMETRY_STATS };

  // Fetch Products
  async getProducts(): Promise<Product[]> {
    try {
      const res = await fetch(`${API_BASE}/api/v1/products`, { signal: AbortSignal.timeout(1500) });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) return data;
      }
    } catch {
      // Graceful fallback to mock products
    }
    return this.products;
  }

  // Search Products (supports exploit trigger)
  async searchProducts(query: string, sessionId = "sess_demo_live"): Promise<{ results: Product[]; blocked?: boolean; message?: string }> {
    // Check if query is SQLi exploit
    const isSqli = /('|--|\bUNION\b|\bSELECT\b|1=1)/i.test(query);

    if (isSqli) {
      // Simulate/trigger fast-path defense
      const incident: SecurityIncident = {
        id: `inc-${Date.now().toString().slice(-4)}`,
        timestamp: new Date().toISOString(),
        session_id: sessionId,
        ip_address: "198.51.100.42",
        endpoint: "/api/v1/products/search",
        method: "GET",
        attack_type: "SQL Injection (CWE-89)",
        cwe: "CWE-89",
        severity: "CRITICAL",
        risk_score: 99,
        containment_action: "QUARANTINE_BLOCK",
        bayesian_confidence: 0.9994,
        trace_id: `otel_live_${Math.random().toString(16).slice(2, 10)}`,
        raw_payload: `q=${query}`,
        response_status: 403,
        details: "Live SQL injection attempt caught by Fast-Path Gate. Bayesian confidence 0.9994. Quarantined.",
      };
      this.incidents.unshift(incident);
      this.stats.blocked_attacks += 1;
      this.stats.total_requests += 1;

      // Update or add session
      const existing = this.sessions.find((s) => s.session_id === sessionId);
      if (existing) {
        existing.risk_score = 99;
        existing.containment_level = "QUARANTINE_BLOCK";
        existing.is_quarantined = true;
        existing.attack_history.push(`SQLi payload: ${query}`);
        existing.total_requests += 1;
      } else {
        this.sessions.unshift({
          session_id: sessionId,
          user_id: "usr_attacker_demo",
          ip_address: "198.51.100.42",
          user_agent: navigator.userAgent || "CyberShield Web Client",
          risk_score: 99,
          containment_level: "QUARANTINE_BLOCK",
          attack_history: [`SQLi payload: ${query}`],
          total_requests: 1,
          last_activity: "Just now",
          is_quarantined: true,
          nat_cluster: "Corp NAT Gateway (198.51.100.42)",
        });
      }

      return {
        results: [],
        blocked: true,
        message: "403 Forbidden: CyberShield Fast-Path Gate blocked SQL injection payload! Bayesian confidence: 0.9994.",
      };
    }

    // Normal search
    this.stats.total_requests += 1;
    const filtered = this.products.filter(
      (p) =>
        p.name.toLowerCase().includes(query.toLowerCase()) ||
        p.description.toLowerCase().includes(query.toLowerCase()) ||
        p.category.toLowerCase().includes(query.toLowerCase())
    );
    return { results: filtered };
  }

  // Trigger Exploit Payload Test
  async triggerExploit(
    attackType: "SQLI" | "BOLA" | "CART_TAMPER" | "BRUTE_FORCE",
    sessionId = "sess_demo_live"
  ): Promise<{ success: boolean; blocked: boolean; status: number; message: string; incident: SecurityIncident }> {
    let endpoint = "";
    let method = "GET";
    let payload = "";
    let cwe = "";
    let risk = 95;
    let containment: SecurityIncident["containment_action"] = "QUARANTINE_BLOCK";
    let status = 403;
    let details = "";
    let bayesian = 0.998;

    switch (attackType) {
      case "SQLI":
        endpoint = "/api/v1/products/search";
        method = "GET";
        payload = "q=' UNION SELECT id, password_hash, secret_key FROM users--";
        cwe = "CWE-89";
        risk = 99;
        containment = "QUARANTINE_BLOCK";
        status = 403;
        bayesian = 0.9994;
        details = "Exploit payload ' UNION SELECT ... intercepted. Fast-path gate issued immediate HTTP 403.";
        break;
      case "BOLA":
        endpoint = "/api/v1/orders/ord-tenant2-99";
        method = "GET";
        payload = "Targeting foreign tenant order #ord-tenant2-99 from tenant1 session";
        cwe = "CWE-284";
        risk = 88;
        containment = "ISOLATE_CONTAIN";
        status = 403;
        bayesian = 0.9942;
        details = "Cross-tenant access attempted without proper tenant scope. Blocked by session containment.";
        break;
      case "CART_TAMPER":
        endpoint = "/api/v1/cart/checkout";
        method = "POST";
        payload = JSON.stringify({ items: [{ product_id: "prod-003", quantity: -5 }] });
        cwe = "CWE-840";
        risk = 82;
        containment = "ISOLATE_CONTAIN";
        status = 422;
        bayesian = 0.991;
        details = "Negative quantity (-5) rejected by Pydantic validation schema guard.";
        break;
      case "BRUTE_FORCE":
        endpoint = "/api/v1/auth/token";
        method = "POST";
        payload = "Burst login attempts: 45 req/sec";
        cwe = "CWE-307";
        risk = 68;
        containment = "RATE_LIMIT";
        status = 429;
        bayesian = 0.892;
        details = "Redis sliding window rate-limiter triggered. HTTP 429 Too Many Requests.";
        break;
    }

    const incident: SecurityIncident = {
      id: `inc-${Date.now().toString().slice(-4)}`,
      timestamp: new Date().toISOString(),
      session_id: sessionId,
      ip_address: "198.51.100.42",
      endpoint,
      method,
      attack_type: `${attackType} Exploit Simulation`,
      cwe,
      severity: risk > 90 ? "CRITICAL" : "HIGH",
      risk_score: risk,
      containment_action: containment,
      bayesian_confidence: bayesian,
      trace_id: `otel_exp_${Math.random().toString(16).slice(2, 10)}`,
      raw_payload: payload,
      response_status: status,
      details,
    };

    this.incidents.unshift(incident);
    this.stats.blocked_attacks += 1;
    this.stats.total_requests += 1;

    // Update session
    const sess = this.sessions.find((s) => s.session_id === sessionId);
    if (sess) {
      sess.risk_score = risk;
      sess.containment_level = containment;
      sess.is_quarantined = containment === "QUARANTINE_BLOCK";
      sess.attack_history.push(`${attackType}: ${payload}`);
      sess.total_requests += 1;
    } else {
      this.sessions.unshift({
        session_id: sessionId,
        user_id: "usr_attacker_demo",
        ip_address: "198.51.100.42",
        user_agent: navigator.userAgent || "CyberShield Web Client",
        risk_score: risk,
        containment_level: containment,
        attack_history: [`${attackType}: ${payload}`],
        total_requests: 1,
        last_activity: "Just now",
        is_quarantined: containment === "QUARANTINE_BLOCK",
        nat_cluster: "Corp NAT Gateway (198.51.100.42)",
      });
    }

    return {
      success: true,
      blocked: status === 403 || status === 429 || status === 422,
      status,
      message: `CyberShield intercepted ${attackType}! HTTP ${status} — Action: ${containment} (Bayesian: ${(bayesian * 100).toFixed(2)}%)`,
      incident,
    };
  }

  // Reset Session Risk
  async resetSessionRisk(sessionId: string): Promise<boolean> {
    const sess = this.sessions.find((s) => s.session_id === sessionId);
    if (sess) {
      sess.risk_score = 0;
      sess.containment_level = "MONITOR";
      sess.is_quarantined = false;
      sess.attack_history = [];
      sess.last_activity = "Reset just now";
      return true;
    }
    return false;
  }

  // Telemetry & Statistics
  async getTelemetryStats(): Promise<TelemetryStats> {
    return { ...this.stats };
  }

  // Live Incidents
  async getIncidents(): Promise<SecurityIncident[]> {
    return [...this.incidents];
  }

  // Active Sessions
  async getSessions(): Promise<SessionRiskProfile[]> {
    return [...this.sessions];
  }

  // Triangulated Dossiers
  async getDossiers(): Promise<TriangulatedDossier[]> {
    return [...this.dossiers];
  }

  // Remediation Proposals
  async getRemediationProposals(): Promise<RemediationProposal[]> {
    return [...this.remediations];
  }

  // Apply Patch
  async applyPatch(proposalId: string): Promise<boolean> {
    const proposal = this.remediations.find((r) => r.proposal_id === proposalId);
    if (proposal) {
      proposal.status = "APPLIED";
      proposal.applied_at = new Date().toISOString();
      const dossier = this.dossiers.find((d) => d.dossier_id === proposal.dossier_id);
      if (dossier) {
        dossier.status = "REMEDIATED";
      }
      return true;
    }
    return false;
  }

  // Rollback Patch
  async rollbackPatch(proposalId: string): Promise<boolean> {
    const proposal = this.remediations.find((r) => r.proposal_id === proposalId);
    if (proposal) {
      proposal.status = "ROLLED_BACK";
      const dossier = this.dossiers.find((d) => d.dossier_id === proposal.dossier_id);
      if (dossier) {
        dossier.status = "PATCH_VERIFIED";
      }
      return true;
    }
    return false;
  }

  // Execute Traffic Benchmark Simulation
  async runSimulation(scenario: SimulationScenario): Promise<SimulationReport> {
    const totalLegit = scenario.legitimate_threads * 40;
    const totalAttack = scenario.attacker_threads * 35;
    const totalRequests = totalLegit + totalAttack;

    // Timeline points
    const points = [];
    for (let t = 1; t <= scenario.duration_seconds; t++) {
      points.push({
        timestamp: t,
        legitimate_throughput: Math.floor(totalLegit / scenario.duration_seconds + (Math.random() * 10 - 5)),
        attack_throughput: Math.floor(totalAttack / scenario.duration_seconds + (Math.random() * 8 - 4)),
        blocked_count: Math.floor((totalAttack / scenario.duration_seconds) * 0.99),
        containment_escalations: t === 2 ? 15 : t === 4 ? 8 : 1,
      });
    }

    return {
      id: `SIM-${Date.now().toString().slice(-6)}`,
      scenario,
      start_time: new Date(Date.now() - scenario.duration_seconds * 1000).toISOString(),
      end_time: new Date().toISOString(),
      total_requests: totalRequests,
      legitimate_requests: totalLegit,
      attacker_requests: totalAttack,
      legitimate_200_rate: 100.0,
      attacker_blocked_rate: 100.0,
      mean_response_time_ms: 1.38,
      nat_false_positives: 0,
      summary: `Benchmark completed: 100% of attacker payloads blocked across ${scenario.attacker_threads} threads. 100% of ${scenario.legitimate_threads} legitimate shoppers maintained uninterrupted HTTP 200 service, even when sharing NAT gateway 198.51.100.42.`,
      timeline: points,
    };
  }
}

export const api = new CyberShieldApiClient();
