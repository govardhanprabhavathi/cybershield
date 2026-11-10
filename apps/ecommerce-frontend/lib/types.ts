export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ContainmentLevel =
  | "MONITOR"
  | "RATE_LIMIT"
  | "REQUIRE_CHALLENGE"
  | "ISOLATE_CONTAIN"
  | "QUARANTINE_BLOCK";

export interface VulnerabilityFlag {
  cwe: string;
  title: string;
  description: string;
  exploitHint: string;
  remediationSummary: string;
}

export interface Product {
  id: string;
  name: string;
  description: string;
  price: number;
  category: string;
  stock: number;
  rating: number;
  badge?: string;
  imageUrl?: string;
  vulnerabilityHint?: VulnerabilityFlag;
}

export interface CartItem {
  product: Product;
  quantity: number;
}

export interface OrderItem {
  product_id: string;
  product_name: string;
  unit_price: number;
  quantity: number;
}

export interface Order {
  id: string;
  tenant_id: string;
  user_id: string;
  items: OrderItem[];
  total_price: number;
  status: "PENDING" | "PAID" | "SHIPPED" | "DELIVERED" | "BLOCKED";
  created_at: string;
  security_flag?: string;
}

export interface TelemetryStats {
  total_requests: number;
  blocked_attacks: number;
  active_sessions: number;
  mean_detection_latency_ms: number;
  fpr_percentage: number;
  lspr_percentage: number;
  acr_percentage: number;
  active_quarantines: number;
  high_confidence_dossiers: number;
}

export interface SecurityIncident {
  id: string;
  timestamp: string;
  session_id: string;
  ip_address: string;
  endpoint: string;
  method: string;
  attack_type: string;
  cwe: string;
  severity: Severity;
  risk_score: number;
  containment_action: ContainmentLevel;
  bayesian_confidence: number;
  trace_id: string;
  raw_payload?: string;
  response_status: number;
  details: string;
}

export interface SessionRiskProfile {
  session_id: string;
  user_id: string;
  ip_address: string;
  user_agent: string;
  risk_score: number;
  containment_level: ContainmentLevel;
  attack_history: string[];
  total_requests: number;
  last_activity: string;
  is_quarantined: boolean;
  nat_cluster?: string;
}

export interface PillarEvidence {
  pillar: "SAST" | "DAST" | "RUNTIME";
  agent_name: string;
  finding_id: string;
  rule_id: string;
  cwe: string;
  endpoint: string;
  confidence: number;
  evidence_summary: string;
  code_snippet?: string;
  http_sample?: string;
  timestamp: string;
}

export interface TriangulatedDossier {
  dossier_id: string;
  cwe: string;
  title: string;
  normalized_route: string;
  composite_confidence: number;
  bayesian_details: {
    prior: number;
    likelihoods: {
      sast: number;
      dast: number;
      runtime: number;
    };
    posterior: number;
    all_three_agree: boolean;
  };
  sast_evidence?: PillarEvidence;
  dast_evidence?: PillarEvidence;
  runtime_evidence?: PillarEvidence;
  first_seen: string;
  last_seen: string;
  status: "TRIANGULATED" | "PATCH_PROPOSED" | "PATCH_VERIFIED" | "REMEDIATED";
  remediation_id?: string;
}

export interface ASTDiffItem {
  file_path: string;
  line_number: number;
  vulnerable_code: string;
  remediated_code: string;
  cwe: string;
  fix_type: "PARAMETERIZATION" | "TENANT_AUTH_GATE" | "SCHEMA_VALIDATION" | "TIMING_RESISTANT_EQUALS";
}

export interface VerificationTestRun {
  test_name: string;
  exploit_payload: string;
  expected_vulnerable_status: number;
  actual_remediated_status: number;
  passed: boolean;
  message: string;
}

export interface RemediationProposal {
  proposal_id: string;
  dossier_id: string;
  cwe: string;
  title: string;
  target_file: string;
  description: string;
  diff_items: ASTDiffItem[];
  syntax_valid: boolean;
  sandbox_verified: boolean;
  verification_results: VerificationTestRun[];
  status: "DRAFTED" | "SANDBOX_PASSED" | "APPLIED" | "ROLLED_BACK";
  created_at: string;
  applied_at?: string;
}

export interface SimulationScenario {
  id: string;
  name: string;
  description: string;
  legitimate_threads: number;
  attacker_threads: number;
  attack_vectors: string[];
  duration_seconds: number;
  nat_spoofing: boolean;
}

export interface SimulationMetricPoint {
  timestamp: number;
  legitimate_throughput: number;
  attack_throughput: number;
  blocked_count: number;
  containment_escalations: number;
}

export interface SimulationReport {
  id: string;
  scenario: SimulationScenario;
  start_time: string;
  end_time: string;
  total_requests: number;
  legitimate_requests: number;
  attacker_requests: number;
  legitimate_200_rate: number;
  attacker_blocked_rate: number;
  mean_response_time_ms: number;
  nat_false_positives: number;
  summary: string;
  timeline: SimulationMetricPoint[];
}
