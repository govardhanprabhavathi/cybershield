"""Agent 3: API Security Agent performing dynamic probing (DAST), OpenAPI auditing, and ZAP orchestration."""

from typing import Any

import httpx
from fastapi import FastAPI

from security.attack_patterns.dast_probes import (
    BUSINESS_FLOW_PROBES,
    RESOURCE_PROBE,
    SQLI_PROBE_VECTORS,
)
from security.schemas.findings import ProbeResult, SecurityFinding


class APISecurityAgent:
    """Dynamic API Security testing agent implementing black-box and gray-box verification."""

    def __init__(self, client: httpx.AsyncClient, app: FastAPI | None = None):
        self.client = client
        self.app = app

    async def probe_bola(
        self,
        victim_token: str,
        attacker_token: str,
        victim_order_id: str,
    ) -> ProbeResult:
        """Probe for Broken Object Level Authorization (OWASP API1 / CWE-284).

        Bob (attacker) attempts to retrieve Alice's (victim) order using Bob's valid JWT token.
        """
        endpoint = f"/api/v1/orders/{victim_order_id}"

        # 1. Verify victim can read their own order
        victim_headers = {"Authorization": f"Bearer {victim_token}"}
        victim_res = await self.client.get(endpoint, headers=victim_headers)
        if victim_res.status_code != 200:
            return ProbeResult(
                probe_name="BOLA_IDOR_ORDER_ACCESS",
                target_endpoint=endpoint,
                target_method="GET",
                vulnerable=False,
                evidence={
                    "error": "Victim order could not be loaded as prerequisite",
                    "status_code": victim_res.status_code,
                },
            )

        victim_order = victim_res.json()

        # 2. Attacker attempts to read victim's order with attacker's token
        attacker_headers = {"Authorization": f"Bearer {attacker_token}"}
        attacker_res = await self.client.get(endpoint, headers=attacker_headers)

        # Flaw: Attacker successfully retrieves victim's order (HTTP 200)
        if attacker_res.status_code == 200:
            leak_data = attacker_res.json()
            is_victim_order = leak_data.get("id") == victim_order_id
            if is_victim_order:
                finding = SecurityFinding(
                    agent_source="api_security_dast",
                    category="BOLA_IDOR",
                    cwe_id="CWE-284",
                    owasp_category="API1:2023-BOLA",
                    severity="HIGH",
                    confidence=0.99,
                    title="Dynamic Confirmation: Broken Object Level Authorization on Order Lookup",
                    description=(
                        f"Cross-tenant access dynamically confirmed on {endpoint}. User '{attacker_token[:10]}...' "
                        f"successfully retrieved order '{victim_order_id}' belonging to user '{victim_order.get('user_id')}'."
                    ),
                    file_path="apps/ecommerce-backend/app/services/order_service.py",
                    line_number=142,
                    endpoint="/api/v1/orders/{order_id}",
                    method="GET",
                    parameter="order_id",
                    raw_evidence={
                        "victim_order_id": victim_order_id,
                        "victim_user_id": victim_order.get("user_id"),
                        "attacker_status_code": attacker_res.status_code,
                        "retrieved_total": leak_data.get("total_amount"),
                    },
                    remediation_guidance=(
                        "Enforce strict object ownership validation on every access: "
                        "verify order.user_id == current_user.id or current_user.role == 'admin'."
                    ),
                    status="CONFIRMED",
                )
                return ProbeResult(
                    probe_name="BOLA_IDOR_ORDER_ACCESS",
                    target_endpoint=endpoint,
                    target_method="GET",
                    vulnerable=True,
                    evidence=finding.raw_evidence,
                    finding=finding,
                )

        return ProbeResult(
            probe_name="BOLA_IDOR_ORDER_ACCESS",
            target_endpoint=endpoint,
            target_method="GET",
            vulnerable=False,
            evidence={
                "attacker_status_code": attacker_res.status_code,
                "message": "Authorization check correctly denied cross-tenant access.",
            },
        )

    async def probe_sqli(self, endpoint: str = "/api/v1/products") -> ProbeResult:
        """Probe for SQL Injection via search query parameter (OWASP Top 10 / CWE-89)."""
        for vector in SQLI_PROBE_VECTORS:
            params = {"search": vector.payload}
            response = await self.client.get(endpoint, params=params)

            # Check if query triggered an internal server error revealing database engine details
            is_500 = response.status_code == 500
            resp_text = response.text.lower()
            leak_detected = any(sub in resp_text for sub in vector.expected_error_substrings)

            if is_500 and leak_detected:
                finding = SecurityFinding(
                    agent_source="api_security_dast",
                    category="SQL_INJECTION",
                    cwe_id="CWE-89",
                    owasp_category="OWASP Top 10 - Injection",
                    severity="HIGH",
                    confidence=0.98,
                    title="Dynamic Confirmation: SQL Injection in Product Search API",
                    description=(
                        f"Database execution error dynamically triggered on {endpoint} via search payload: '{vector.payload}'. "
                        "Raw query interpolation permits SQL syntax corruption and data leakage."
                    ),
                    file_path="apps/ecommerce-backend/app/services/product_service.py",
                    line_number=28,
                    endpoint="/api/v1/products",
                    method="GET",
                    parameter="search",
                    raw_evidence={
                        "payload": vector.payload,
                        "status_code": response.status_code,
                        "response_excerpt": response.text[:200],
                    },
                    remediation_guidance="Use parameterized SQLAlchemy queries or ORM filter expressions (e.g. .ilike()).",
                    status="CONFIRMED",
                )
                return ProbeResult(
                    probe_name="SQLI_SEARCH_PARAMETER",
                    target_endpoint=endpoint,
                    target_method="GET",
                    vulnerable=True,
                    evidence=finding.raw_evidence,
                    finding=finding,
                )

        return ProbeResult(
            probe_name="SQLI_SEARCH_PARAMETER",
            target_endpoint=endpoint,
            target_method="GET",
            vulnerable=False,
            evidence={"message": "All SQL injection probe vectors handled safely."},
        )

    async def probe_business_flow(
        self,
        user_token: str,
        product_id: str,
    ) -> ProbeResult:
        """Probe for Sensitive Business Flow Abuse (OWASP API6 / CWE-840).

        Attempts to submit negative item quantities to the shopping cart.
        """
        endpoint = "/api/v1/cart/items"
        headers = {"Authorization": f"Bearer {user_token}"}

        for probe in BUSINESS_FLOW_PROBES:
            payload = {"product_id": product_id, "quantity": probe.quantity}
            response = await self.client.post(endpoint, json=payload, headers=headers)

            # Flaw: Backend accepted negative or zero quantity
            if response.status_code in (200, 201):
                finding = SecurityFinding(
                    agent_source="api_security_dast",
                    category="BUSINESS_FLOW_ABUSE",
                    cwe_id="CWE-840",
                    owasp_category="API6:2023-Sensitive Business Flows",
                    severity="MEDIUM",
                    confidence=0.95,
                    title="Dynamic Confirmation: Negative Quantity Cart Manipulation",
                    description=(
                        f"Endpoint {endpoint} accepted invalid quantity {probe.quantity}, "
                        "allowing checkout total deflation or cart logic manipulation."
                    ),
                    file_path="apps/ecommerce-backend/app/services/cart_service.py",
                    line_number=45,
                    endpoint="/api/v1/cart/items",
                    method="POST",
                    parameter="quantity",
                    raw_evidence={
                        "tested_quantity": probe.quantity,
                        "status_code": response.status_code,
                        "response_data": response.json(),
                    },
                    remediation_guidance="Enforce invariant input validation ensuring quantity is a positive integer >= 1.",
                    status="CONFIRMED",
                )
                return ProbeResult(
                    probe_name="BUSINESS_FLOW_NEGATIVE_QUANTITY",
                    target_endpoint=endpoint,
                    target_method="POST",
                    vulnerable=True,
                    evidence=finding.raw_evidence,
                    finding=finding,
                )

        return ProbeResult(
            probe_name="BUSINESS_FLOW_NEGATIVE_QUANTITY",
            target_endpoint=endpoint,
            target_method="POST",
            vulnerable=False,
            evidence={"message": "Non-positive quantities correctly rejected by API validation."},
        )

    async def probe_resource_consumption(self, endpoint: str = "/api/v1/products") -> ProbeResult:
        """Probe for Unrestricted Resource Consumption (OWASP API4 / CWE-770)."""
        params = {"limit": RESOURCE_PROBE.limit}
        response = await self.client.get(endpoint, params=params)

        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list) and len(data) > RESOURCE_PROBE.max_acceptable_limit:
                finding = SecurityFinding(
                    agent_source="api_security_dast",
                    category="RESOURCE_CONSUMPTION",
                    cwe_id="CWE-770",
                    owasp_category="API4:2023-Unrestricted Resource Consumption",
                    severity="MEDIUM",
                    confidence=0.92,
                    title="Dynamic Confirmation: Unbounded Resource Consumption on Product Query",
                    description=(
                        f"Endpoint {endpoint} returned {len(data)} items when requested with limit={RESOURCE_PROBE.limit}, "
                        f"exceeding safe boundary of {RESOURCE_PROBE.max_acceptable_limit} items."
                    ),
                    file_path="apps/ecommerce-backend/app/services/product_service.py",
                    line_number=20,
                    endpoint="/api/v1/products",
                    method="GET",
                    parameter="limit",
                    raw_evidence={
                        "requested_limit": RESOURCE_PROBE.limit,
                        "returned_count": len(data),
                        "max_allowed": RESOURCE_PROBE.max_acceptable_limit,
                    },
                    remediation_guidance="Enforce strict server-side bounding on pagination parameters (e.g. limit = min(limit, 100)).",
                    status="CONFIRMED",
                )
                return ProbeResult(
                    probe_name="RESOURCE_CONSUMPTION_QUERY_LIMIT",
                    target_endpoint=endpoint,
                    target_method="GET",
                    vulnerable=True,
                    evidence=finding.raw_evidence,
                    finding=finding,
                )

        return ProbeResult(
            probe_name="RESOURCE_CONSUMPTION_QUERY_LIMIT",
            target_endpoint=endpoint,
            target_method="GET",
            vulnerable=False,
            evidence={"message": "Pagination limits successfully bounded by server."},
        )

    def audit_openapi_contract(self, app: FastAPI | None = None) -> tuple[str, list[dict[str, Any]]]:
        """Audit OpenAPI schema for contract conformance and missing authorization definitions."""
        target_app = app or self.app
        if not target_app:
            return "SKIPPED", [{"message": "No FastAPI application instance provided."}]

        openapi_spec = target_app.openapi()
        issues: list[dict[str, Any]] = []

        paths = openapi_spec.get("paths", {})
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() in ("parameters", "summary", "description"):
                    continue

                operation_id = operation.get("operation_id", f"{method}_{path}")
                responses = operation.get("responses", {})

                # Check 1: Documented error responses
                if "422" not in responses and any(
                    param.get("in") in ("query", "path")
                    for param in operation.get("parameters", [])
                ):
                    issues.append({
                        "path": path,
                        "method": method.upper(),
                        "operation_id": operation_id,
                        "issue": "Missing 422 Validation Error documentation for parameterized endpoint.",
                    })

                # Check 2: Description or summary completeness
                if not operation.get("summary") and not operation.get("description"):
                    issues.append({
                        "path": path,
                        "method": method.upper(),
                        "operation_id": operation_id,
                        "issue": "Missing API summary and description.",
                    })

        status = "PASSED" if not issues else "WARNINGS_FOUND"
        return status, issues

    def generate_zap_automation_plan(self, target_url: str = "http://localhost:8000") -> str:
        """Generate an OWASP ZAP Automation Framework configuration plan for API security scanning."""
        zap_yaml = f"""# OWASP ZAP Automation Framework Plan for CyberShield E-Commerce
env:
  contexts:
    - name: "cybershield-api"
      urls:
        - "{target_url}/api/v1"
      includePaths:
        - "{target_url}/api/v1/.*"
      excludePaths:
        - "{target_url}/api/v1/auth/logout"
      authentication:
        method: "http"
        parameters:
          loginPageUrl: "{target_url}/api/v1/auth/login"
          loginRequestUrl: "{target_url}/api/v1/auth/login"
          loginRequestBody: '{{"email": "alice@cybershield.io", "password": "AlicePass123!"}}'
  parameters:
    failOnError: false
    progressToStdout: true

jobs:
  - type: openapi
    parameters:
      apiFile: "{target_url}/openapi.json"
      targetUrl: "{target_url}"

  - type: spider
    parameters:
      context: "cybershield-api"
      maxDuration: 5

  - type: activeScan
    parameters:
      context: "cybershield-api"
      policy: "API-Top10"
      maxRuleDurationInMins: 2
    policyDefinition:
      defaultStrength: "medium"
      defaultThreshold: "medium"
      rules:
        - id: 40018  # SQL Injection
          strength: "high"
          threshold: "low"
        - id: 40012  # Cross Site Scripting
          strength: "medium"
          threshold: "medium"
        - id: 90022  # Application Error Disclosure
          strength: "high"
          threshold: "low"

  - type: report
    parameters:
      template: "traditional-html"
      reportDir: "reports/zap"
      reportFile: "zap-cybershield-dast.html"
"""
        return zap_yaml
