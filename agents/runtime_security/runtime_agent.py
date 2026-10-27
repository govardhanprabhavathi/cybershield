"""Agent 7: Runtime Security Agent analyzing real-time telemetry stream for deterministic attacks and behavioral anomalies."""

import time
from collections import defaultdict
from typing import Any

from security.rules.runtime_rules import match_sqli, match_xss
from security.schemas.incident import RuntimeIncident
from telemetry.schemas.events import SecurityTelemetryEvent


class RuntimeSecurityAgent:
    """Consumes telemetry events and detects attack patterns, brute-force anomalies, and authorization bypasses."""

    def __init__(self, brute_force_threshold: int = 5, window_seconds: float = 60.0):
        self.brute_force_threshold = brute_force_threshold
        self.window_seconds = window_seconds
        # In-memory session trackers (session_id -> list of failure timestamps)
        self.failed_logins: dict[str, list[float]] = defaultdict(list)
        # Tracking distinct resource accesses (session_id -> set of accessed order IDs)
        self.session_order_access: dict[str, set[str]] = defaultdict(set)

    def analyze_event(self, event: SecurityTelemetryEvent) -> list[RuntimeIncident]:
        """Analyze a single telemetry event and return any detected security incidents."""
        incidents: list[RuntimeIncident] = []
        now = time.time()

        # 1. SQL Injection Detection
        matched_sql = None
        for val in event.query_params.values():
            matched_sql = match_sqli(str(val))
            if matched_sql:
                break
        if not matched_sql and event.payload_sample:
            matched_sql = match_sqli(event.payload_sample)

        if matched_sql or (event.indicators.has_sql_chars and event.status_code >= 500):
            confidence = 0.98 if (matched_sql and event.status_code >= 500) else (0.92 if matched_sql else 0.85)
            evidence: dict[str, Any] = {
                "matched_pattern": matched_sql,
                "has_sql_chars": event.indicators.has_sql_chars,
                "status_code": event.status_code,
                "query_params": event.query_params,
                "payload_sample": event.payload_sample,
            }
            incidents.append(
                RuntimeIncident(
                    session_id=event.session_id,
                    user_id=event.user_id,
                    client_ip=event.client_ip,
                    attack_type="SQL_INJECTION",
                    severity="HIGH",
                    confidence=confidence,
                    cwe_id="CWE-89",
                    endpoint=event.path,
                    method=event.method,
                    trigger_event_id=event.event_id,
                    raw_evidence=evidence,
                )
            )

        # 2. XSS & Client-Side Code Injection Detection
        matched_xss_token = None
        for val in event.query_params.values():
            matched_xss_token = match_xss(str(val))
            if matched_xss_token:
                break
        if not matched_xss_token and event.payload_sample:
            matched_xss_token = match_xss(event.payload_sample)

        if matched_xss_token or event.indicators.has_script_tags:
            incidents.append(
                RuntimeIncident(
                    session_id=event.session_id,
                    user_id=event.user_id,
                    client_ip=event.client_ip,
                    attack_type="XSS",
                    severity="MEDIUM",
                    confidence=0.92 if matched_xss_token else 0.80,
                    cwe_id="CWE-79",
                    endpoint=event.path,
                    method=event.method,
                    trigger_event_id=event.event_id,
                    raw_evidence={
                        "matched_token": matched_xss_token,
                        "has_script_tags": event.indicators.has_script_tags,
                        "query_params": event.query_params,
                    },
                )
            )

        # 3. Authentication Brute-Force Detection
        if event.path.endswith("/auth/login") and event.status_code == 401:
            key = event.session_id or event.client_ip
            # Clean expired timestamps outside the sliding window
            self.failed_logins[key] = [
                ts for ts in self.failed_logins[key]
                if now - ts <= self.window_seconds
            ]
            self.failed_logins[key].append(now)

            if len(self.failed_logins[key]) >= self.brute_force_threshold:
                incidents.append(
                    RuntimeIncident(
                        session_id=event.session_id,
                        user_id=event.user_id,
                        client_ip=event.client_ip,
                        attack_type="BRUTE_FORCE_AUTH",
                        severity="HIGH",
                        confidence=0.95,
                        cwe_id="CWE-307",
                        endpoint=event.path,
                        method=event.method,
                        trigger_event_id=event.event_id,
                        raw_evidence={
                            "failure_count": len(self.failed_logins[key]),
                            "window_seconds": self.window_seconds,
                            "threshold": self.brute_force_threshold,
                        },
                    )
                )

        # 4. BOLA / IDOR Cross-Tenant Access & Enumeration Detection
        if "/orders/" in event.path:
            parts = event.path.rstrip("/").split("/")
            order_id = parts[-1] if len(parts) >= 5 else None

            # A) Unauthorized access blocked by tenant check (HTTP 403)
            if event.status_code == 403:
                incidents.append(
                    RuntimeIncident(
                        session_id=event.session_id,
                        user_id=event.user_id,
                        client_ip=event.client_ip,
                        attack_type="BOLA_IDOR",
                        severity="HIGH",
                        confidence=0.95,
                        cwe_id="CWE-284",
                        endpoint=event.path,
                        method=event.method,
                        trigger_event_id=event.event_id,
                        raw_evidence={
                            "attempted_order_id": order_id,
                            "status_code": 403,
                            "message": "Cross-tenant order lookup denied by ownership check.",
                        },
                    )
                )

            # B) Sequential order enumeration across sessions
            if order_id and order_id != "checkout":
                self.session_order_access[event.session_id].add(order_id)
                if len(self.session_order_access[event.session_id]) >= 3:
                    incidents.append(
                        RuntimeIncident(
                            session_id=event.session_id,
                            user_id=event.user_id,
                            client_ip=event.client_ip,
                            attack_type="BOLA_IDOR",
                            severity="MEDIUM",
                            confidence=0.88,
                            cwe_id="CWE-284",
                            endpoint=event.path,
                            method=event.method,
                            trigger_event_id=event.event_id,
                            raw_evidence={
                                "distinct_orders_accessed": list(self.session_order_access[event.session_id]),
                                "count": len(self.session_order_access[event.session_id]),
                            },
                        )
                    )

        # 5. Resource Consumption Anomaly Detection
        limit_param = event.query_params.get("limit")
        if limit_param:
            try:
                limit_val = int(limit_param)
                if limit_val >= 1000:
                    incidents.append(
                        RuntimeIncident(
                            session_id=event.session_id,
                            user_id=event.user_id,
                            client_ip=event.client_ip,
                            attack_type="RESOURCE_CONSUMPTION",
                            severity="LOW",
                            confidence=0.85,
                            cwe_id="CWE-770",
                            endpoint=event.path,
                            method=event.method,
                            trigger_event_id=event.event_id,
                            raw_evidence={
                                "requested_limit": limit_val,
                                "threshold": 1000,
                            },
                        )
                    )
            except ValueError:
                pass

        return incidents
