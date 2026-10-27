"""Graduated response policy mapping Risk and Confidence scores to deterministic containment states."""

from typing import Any

from security.schemas.session_risk import ResponseState


class GraduatedResponsePolicy:
    """Evaluates risk score and confidence against university-aligned graduated defense tiers."""

    @staticmethod
    def evaluate(risk_score: int, confidence: float) -> tuple[ResponseState, str]:
        """Determines response tier based on (Risk Score, Confidence).

        Tiers:
        - [0 - 29]: ALLOW (Normal User Baseline)
        - [30 - 59]: MONITOR (Telemetry Sampling, No User Interruption)
        - [60 - 79]: THROTTLE (Rate Limiting / Latency Injection)
        - [80 - 89]: CHALLENGE (Step-Up Verification / CAPTCHA)
        - [90 - 100]: CONTAIN (Immediate Token Revocation / Request Drop)
        """
        if risk_score >= 90 and confidence >= 0.85:
            return (
                "CONTAIN",
                "High-confidence attack session confirmed. Execute immediate token revocation and gateway block.",
            )

        if risk_score >= 80 and confidence >= 0.75:
            return (
                "CHALLENGE",
                "Elevated threat probability. Require step-up re-authentication or CAPTCHA challenge.",
            )

        if risk_score >= 60 and confidence >= 0.65:
            return (
                "THROTTLE",
                "Suspicious behavioral anomalies observed. Apply adaptive rate limiting and delayed responses.",
            )

        if risk_score >= 30:
            return (
                "MONITOR",
                "Low-level anomaly detected. Increase telemetry sampling rate; preserve normal user flow.",
            )

        return (
            "ALLOW",
            "Normal legitimate session behavior. Permitted full access.",
        )

    @staticmethod
    def get_tier_matrix() -> list[dict[str, Any]]:
        """Return human-readable specification of the graduated defense tier matrix."""
        return [
            {
                "tier": "ALLOW",
                "risk_range": "0 - 29",
                "min_confidence": 0.0,
                "action": "Unrestricted request processing (Legitimate Session Baseline)",
            },
            {
                "tier": "MONITOR",
                "risk_range": "30 - 59",
                "min_confidence": 0.50,
                "action": "Detailed telemetry logging, no user disruption",
            },
            {
                "tier": "THROTTLE",
                "risk_range": "60 - 79",
                "min_confidence": 0.65,
                "action": "Adaptive rate limiting and latency injection",
            },
            {
                "tier": "CHALLENGE",
                "risk_range": "80 - 89",
                "min_confidence": 0.75,
                "action": "Trigger step-up re-authentication or verification challenge",
            },
            {
                "tier": "CONTAIN",
                "risk_range": "90 - 100",
                "min_confidence": 0.85,
                "action": "Immediate token revocation and HTTP 403 containment gate",
            },
        ]
