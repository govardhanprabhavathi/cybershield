"""Deterministic, explainable risk and confidence calculation algorithms for session evaluation."""

from security.schemas.incident import RuntimeIncident

ATTACK_WEIGHTS: dict[str, int] = {
    "SQL_INJECTION": 40,
    "BOLA_IDOR": 35,
    "BUSINESS_FLOW_ABUSE": 30,
    "BRUTE_FORCE_AUTH": 30,
    "XSS": 25,
    "RESOURCE_CONSUMPTION": 20,
}
DEFAULT_WEIGHT: int = 15


class ExplainableRiskCalculator:
    """Calculates auditable risk and confidence scores with multi-vector compounding."""

    @staticmethod
    def calculate_risk_and_confidence(
        incidents: list[RuntimeIncident],
    ) -> tuple[int, float, list[str]]:
        """Computes risk score (0-100), confidence (0.0-1.0), and human-readable explanation."""
        if not incidents:
            return 0, 0.0, ["Clean legitimate session baseline: No security incidents observed."]

        base_score = 0
        total_weighted_confidence = 0.0
        total_weight = 0
        contributing_factors: list[str] = []
        attack_types: set[str] = set()

        for inc in incidents:
            weight = ATTACK_WEIGHTS.get(inc.attack_type, DEFAULT_WEIGHT)
            base_score += weight
            total_weighted_confidence += inc.confidence * weight
            total_weight += weight
            attack_types.add(inc.attack_type)

            contributing_factors.append(
                f"{inc.attack_type} on {inc.endpoint} (+{weight} risk, confidence: {inc.confidence:.2f})"
            )

        # Multi-vector compounding: Cross-vector attacks are significantly more indicative of an active adversary
        multiplier = 1.0
        if len(attack_types) >= 2:
            multiplier = 1.2
            base_score = int(base_score * multiplier)
            contributing_factors.append(
                f"Multi-vector correlation multiplier (1.2x) applied across {len(attack_types)} distinct attack vectors."
            )

        # Compute combined confidence with multi-incident corroboration boost
        avg_confidence = total_weighted_confidence / total_weight if total_weight > 0 else 0.5
        corroboration_boost = min(0.10, 0.03 * (len(incidents) - 1))
        confidence = min(1.0, round(avg_confidence + corroboration_boost, 2))

        # Clamp risk score to [0, 100]
        final_risk = min(100, max(0, base_score))

        return final_risk, confidence, contributing_factors

    @staticmethod
    def apply_time_decay(current_risk: int, elapsed_minutes: float) -> int:
        """Decay risk score by 5 points for every 5 minutes of benign activity."""
        if elapsed_minutes < 5.0 or current_risk == 0:
            return current_risk
        decay_intervals = int(elapsed_minutes // 5.0)
        decay_amount = decay_intervals * 5
        return max(0, current_risk - decay_amount)
