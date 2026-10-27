"""Session Risk Service coordinating Agent 8 session risk lifecycle, queries, and policy enforcement."""

from typing import Any

from agents.session_security.session_agent import SessionSecurityAgent
from security.policies.response_policy import GraduatedResponsePolicy
from security.schemas.incident import RuntimeIncident
from security.schemas.session_risk import SessionRiskProfile


class SessionRiskService:
    """Service layer exposing session risk tracking, containment actions, and audit matrix."""

    def __init__(self, agent: SessionSecurityAgent | None = None):
        self.agent = agent or SessionSecurityAgent()

    async def get_session_risk(self, session_id: str) -> SessionRiskProfile:
        """Fetch current explainable risk profile for an active session."""
        return await self.agent.get_profile(session_id)

    async def record_incident(self, incident: RuntimeIncident) -> SessionRiskProfile:
        """Record runtime incident, update risk score, and enact graduated response."""
        return await self.agent.record_incident(incident)

    async def list_high_risk_sessions(
        self,
        min_risk: int = 30,
        limit: int = 50,
    ) -> list[SessionRiskProfile]:
        """List active sessions exceeding specified risk threshold."""
        return await self.agent.get_high_risk_sessions(min_risk=min_risk, limit=limit)

    async def decay_session(
        self,
        session_id: str,
        elapsed_minutes: float = 5.0,
    ) -> SessionRiskProfile:
        """Apply time decay to session risk."""
        return await self.agent.decay_session(session_id, elapsed_minutes=elapsed_minutes)

    async def reset_session(self, session_id: str) -> SessionRiskProfile:
        """Reset session risk back to legitimate baseline."""
        return await self.agent.reset_session(session_id)

    @staticmethod
    def get_defense_matrix() -> list[dict[str, Any]]:
        """Return the graduated defense tier mapping matrix."""
        return GraduatedResponsePolicy.get_tier_matrix()
