"""Session Risk Profile schema capturing real-time risk scores and graduated defense tiers."""

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


ResponseState = Literal["ALLOW", "MONITOR", "THROTTLE", "CHALLENGE", "CONTAIN"]


class SessionRiskProfile(BaseModel):
    """Real-time security risk profile maintained for each active session."""

    session_id: str
    user_id: str | None = None
    client_ip: str = "127.0.0.1"
    risk_score: int = Field(default=0, ge=0, le=100)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    state: ResponseState = "ALLOW"
    contributing_factors: list[str] = Field(default_factory=list)
    incident_count: int = 0
    attack_types_seen: list[str] = Field(default_factory=list)
    last_evaluated_at: datetime = Field(default_factory=utcnow)
    created_at: datetime = Field(default_factory=utcnow)
