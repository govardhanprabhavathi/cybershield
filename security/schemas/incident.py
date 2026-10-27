"""Runtime Incident Schema representing security incidents detected during live application monitoring."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class RuntimeIncident(BaseModel):
    """Structured security incident detected by Agent 7 from live telemetry stream."""

    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    session_id: str
    user_id: str | None = None
    client_ip: str = "127.0.0.1"
    attack_type: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    cwe_id: str
    endpoint: str
    method: str
    trigger_event_id: str
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    status: str = "OPEN"
    detected_at: datetime = Field(default_factory=utcnow)
