"""Security Telemetry Event Schema capturing granular request/response context for runtime defense."""

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class SecurityIndicators(BaseModel):
    """Pre-computed deterministic flags to accelerate downstream stream worker analysis."""

    has_sql_chars: bool = False
    has_script_tags: bool = False
    is_auth_failure: bool = False
    is_server_error: bool = False
    is_sensitive_endpoint: bool = False
    query_param_count: int = 0
    body_length: int = 0


class SecurityTelemetryEvent(BaseModel):
    """Enriched security telemetry event emitted per HTTP request/response cycle."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=utcnow)
    trace_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    span_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])

    # Core Identity & Session Context (Session is the primary unit)
    session_id: str
    user_id: str | None = None
    user_role: str = "anonymous"
    client_ip: str = "127.0.0.1"
    user_agent: str = ""

    # Request Lifecycle
    method: str
    path: str
    route: str | None = None
    query_params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)

    # Response & Performance
    status_code: int
    duration_ms: float
    response_size_bytes: int = 0

    # Detection Indicators & Snippets
    indicators: SecurityIndicators = Field(default_factory=SecurityIndicators)
    payload_sample: str | None = None
