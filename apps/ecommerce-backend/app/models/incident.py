"""SQLAlchemy ORM model for storing live runtime security incidents."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class RuntimeIncidentRecord(Base):
    """Database entity persisting security incidents detected by Runtime Security Agent."""

    __tablename__ = "runtime_incidents"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}",
    )
    session_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    client_ip: Mapped[str] = mapped_column(String(64), default="127.0.0.1", nullable=False)
    attack_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    method: Mapped[str] = mapped_column(String(16), default="GET", nullable=False)
    trigger_event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
