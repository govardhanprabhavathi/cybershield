import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class SecurityFindingRecord(Base):
    """Database record for pre-deployment and runtime security findings."""

    __tablename__ = "security_findings"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    agent_source: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    owasp_category: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    file_path: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    line_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_evidence: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    remediation_guidance: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
