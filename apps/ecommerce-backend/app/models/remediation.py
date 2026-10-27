"""SQLAlchemy ORM model for storing automated remediation proposals and verification reports."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class RemediationProposalRecord(Base):
    """Database entity persisting automated AST code patches and verification lifecycle states."""

    __tablename__ = "remediation_proposals"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: f"REM-{uuid.uuid4().hex[:8].upper()}",
    )
    dossier_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    finding_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    cwe_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    vulnerability_title: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    target_file: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="DRAFTED", index=True, nullable=False)
    strategy: Mapped[str] = mapped_column(String(64), default="AST_TRANSFORM", nullable=False)
    explanation: Mapped[str] = mapped_column(String(2048), default="", nullable=False)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    original_code: Mapped[str] = mapped_column(Text, nullable=False)
    patched_code: Mapped[str] = mapped_column(Text, nullable=False)
    unified_diff: Mapped[str] = mapped_column(Text, nullable=False)
    verification_report: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
