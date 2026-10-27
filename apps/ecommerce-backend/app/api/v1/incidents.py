"""Incident management and detection worker REST API endpoints."""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.incident import RuntimeIncidentRecord
from security.schemas.incident import RuntimeIncident
from services.runtime_security.detection_worker import DetectionWorkerService

router = APIRouter()
worker = DetectionWorkerService()


@router.get(
    "/incidents",
    response_model=list[RuntimeIncident],
    status_code=status.HTTP_200_OK,
    summary="Query live runtime security incidents with optional filters",
)
async def list_runtime_incidents(
    session_id: str | None = Query(default=None),
    attack_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    db: AsyncSession = Depends(get_db),
):
    query = select(RuntimeIncidentRecord)
    if session_id:
        query = query.where(RuntimeIncidentRecord.session_id == session_id)
    if attack_type:
        query = query.where(RuntimeIncidentRecord.attack_type == attack_type)
    if severity:
        query = query.where(RuntimeIncidentRecord.severity == severity)
    if status_filter:
        query = query.where(RuntimeIncidentRecord.status == status_filter)

    query = query.order_by(RuntimeIncidentRecord.detected_at.desc())
    result = await db.execute(query)
    records = result.scalars().all()

    return [
        RuntimeIncident(
            incident_id=r.id,
            session_id=r.session_id,
            user_id=r.user_id,
            client_ip=r.client_ip,
            attack_type=r.attack_type,
            severity=r.severity,
            confidence=r.confidence,
            cwe_id=r.cwe_id,
            endpoint=r.endpoint,
            method=r.method,
            trigger_event_id=r.trigger_event_id,
            raw_evidence=r.raw_evidence,
            status=r.status,
            detected_at=r.detected_at,
        )
        for r in records
    ]


@router.post(
    "/detection/process-batch",
    response_model=list[RuntimeIncident],
    status_code=status.HTTP_200_OK,
    summary="Trigger detection worker batch processing from Redis telemetry stream",
)
async def process_detection_batch(
    count: int = Query(default=50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Executes a detection processing cycle over buffered telemetry events."""
    return await worker.process_batch(db=db, count=count)
