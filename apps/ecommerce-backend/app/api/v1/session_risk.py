"""Session Risk and Graduated Defense Policy REST API endpoints."""

from typing import Any

from fastapi import APIRouter, Query, status

from security.schemas.session_risk import SessionRiskProfile
from services.session_security.session_risk_service import SessionRiskService

router = APIRouter()
service = SessionRiskService()


@router.get(
    "/sessions/matrix",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="Retrieve graduated defense response policy tier matrix",
)
async def get_defense_matrix():
    """Returns the university-aligned 5-tier graduated response matrix (ALLOW, MONITOR, THROTTLE, CHALLENGE, CONTAIN)."""
    return service.get_defense_matrix()


@router.get(
    "/sessions/high-risk",
    response_model=list[SessionRiskProfile],
    status_code=status.HTTP_200_OK,
    summary="Query active sessions exceeding threat risk threshold",
)
async def list_high_risk_sessions(
    min_risk: int = Query(default=30, ge=0, le=100, description="Minimum risk score threshold"),
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of sessions to return"),
):
    """Returns sessions ranked by risk score using Redis sorted set index."""
    return await service.list_high_risk_sessions(min_risk=min_risk, limit=limit)


@router.get(
    "/sessions/{session_id}/risk",
    response_model=SessionRiskProfile,
    status_code=status.HTTP_200_OK,
    summary="Get real-time explainable risk profile for an active session",
)
async def get_session_risk(session_id: str):
    """Returns current risk score, confidence, response tier, and audit breakdown for session."""
    return await service.get_session_risk(session_id)


@router.post(
    "/sessions/{session_id}/reset",
    response_model=SessionRiskProfile,
    status_code=status.HTTP_200_OK,
    summary="Reset session risk state to clean legitimate baseline",
)
async def reset_session_risk(session_id: str):
    """Administrator containment reset restoring session to ALLOW baseline state."""
    return await service.reset_session(session_id)


@router.post(
    "/sessions/{session_id}/decay",
    response_model=SessionRiskProfile,
    status_code=status.HTTP_200_OK,
    summary="Trigger deterministic time decay on session risk",
)
async def decay_session_risk(
    session_id: str,
    elapsed_minutes: float = Query(default=5.0, ge=0.0, description="Elapsed benign minutes to decay"),
):
    """Applies time decay algorithm (5 points per 5 minutes of benign activity)."""
    return await service.decay_session(session_id, elapsed_minutes=elapsed_minutes)
