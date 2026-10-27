"""FastAPI / Starlette telemetry middleware capturing fine-grained security context on every request."""

import hashlib
import time
import uuid
from collections.abc import Callable

from app.core.logging import logger
from fastapi import Request, Response
from jose import jwt
from starlette.middleware.base import BaseHTTPMiddleware

from telemetry.exporters.stream_publisher import TelemetryStreamPublisher
from telemetry.schemas.events import SecurityIndicators, SecurityTelemetryEvent

SQL_KEYWORDS = ("--", "/*", "*/", ";", " union ", " select ", " or 1=1", " or '1'='1'")
XSS_PATTERNS = ("<script", "javascript:", "onerror=", "onload=")
SENSITIVE_PATHS = ("/api/v1/auth", "/api/v1/orders", "/api/v1/cart", "/api/v1/admin")


class CyberShieldTelemetryMiddleware(BaseHTTPMiddleware):
    """Enriches every incoming and outgoing HTTP transaction with security telemetry and publishes to Redis Streams."""

    def __init__(self, app, publisher: TelemetryStreamPublisher | None = None):
        super().__init__(app)
        self.publisher = publisher or TelemetryStreamPublisher()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        trace_id = request.headers.get("x-trace-id") or uuid.uuid4().hex
        span_id = uuid.uuid4().hex[:16]

        # Extract Client Identity
        forwarded_for = request.headers.get("x-forwarded-for")
        client_ip = (
            forwarded_for.split(",")[0].strip()
            if forwarded_for
            else (request.client.host if request.client else "127.0.0.1")
        )
        user_agent = request.headers.get("user-agent", "")

        # Extract Session and User Context
        session_id: str | None = None
        user_id: str | None = None
        user_role: str = "anonymous"

        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            try:
                claims = jwt.get_unverified_claims(token)
                session_id = claims.get("session_id")
                user_id = claims.get("sub")
                user_role = claims.get("role", "customer")
            except (jwt.JWTError, ValueError) as err:
                logger.debug(f"Unverified claims extraction skipped: {err}")

        if not session_id:
            session_id = request.headers.get("x-session-id")

        if not session_id:
            # Deterministic anonymous session fingerprint
            fp_raw = f"{client_ip}_{user_agent}".encode()
            session_id = f"anon_{hashlib.sha256(fp_raw).hexdigest()[:16]}"

        # Pre-execution query inspection
        query_string = request.url.query.lower()
        has_sql_chars = any(kw in query_string for kw in SQL_KEYWORDS)
        has_script_tags = any(xss in query_string for xss in XSS_PATTERNS)
        is_sensitive = any(request.url.path.startswith(sp) for sp in SENSITIVE_PATHS)

        # Call next application handler
        response: Response = await call_next(request)

        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        # Compute Detection Indicators
        is_auth_failure = response.status_code in (401, 403)
        is_server_error = response.status_code >= 500

        # Construct Telemetry Event
        event = SecurityTelemetryEvent(
            event_id=str(uuid.uuid4()),
            trace_id=trace_id,
            span_id=span_id,
            session_id=session_id,
            user_id=user_id,
            user_role=user_role,
            client_ip=client_ip,
            user_agent=user_agent,
            method=request.method,
            path=request.url.path,
            route=request.url.path,
            query_params=dict(request.query_params),
            headers={
                k: v for k, v in request.headers.items()
                if k.lower() not in ("authorization", "cookie")
            },
            status_code=response.status_code,
            duration_ms=duration_ms,
            response_size_bytes=int(response.headers.get("content-length", 0)),
            indicators=SecurityIndicators(
                has_sql_chars=has_sql_chars,
                has_script_tags=has_script_tags,
                is_auth_failure=is_auth_failure,
                is_server_error=is_server_error,
                is_sensitive_endpoint=is_sensitive,
                query_param_count=len(request.query_params),
                body_length=0,
            ),
            payload_sample=query_string[:256] if query_string else None,
        )

        # Response Header Injection for Context Propagation
        response.headers["X-Session-ID"] = session_id
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = str(duration_ms)

        # Asynchronous stream emission (zero blocking on HTTP response)
        self.publisher.publish_background(event)

        return response
