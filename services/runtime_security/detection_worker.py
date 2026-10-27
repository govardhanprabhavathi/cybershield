"""Detection worker service reading telemetry batches from Redis Streams and persisting runtime incidents."""

from app.core.logging import logger
from app.models.incident import RuntimeIncidentRecord
from sqlalchemy.ext.asyncio import AsyncSession

from agents.runtime_security.runtime_agent import RuntimeSecurityAgent
from agents.session_security.session_agent import SessionSecurityAgent
from security.schemas.incident import RuntimeIncident
from telemetry.processors.stream_processor import TelemetryStreamProcessor


class DetectionWorkerService:
    """Consumes telemetry stream batches, executes Agent 7 detection rules, and persists incidents."""

    def __init__(
        self,
        processor: TelemetryStreamProcessor | None = None,
        agent: RuntimeSecurityAgent | None = None,
        session_agent: SessionSecurityAgent | None = None,
    ):
        self.processor = processor or TelemetryStreamProcessor()
        self.agent = agent or RuntimeSecurityAgent()
        self.session_agent = session_agent or SessionSecurityAgent()

    async def process_batch(
        self,
        db: AsyncSession,
        count: int = 50,
        consumer_name: str = "detection-worker-1",
        block_ms: int = 200,
    ) -> list[RuntimeIncident]:
        """Read a batch from telemetry stream, run detection, persist incidents, and acknowledge stream."""
        raw_events = await self.processor.read_batch(
            consumer_name=consumer_name,
            count=count,
            block_ms=block_ms,
        )

        if not raw_events:
            return []

        all_detected_incidents: list[RuntimeIncident] = []
        message_ids_to_ack: list[str] = []

        for msg_id, event in raw_events:
            message_ids_to_ack.append(msg_id)
            incidents = self.agent.analyze_event(event)

            for inc in incidents:
                all_detected_incidents.append(inc)
                record = RuntimeIncidentRecord(
                    id=inc.incident_id,
                    session_id=inc.session_id,
                    user_id=inc.user_id,
                    client_ip=inc.client_ip,
                    attack_type=inc.attack_type,
                    severity=inc.severity,
                    confidence=inc.confidence,
                    cwe_id=inc.cwe_id,
                    endpoint=inc.endpoint,
                    method=inc.method,
                    trigger_event_id=inc.trigger_event_id,
                    raw_evidence=inc.raw_evidence,
                    status=inc.status,
                    detected_at=inc.detected_at,
                )
                db.add(record)
                try:
                    await self.session_agent.record_incident(inc)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(f"Failed to record incident to session risk profile: {exc}")

        if all_detected_incidents:
            await db.commit()
            logger.info(f"Detection worker generated and committed {len(all_detected_incidents)} runtime incidents.")

        # Acknowledge processed stream entries
        if message_ids_to_ack:
            await self.processor.ack(message_ids_to_ack)

        return all_detected_incidents
