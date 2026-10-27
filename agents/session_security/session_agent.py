"""Agent 8: Session Security Agent managing real-time risk scores, explainable factor tracking, and graduated response enforcement."""

import json
from datetime import UTC, datetime

import redis.asyncio as aioredis
from app.core.logging import logger
from app.core.redis import get_redis

from security.policies.response_policy import GraduatedResponsePolicy
from security.risk_engine.scoring import ExplainableRiskCalculator
from security.schemas.incident import RuntimeIncident
from security.schemas.session_risk import SessionRiskProfile


class SessionSecurityAgent:
    """Maintains active session threat telemetry, calculates explainable risk, and enforces graduated defense tiers."""

    def __init__(self, redis_client: aioredis.Redis | None = None):
        self._redis_client = redis_client

    async def _get_redis(self) -> aioredis.Redis:
        if self._redis_client is not None:
            return self._redis_client
        return await get_redis()

    async def get_profile(self, session_id: str) -> SessionRiskProfile:
        """Retrieve real-time risk profile for session, returning clean baseline if uninitialized."""
        redis = await self._get_redis()
        risk_key = f"session:risk:{session_id}"
        raw = await redis.hgetall(risk_key)

        if not raw:
            return SessionRiskProfile(
                session_id=session_id,
                risk_score=0,
                confidence=0.0,
                state="ALLOW",
                contributing_factors=["Clean legitimate session baseline: No security incidents observed."],
                incident_count=0,
                attack_types_seen=[],
                last_evaluated_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )

        # Parse factors
        contributing_factors: list[str] = []
        if "contributing_factors" in raw:
            try:
                contributing_factors = json.loads(raw["contributing_factors"])
            except (json.JSONDecodeError, TypeError, KeyError):
                contributing_factors = []
        elif "status" in raw and raw.get("risk_score") == "0":
            contributing_factors = ["Clean legitimate session baseline: No security incidents observed."]

        # Parse attack types seen
        attack_types_seen: list[str] = []
        if "attack_types_seen" in raw:
            try:
                attack_types_seen = json.loads(raw["attack_types_seen"])
            except (json.JSONDecodeError, TypeError, KeyError):
                attack_types_seen = []

        # Parse timestamps
        try:
            last_eval = datetime.fromisoformat(raw.get("last_evaluated_at", datetime.now(UTC).isoformat()))
        except (ValueError, TypeError):
            last_eval = datetime.now(UTC)

        try:
            created_at = datetime.fromisoformat(raw.get("created_at", datetime.now(UTC).isoformat()))
        except (ValueError, TypeError):
            created_at = datetime.now(UTC)

        # Normalize state
        raw_state = raw.get("state") or raw.get("status") or "ALLOW"
        if raw_state in ("CONTAINED", "CONTAIN"):
            state = "CONTAIN"
        elif raw_state in ("ALLOW", "NORMAL"):
            state = "ALLOW"
        elif raw_state in ("MONITOR", "THROTTLE", "CHALLENGE"):
            state = raw_state
        else:
            state = "ALLOW"

        return SessionRiskProfile(
            session_id=raw.get("session_id", session_id),
            user_id=raw.get("user_id") or None,
            client_ip=raw.get("client_ip", "127.0.0.1"),
            risk_score=int(raw.get("risk_score", 0)),
            confidence=float(raw.get("confidence", raw.get("confidence_score", 0.0))),
            state=state,
            contributing_factors=contributing_factors,
            incident_count=int(raw.get("incident_count", 0)),
            attack_types_seen=attack_types_seen,
            last_evaluated_at=last_eval,
            created_at=created_at,
        )

    async def record_incident(self, incident: RuntimeIncident) -> SessionRiskProfile:
        """Append incident to session ledger, recompute explainable risk and confidence, and enact graduated tier."""
        redis = await self._get_redis()
        session_id = incident.session_id
        incidents_key = f"session:incidents:{session_id}"
        risk_key = f"session:risk:{session_id}"

        # 1. Store serialized incident in Redis list
        incident_data = json.dumps(incident.model_dump(), default=str)
        await redis.rpush(incidents_key, incident_data)
        await redis.expire(incidents_key, 86400)

        # 2. Retrieve all incidents for session history
        raw_incidents = await redis.lrange(incidents_key, 0, -1)
        incidents_list: list[RuntimeIncident] = []
        for raw_inc in raw_incidents:
            try:
                data = json.loads(raw_inc)
                incidents_list.append(RuntimeIncident(**data))
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"Failed to deserialize incident in session {session_id}: {exc}")

        # 3. Compute explainable risk and confidence score
        risk_score, confidence, factors = ExplainableRiskCalculator.calculate_risk_and_confidence(incidents_list)

        # 4. Evaluate defense response policy
        state, policy_reason = GraduatedResponsePolicy.evaluate(risk_score, confidence)
        factors.append(f"Policy Decision: {state} — {policy_reason}")

        # 5. Extract unique attack types seen
        attack_types = sorted({inc.attack_type for inc in incidents_list})

        # 6. Retrieve original creation timestamp if exists
        existing_created = await redis.hget(risk_key, "created_at")
        created_at = (
            datetime.fromisoformat(existing_created)
            if existing_created
            else datetime.now(UTC)
        )

        profile = SessionRiskProfile(
            session_id=session_id,
            user_id=incident.user_id,
            client_ip=incident.client_ip,
            risk_score=risk_score,
            confidence=confidence,
            state=state,
            contributing_factors=factors,
            incident_count=len(incidents_list),
            attack_types_seen=attack_types,
            last_evaluated_at=datetime.now(UTC),
            created_at=created_at,
        )

        # 7. Persist updated risk profile to Redis hash
        mapping = {
            "session_id": profile.session_id,
            "user_id": profile.user_id or "",
            "client_ip": profile.client_ip,
            "risk_score": str(profile.risk_score),
            "confidence": str(profile.confidence),
            "state": profile.state,
            "status": "CONTAINED" if profile.state == "CONTAIN" else profile.state,
            "contributing_factors": json.dumps(profile.contributing_factors),
            "incident_count": str(profile.incident_count),
            "attack_types_seen": json.dumps(profile.attack_types_seen),
            "last_evaluated_at": profile.last_evaluated_at.isoformat(),
            "created_at": profile.created_at.isoformat(),
        }
        await redis.hset(risk_key, mapping=mapping)
        await redis.expire(risk_key, 86400)

        # 8. Index session risk in sorted set for fast ranking / filtering
        await redis.zadd("sessions:risk:zset", {session_id: float(risk_score)})

        # 9. Server-side Fast-Path Containment Execution if tier is CONTAIN
        if profile.state == "CONTAIN":
            # Mark session general status as CONTAINED
            await redis.hset(f"session:{session_id}", "status", "CONTAINED")

            # Revoke associated token JTI if recorded in session
            jti = await redis.hget(f"session:{session_id}", "jti")
            if jti:
                await redis.set(f"revoked:jti:{jti}", "1", ex=86400)
                logger.warning(
                    f"SessionSecurityAgent revoked token JTI {jti} for contained session {session_id}"
                )

            logger.warning(
                f"SessionSecurityAgent contained adversary session {session_id} (Risk: {risk_score}, Conf: {confidence:.2f})"
            )

        return profile

    async def decay_session(self, session_id: str, elapsed_minutes: float = 5.0) -> SessionRiskProfile:
        """Apply deterministic time decay to session risk score after benign duration."""
        redis = await self._get_redis()
        profile = await self.get_profile(session_id)

        if profile.risk_score == 0:
            return profile

        new_risk = ExplainableRiskCalculator.apply_time_decay(profile.risk_score, elapsed_minutes)
        new_state, _ = GraduatedResponsePolicy.evaluate(new_risk, profile.confidence)

        decayed_factors = list(profile.contributing_factors)
        decayed_factors.append(
            f"Time decay applied ({elapsed_minutes:.1f} mins benign window): Risk reduced from {profile.risk_score} to {new_risk}."
        )

        profile.risk_score = new_risk
        profile.state = new_state
        profile.contributing_factors = decayed_factors
        profile.last_evaluated_at = datetime.now(UTC)

        risk_key = f"session:risk:{session_id}"
        mapping = {
            "risk_score": str(profile.risk_score),
            "state": profile.state,
            "status": "CONTAINED" if profile.state == "CONTAIN" else profile.state,
            "contributing_factors": json.dumps(profile.contributing_factors),
            "last_evaluated_at": profile.last_evaluated_at.isoformat(),
        }
        await redis.hset(risk_key, mapping=mapping)
        await redis.zadd("sessions:risk:zset", {session_id: float(new_risk)})

        return profile

    async def reset_session(self, session_id: str) -> SessionRiskProfile:
        """Reset session to clean baseline, clearing incidents and risk state."""
        redis = await self._get_redis()
        incidents_key = f"session:incidents:{session_id}"
        risk_key = f"session:risk:{session_id}"

        await redis.delete(incidents_key)
        await redis.zrem("sessions:risk:zset", session_id)

        profile = SessionRiskProfile(
            session_id=session_id,
            risk_score=0,
            confidence=0.0,
            state="ALLOW",
            contributing_factors=["Session risk reset to clean baseline by administrator."],
            incident_count=0,
            attack_types_seen=[],
            last_evaluated_at=datetime.now(UTC),
            created_at=datetime.now(UTC),
        )

        mapping = {
            "session_id": profile.session_id,
            "user_id": "",
            "client_ip": "127.0.0.1",
            "risk_score": "0",
            "confidence": "0.0",
            "state": "ALLOW",
            "status": "ALLOW",
            "contributing_factors": json.dumps(profile.contributing_factors),
            "incident_count": "0",
            "attack_types_seen": "[]",
            "last_evaluated_at": profile.last_evaluated_at.isoformat(),
            "created_at": profile.created_at.isoformat(),
        }
        await redis.hset(risk_key, mapping=mapping)
        await redis.hset(f"session:{session_id}", "status", "NORMAL")

        # Un-blacklist token JTI if revoked during containment
        jti = await redis.hget(f"session:{session_id}", "jti")
        if jti:
            await redis.delete(f"revoked:jti:{jti}")

        return profile

    async def get_high_risk_sessions(
        self,
        min_risk: int = 30,
        limit: int = 50,
    ) -> list[SessionRiskProfile]:
        """Query sessions ranked by risk score using Redis sorted set index."""
        redis = await self._get_redis()
        # zrevrangebyscore returns items with score between 100 and min_risk descending
        session_ids = await redis.zrevrangebyscore(
            "sessions:risk:zset",
            max=100,
            min=min_risk,
            start=0,
            num=limit,
        )

        profiles: list[SessionRiskProfile] = []
        for sid in session_ids:
            p = await self.get_profile(sid)
            profiles.append(p)

        return profiles
