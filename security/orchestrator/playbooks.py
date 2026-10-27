from __future__ import annotations

import uuid
from datetime import UTC, datetime

from security.schemas.orchestrator import PlaybookAction


class SecurityPlaybookRunner:
    """Predefined incident response playbooks for autonomous and assisted execution."""

    @classmethod
    def get_playbook_actions(cls, cwe_id: str, session_id: str | None = None) -> list[PlaybookAction]:
        """Generate structured playbook action plan tailored to target weakness."""
        now = datetime.now(UTC)

        if cwe_id == "CWE-89":
            return [
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="CONTAIN_SESSION",
                    description=f"Escalate adversary session {session_id or 'unknown'} to QUARANTINE_BLOCK in Redis.",
                    status="EXECUTED",
                    automated=True,
                    executed_at=now,
                    details={"session_id": session_id, "gate": "FAST_PATH_HTTP_403"},
                ),
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="TRIGGER_TRIANGULATION",
                    description="Correlate runtime SQLi incident with pre-deployment SAST AST and DAST evidence.",
                    status="PENDING",
                    automated=True,
                    details={"cwe_id": "CWE-89"},
                ),
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="DRAFT_AST_PATCH",
                    description="Dispatch Agent 10 to parameterize raw SQL interpolation using SQLAlchemy :param bindings.",
                    status="PENDING",
                    automated=True,
                    details={"strategy": "PARAMETERIZATION"},
                ),
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="VERIFY_SANDBOX",
                    description="Dispatch Agent 11 to execute exploit replay in isolated sandbox environment.",
                    status="PENDING",
                    automated=True,
                    details={"replay_tests": ["SQL_TAUTOLOGY", "UNION_SELECT"]},
                ),
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="DEPLOY_HOTPATCH",
                    description="Commit verified patch to codebase and reload route handler.",
                    status="PENDING",
                    automated=False,  # Governed by HITL approval or autonomous policy
                    details={"target_file": "apps/ecommerce-backend/app/services/product_service.py"},
                ),
            ]

        if cwe_id == "CWE-284":
            return [
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="CONTAIN_SESSION",
                    description=f"Isolate session {session_id or 'unknown'} for cross-tenant IDOR probing.",
                    status="EXECUTED",
                    automated=True,
                    executed_at=now,
                    details={"session_id": session_id, "action": "ISOLATE_CONTAIN"},
                ),
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="DRAFT_AST_PATCH",
                    description="Enforce user ownership predicate `order.user_id == current_user.id`.",
                    status="PENDING",
                    automated=True,
                    details={"strategy": "AUTHORIZATION_GATE"},
                ),
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="VERIFY_SANDBOX",
                    description="Replay cross-tenant order query in sandbox to verify HTTP 403/404 response.",
                    status="PENDING",
                    automated=True,
                    details={"cwe_id": "CWE-284"},
                ),
            ]

        if cwe_id == "CWE-840":
            return [
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="CONTAIN_SESSION",
                    description=f"Throttle cart session {session_id or 'unknown'} attempting negative quantity exploit.",
                    status="EXECUTED",
                    automated=True,
                    executed_at=now,
                    details={"session_id": session_id},
                ),
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="DRAFT_AST_PATCH",
                    description="Add positive quantity lower-bound validation (`Field(gt=0)`).",
                    status="PENDING",
                    automated=True,
                    details={"strategy": "INPUT_VALIDATION"},
                ),
                PlaybookAction(
                    action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                    action_type="VERIFY_SANDBOX",
                    description="Verify negative quantity request is rejected with HTTP 422.",
                    status="PENDING",
                    automated=True,
                    details={"cwe_id": "CWE-840"},
                ),
            ]

        # Default fallback playbook
        return [
            PlaybookAction(
                action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                action_type="CONTAIN_SESSION",
                description=f"Enforce monitoring / containment on session {session_id or 'unknown'}.",
                status="EXECUTED",
                automated=True,
                executed_at=now,
                details={"session_id": session_id},
            ),
            PlaybookAction(
                action_id=f"ACT-{uuid.uuid4().hex[:6].upper()}",
                action_type="TRIANGULATE_EVIDENCE",
                description=f"Initiate multi-pillar correlation for weakness {cwe_id}.",
                status="PENDING",
                automated=True,
                details={"cwe_id": cwe_id},
            ),
        ]
