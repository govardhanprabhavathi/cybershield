from __future__ import annotations

import logging
from typing import ClassVar

from security.schemas.orchestrator import WorkflowState

logger = logging.getLogger(__name__)


class StateMachineValidationError(ValueError):
    """Raised when an illegal workflow state transition is attempted."""



class IncidentStateMachine:
    """Deterministic finite state machine governing incident response lifecycles."""

    # Map of permitted forward and corrective transitions
    TRANSITIONS: ClassVar[dict[WorkflowState, set[WorkflowState]]] = {
        WorkflowState.INGESTED: {
            WorkflowState.CONTAINING,
            WorkflowState.TRIANGULATING,
            WorkflowState.FAILED,
        },
        WorkflowState.CONTAINING: {
            WorkflowState.TRIANGULATING,
            WorkflowState.FAILED,
        },
        WorkflowState.TRIANGULATING: {
            WorkflowState.DRAFTING_PATCH,
            WorkflowState.RESOLVED,
            WorkflowState.ESCALATED_HUMAN,
            WorkflowState.FAILED,
        },
        WorkflowState.DRAFTING_PATCH: {
            WorkflowState.VERIFYING_PATCH,
            WorkflowState.ESCALATED_HUMAN,
            WorkflowState.FAILED,
        },
        WorkflowState.VERIFYING_PATCH: {
            WorkflowState.AWAITING_APPROVAL,
            WorkflowState.AUTO_DEPLOYING,
            WorkflowState.DRAFTING_PATCH,  # Retry with revised prompt/context
            WorkflowState.ESCALATED_HUMAN,
            WorkflowState.FAILED,
        },
        WorkflowState.AWAITING_APPROVAL: {
            WorkflowState.AUTO_DEPLOYING,
            WorkflowState.ESCALATED_HUMAN,
            WorkflowState.FAILED,
        },
        WorkflowState.AUTO_DEPLOYING: {
            WorkflowState.VERIFYING_RUNTIME,
            WorkflowState.ROLLED_BACK,
            WorkflowState.FAILED,
        },
        WorkflowState.VERIFYING_RUNTIME: {
            WorkflowState.RESOLVED,
            WorkflowState.ROLLED_BACK,
            WorkflowState.ESCALATED_HUMAN,
            WorkflowState.FAILED,
        },
        WorkflowState.ROLLED_BACK: {
            WorkflowState.ESCALATED_HUMAN,
            WorkflowState.RESOLVED,
            WorkflowState.FAILED,
        },
        WorkflowState.ESCALATED_HUMAN: {
            WorkflowState.AUTO_DEPLOYING,
            WorkflowState.RESOLVED,
            WorkflowState.FAILED,
        },
        WorkflowState.RESOLVED: set(),  # Terminal state
        WorkflowState.FAILED: {
            WorkflowState.INGESTED,
            WorkflowState.TRIANGULATING,
            WorkflowState.DRAFTING_PATCH,
        },  # Allowed retry entrypoints
    }

    @classmethod
    def can_transition(cls, from_state: WorkflowState, to_state: WorkflowState) -> bool:
        """Check if transitioning from `from_state` to `to_state` is legal."""
        allowed = cls.TRANSITIONS.get(from_state, set())
        return to_state in allowed

    @classmethod
    def validate_transition(cls, from_state: WorkflowState, to_state: WorkflowState) -> None:
        """Validate state transition, raising StateMachineValidationError if forbidden."""
        if not cls.can_transition(from_state, to_state):
            msg = (
                f"Illegal workflow state transition: cannot transition from '{from_state.value}' "
                f"to '{to_state.value}'. Permitted transitions: {[s.value for s in cls.TRANSITIONS.get(from_state, set())]}"
            )
            logger.error(msg)
            raise StateMachineValidationError(msg)

    @classmethod
    def get_permitted_next_states(cls, current_state: WorkflowState) -> list[WorkflowState]:
        """Return list of permitted next states from current state."""
        return list(cls.TRANSITIONS.get(current_state, set()))
