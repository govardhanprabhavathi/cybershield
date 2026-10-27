"""Unit tests for the deterministic IncidentStateMachine."""

import pytest

from security.orchestrator.state_machine import IncidentStateMachine, StateMachineValidationError
from security.schemas.orchestrator import WorkflowState


def test_legal_forward_transitions():
    """Verify that expected linear forward transitions succeed without error."""
    # INGESTED -> CONTAINING
    assert IncidentStateMachine.can_transition(WorkflowState.INGESTED, WorkflowState.CONTAINING)
    IncidentStateMachine.validate_transition(WorkflowState.INGESTED, WorkflowState.CONTAINING)

    # CONTAINING -> TRIANGULATING
    assert IncidentStateMachine.can_transition(WorkflowState.CONTAINING, WorkflowState.TRIANGULATING)
    IncidentStateMachine.validate_transition(WorkflowState.CONTAINING, WorkflowState.TRIANGULATING)

    # TRIANGULATING -> DRAFTING_PATCH
    assert IncidentStateMachine.can_transition(WorkflowState.TRIANGULATING, WorkflowState.DRAFTING_PATCH)
    IncidentStateMachine.validate_transition(WorkflowState.TRIANGULATING, WorkflowState.DRAFTING_PATCH)

    # DRAFTING_PATCH -> VERIFYING_PATCH
    assert IncidentStateMachine.can_transition(WorkflowState.DRAFTING_PATCH, WorkflowState.VERIFYING_PATCH)
    IncidentStateMachine.validate_transition(WorkflowState.DRAFTING_PATCH, WorkflowState.VERIFYING_PATCH)

    # VERIFYING_PATCH -> AWAITING_APPROVAL or AUTO_DEPLOYING
    assert IncidentStateMachine.can_transition(WorkflowState.VERIFYING_PATCH, WorkflowState.AWAITING_APPROVAL)
    assert IncidentStateMachine.can_transition(WorkflowState.VERIFYING_PATCH, WorkflowState.AUTO_DEPLOYING)

    # AWAITING_APPROVAL -> AUTO_DEPLOYING
    assert IncidentStateMachine.can_transition(WorkflowState.AWAITING_APPROVAL, WorkflowState.AUTO_DEPLOYING)

    # AUTO_DEPLOYING -> VERIFYING_RUNTIME
    assert IncidentStateMachine.can_transition(WorkflowState.AUTO_DEPLOYING, WorkflowState.VERIFYING_RUNTIME)

    # VERIFYING_RUNTIME -> RESOLVED
    assert IncidentStateMachine.can_transition(WorkflowState.VERIFYING_RUNTIME, WorkflowState.RESOLVED)


def test_illegal_transitions_raise_validation_error():
    """Verify that skipping lifecycle phases or illegal backward jumps raise StateMachineValidationError."""
    # Cannot jump directly from INGESTED to RESOLVED
    assert not IncidentStateMachine.can_transition(WorkflowState.INGESTED, WorkflowState.RESOLVED)
    with pytest.raises(StateMachineValidationError, match="Illegal workflow state transition"):
        IncidentStateMachine.validate_transition(WorkflowState.INGESTED, WorkflowState.RESOLVED)

    # Cannot jump from INGESTED directly to AUTO_DEPLOYING
    assert not IncidentStateMachine.can_transition(WorkflowState.INGESTED, WorkflowState.AUTO_DEPLOYING)
    with pytest.raises(StateMachineValidationError):
        IncidentStateMachine.validate_transition(WorkflowState.INGESTED, WorkflowState.AUTO_DEPLOYING)

    # Terminal RESOLVED state cannot transition anywhere
    assert not IncidentStateMachine.can_transition(WorkflowState.RESOLVED, WorkflowState.INGESTED)
    with pytest.raises(StateMachineValidationError):
        IncidentStateMachine.validate_transition(WorkflowState.RESOLVED, WorkflowState.INGESTED)


def test_rollback_and_escalation_transitions():
    """Verify error recovery and rollback state transitions."""
    # AUTO_DEPLOYING -> ROLLED_BACK
    assert IncidentStateMachine.can_transition(WorkflowState.AUTO_DEPLOYING, WorkflowState.ROLLED_BACK)

    # VERIFYING_RUNTIME -> ROLLED_BACK
    assert IncidentStateMachine.can_transition(WorkflowState.VERIFYING_RUNTIME, WorkflowState.ROLLED_BACK)

    # ROLLED_BACK -> ESCALATED_HUMAN
    assert IncidentStateMachine.can_transition(WorkflowState.ROLLED_BACK, WorkflowState.ESCALATED_HUMAN)

    # AWAITING_APPROVAL -> ESCALATED_HUMAN
    assert IncidentStateMachine.can_transition(WorkflowState.AWAITING_APPROVAL, WorkflowState.ESCALATED_HUMAN)


def test_permitted_next_states():
    """Verify list of next allowed states matches state machine specification."""
    ingested_next = IncidentStateMachine.get_permitted_next_states(WorkflowState.INGESTED)
    assert WorkflowState.CONTAINING in ingested_next
    assert WorkflowState.TRIANGULATING in ingested_next
    assert WorkflowState.FAILED in ingested_next
    assert WorkflowState.RESOLVED not in ingested_next
