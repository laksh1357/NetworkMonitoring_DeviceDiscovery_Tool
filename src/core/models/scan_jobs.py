"""Scan job states and their legal transitions."""

from __future__ import annotations

from enum import StrEnum


class ScanJobState(StrEnum):
    """Lifecycle states for a persisted scan job."""

    NEW = "NEW"
    VALIDATING = "VALIDATING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    RETRY_PENDING = "RETRY_PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


_ALLOWED_TRANSITIONS: dict[ScanJobState, frozenset[ScanJobState]] = {
    ScanJobState.NEW: frozenset({ScanJobState.VALIDATING, ScanJobState.CANCELLED}),
    ScanJobState.VALIDATING: frozenset(
        {ScanJobState.QUEUED, ScanJobState.FAILED, ScanJobState.CANCELLED}
    ),
    ScanJobState.QUEUED: frozenset({ScanJobState.RUNNING, ScanJobState.CANCELLED}),
    ScanJobState.RUNNING: frozenset(
        {
            ScanJobState.RETRY_PENDING,
            ScanJobState.COMPLETED,
            ScanJobState.FAILED,
            ScanJobState.CANCELLED,
            ScanJobState.TIMED_OUT,
        }
    ),
    ScanJobState.RETRY_PENDING: frozenset(
        {ScanJobState.QUEUED, ScanJobState.FAILED, ScanJobState.CANCELLED}
    ),
    ScanJobState.COMPLETED: frozenset(),
    ScanJobState.FAILED: frozenset(),
    ScanJobState.CANCELLED: frozenset(),
    ScanJobState.TIMED_OUT: frozenset(),
}


def validate_scan_job_transition(
    current: ScanJobState | str, target: ScanJobState | str
) -> None:
    """Raise ``ValueError`` unless ``current -> target`` is legal."""

    try:
        current_state = ScanJobState(current)
        target_state = ScanJobState(target)
    except ValueError as exc:
        raise ValueError("unknown scan job state") from exc
    if target_state not in _ALLOWED_TRANSITIONS[current_state]:
        raise ValueError(f"invalid scan job transition: {current_state} -> {target_state}")


def allowed_scan_job_transitions(state: ScanJobState | str) -> frozenset[ScanJobState]:
    """Return the legal next states for a state."""

    try:
        return _ALLOWED_TRANSITIONS[ScanJobState(state)]
    except ValueError as exc:
        raise ValueError("unknown scan job state") from exc
