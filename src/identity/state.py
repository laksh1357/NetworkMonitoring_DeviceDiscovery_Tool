"""Explicit ECIV identity state transitions."""

from __future__ import annotations

from .models import IdentityState


class IdentityStateManager:
    """Single owner of legal identity state transitions."""

    _transitions = {
        IdentityState.TRUSTED: {IdentityState.UNCERTAIN},
        IdentityState.UNCERTAIN: {IdentityState.VERIFYING, IdentityState.UNRESOLVED},
        IdentityState.VERIFYING: {
            IdentityState.CONFIRMED_CHANGE,
            IdentityState.UNRESOLVED,
            IdentityState.QUARANTINED,
        },
        IdentityState.CONFIRMED_CHANGE: {IdentityState.TRUSTED},
        IdentityState.UNRESOLVED: {IdentityState.VERIFYING, IdentityState.QUARANTINED},
        IdentityState.QUARANTINED: {IdentityState.VERIFYING, IdentityState.TRUSTED},
    }

    def __init__(self, state: IdentityState = IdentityState.TRUSTED) -> None:
        self.state = state

    def transition(self, target: IdentityState) -> tuple[IdentityState, IdentityState]:
        if target == self.state:
            return self.state, target
        if target not in self._transitions[self.state]:
            raise ValueError(f"invalid identity transition: {self.state} -> {target}")
        previous = self.state
        self.state = target
        return previous, target
