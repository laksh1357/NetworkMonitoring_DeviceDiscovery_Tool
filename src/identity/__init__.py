"""Evidence-correlated identity verification (ECIV)."""
from .engine import EvidenceCorrelatedIdentityEngine
from .models import IdentityConflict, IdentityState, NetworkObservation, VerificationResult
from .state import IdentityStateManager
from .service import IdentityVerificationService
__all__ = ["EvidenceCorrelatedIdentityEngine", "IdentityConflict", "IdentityState", "IdentityStateManager", "IdentityVerificationService", "NetworkObservation", "VerificationResult"]
