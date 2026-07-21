"""Falsify stage — second pass that tries to DISPROVE each candidate finding.

Only confirmed/unresolved findings stay live; killed candidates are persisted with
their status and reason (explicit null-result logging), never deleted.
"""

from .challenger import challenge, challenge_finding
from .outcome import FalsificationOutcome, SelfCritique

__all__ = ["challenge", "challenge_finding", "FalsificationOutcome", "SelfCritique"]
