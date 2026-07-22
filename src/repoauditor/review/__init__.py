"""Review stage — the human-in-the-loop checkpoint (maker-checker / four-eyes control).

Findings the automated pipeline cannot resolve (unresolved from falsify/ or normalize/,
or a too-uncertain triage/ result) are held as `ReviewRequest`s and blocked from any
analyze-style query until a human records a `ReviewDecision`. `checkpoint` raises and
gates; `audit` records the append-only decision trail.
"""

from .audit import (
    correct_decision,
    decide,
    decision_history,
    effective_decision,
    record_decision,
)
from .checkpoint import (
    analyzable_findings,
    is_blocked,
    open_review_requests,
    raise_review_requests,
    render_open_requests,
)

__all__ = [
    "raise_review_requests",
    "analyzable_findings",
    "open_review_requests",
    "render_open_requests",
    "is_blocked",
    "record_decision",
    "correct_decision",
    "decide",
    "decision_history",
    "effective_decision",
]
