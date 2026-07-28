"""The falsification verdict shape.

Kept in its own module (no heavy imports) so `normalize/` and `store/` can reference
it without pulling in the challenger's map/detect/retrieval dependencies.
"""

from __future__ import annotations

from pydantic import BaseModel

from ..store.models import FalsificationStatus
from .counterexample import RegexGuardWitness


class FalsificationOutcome(BaseModel):
    """Result of challenging a candidate: the verdict plus its rationale.

    `rationale` is mandatory — a killed finding must record *why* it was killed.
    `reachable` records the reachability check; `mitigating_control` names any
    existing control that neutralised the issue, when one was found.
    """

    status: FalsificationStatus
    rationale: str
    reachable: bool | None = None
    mitigating_control: str | None = None
    # The model's confidence in this verdict (falsification_v2+). Below the configured
    # threshold, the verdict is escalated to `unresolved` rather than guessed either way.
    confidence: float = 1.0
    # Concrete, deterministically checkable evidence for a JavaScript regex-control
    # bypass claim. Optional for findings outside that deliberately narrow checker.
    counterexample_witness: RegexGuardWitness | None = None


class SelfCritique(BaseModel):
    """The reflect step of the challenger loop: does the verdict survive scrutiny?

    After forming a verdict, the challenger re-examines it against the evidence it
    actually gathered (falsification_selfcritique_v1). `upholds=False` means the
    verdict over-reached — the loop does not commit it and gathers more context. Its
    own `confidence` is gated the same way a verdict's is: a shaky critique does not
    license committing.
    """

    upholds: bool
    concern: str  # the specific weakness found, or why the verdict holds
    confidence: float = 1.0
