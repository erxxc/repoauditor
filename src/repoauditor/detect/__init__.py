"""Detect stage — multi-lens AI ensemble + deterministic tools, retrieval-augmented.

Interface stubs only in this scaffold. The lenses live as versioned prompts under
`lenses/`; deterministic tool adapters under `deterministic/`; the retrieval index
under `retrieval/`.
"""

from .ensemble import CandidateFinding, DetectionRun, LensCandidate, LensFindings, run_ensemble
from .planning import (
    DetectionProjection,
    project_detection_work,
    validate_detection_projection,
)
from .retrieval import RetrievalIndex

__all__ = [
    "CandidateFinding",
    "DetectionRun",
    "LensCandidate",
    "LensFindings",
    "run_ensemble",
    "DetectionProjection",
    "project_detection_work",
    "validate_detection_projection",
    "RetrievalIndex",
]
