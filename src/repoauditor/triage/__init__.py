"""Triage stage — calibrated P(actionable) ranking of deterministic-tool findings.

Runs after `detect` and before `falsify` (see CLAUDE.md pipeline). Deterministic SAST
output is noisy; triage re-ranks it by a *calibrated* probability that each finding is
actionable, so the expensive LLM falsification pass spends its budget best-first. It is
a ranking/prioritization layer — it may suppress (demote) a finding, but never deletes
one from the store.

Method lineage: EPSS-style feature engineering + the SAST alert-quality / actionable-
warning (AWI) literature for the classifier; a Beta-Binomial conjugate prior with
Bayesian shrinkage for per-rule cold-start P(actionable).
"""

from .classifier import TriageClassifier, TriageOutcome, triage_repo
from .collection import CollectionStatus, collection_status, render_collection_status
from .features import FEATURE_NAMES, SarifFinding, extract_feature_vector, load_sarif
from .labels import DerivedLabelSummary, assess_finding, derive_labels, label_finding
from .stats import ThresholdStats, render_threshold_stats, threshold_stats

__all__ = [
    "CollectionStatus",
    "DerivedLabelSummary",
    "FEATURE_NAMES",
    "SarifFinding",
    "TriageClassifier",
    "TriageOutcome",
    "ThresholdStats",
    "assess_finding",
    "collection_status",
    "derive_labels",
    "extract_feature_vector",
    "label_finding",
    "load_sarif",
    "render_collection_status",
    "render_threshold_stats",
    "threshold_stats",
    "triage_repo",
]
