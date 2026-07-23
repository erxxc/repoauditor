"""Read-only pipeline funnel metrics derived from stage return values.

These helpers describe what happened; they never change ranking, verdicts, grouping, or
persistence. Their stage-only projections use ``not recorded`` as a placeholder; the
pipeline orchestrator replaces it with authoritative provider usage aggregated by store/.
Dollar cost remains unavailable without a dated provider/model price source.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from .matching import find_matches
from .store.models import Finding


def _rows(values: Iterable | None) -> list:
    if values is None:
        return []
    try:
        return list(values)
    except TypeError:
        return []


def detection_metrics(
    findings: Iterable[Finding], source_counts: dict[str, int]
) -> dict:
    rows = _rows(findings)
    groups = find_matches(rows).groups
    return {
        "raw_candidates": len(rows),
        "unique_candidate_groups": len(groups),
        "duplicate_amplification": max(0, len(rows) - len(groups)),
        "source_counts": dict(source_counts),
        "model_usage": "not recorded",
    }


def falsification_metrics(outcomes: Iterable, deferred_count: int = 0) -> dict:
    counts = Counter(str(outcome.status) for outcome in _rows(outcomes))
    return {
        "challenged": sum(counts.values()),
        "confirmed": counts["confirmed"],
        "killed": counts["killed"],
        "unresolved": counts["unresolved"],
        "deferred": deferred_count,
        "model_usage": "not recorded",
    }


def normalization_metrics(findings: Iterable[Finding]) -> dict:
    rows = _rows(findings)
    unresolved = sum(
        finding.falsification_status.value == "unresolved" for finding in rows
    )
    return {
        "canonical_findings": len(rows),
        "resolved": len(rows) - unresolved,
        "unresolved": unresolved,
        "model_usage": "not recorded",
    }
