"""Pipeline observability describes stage outcomes without changing them."""

from types import SimpleNamespace

from repoauditor.observability import (
    detection_metrics,
    falsification_metrics,
    normalization_metrics,
)
from repoauditor.store.models import FalsificationStatus, Finding


def _finding(source: str, *, status=FalsificationStatus.UNRESOLVED) -> Finding:
    return Finding(
        repo_id="r",
        title="SQL injection",
        file="app.py",
        line_start=4,
        line_end=4,
        citation_snippet="execute(user_input)",
        source_tool=source,
        confidence=0.8,
        severity="high",
        falsification_status=status,
        description="[CWE-89]",
    )


def test_detection_metrics_expose_duplicate_amplification():
    metrics = detection_metrics(
        [_finding("semgrep"), _finding("other-sast")],
        {"semgrep": 1, "other-sast": 1},
    )

    assert metrics["raw_candidates"] == 2
    assert metrics["unique_candidate_groups"] == 1
    assert metrics["duplicate_amplification"] == 1
    assert metrics["model_usage"] == "not recorded"


def test_falsification_and_normalization_metrics_preserve_abstentions():
    falsify = falsification_metrics(
        [
            SimpleNamespace(status=FalsificationStatus.CONFIRMED),
            SimpleNamespace(status=FalsificationStatus.UNRESOLVED),
        ],
        deferred_count=1,
    )
    normalized = normalization_metrics(
        [
            _finding("semgrep", status=FalsificationStatus.CONFIRMED),
            _finding("other-sast", status=FalsificationStatus.UNRESOLVED),
        ]
    )

    assert falsify == {
        "challenged": 2,
        "confirmed": 1,
        "killed": 0,
        "unresolved": 1,
        "deferred": 1,
        "model_usage": "not recorded",
    }
    assert normalized["resolved"] == 1
    assert normalized["unresolved"] == 1
