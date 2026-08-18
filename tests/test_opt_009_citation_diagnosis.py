from __future__ import annotations

from repoauditor.detect.ensemble import LensCandidate
from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.eval.novelty_citation_diagnosis import (
    ANCHOR,
    FIXTURE_ROOT,
    POSITIVE_REL,
    _classify_candidate,
    _region_and_requests,
    run_offline_diagnosis,
)


def _candidate(citation: str) -> LensCandidate:
    return LensCandidate(
        title="diagnostic",
        file=POSITIVE_REL,
        line_start=49,
        line_end=49,
        citation_snippet=citation,
        severity="critical",
        confidence=0.9,
    )


def test_citation_classifier_distinguishes_exact_and_display_prefix():
    index = RetrievalIndex().build(FIXTURE_ROOT)

    assert _classify_candidate(_candidate(ANCHOR), index) == ("exact", True)
    assert _classify_candidate(_candidate(f"49\t{ANCHOR}"), index) == (
        "display-prefix-recoverable",
        True,
    )
    assert _classify_candidate(_candidate("paraphrased sink"), index) == (
        "other-nonverbatim",
        False,
    )


def test_both_diagnostic_requests_fit_frozen_bounds():
    _region, bounds = _region_and_requests()

    assert bounds["source_truncated"] is False
    assert bounds["region_utf8_bytes"] < 240_000
    assert bounds["exact_request_content_utf8_bytes"] < 320_000
    assert bounds["clarified_request_content_utf8_bytes"] < 320_000


def test_offline_diagnosis_passes_without_disclosing_source():
    result = run_offline_diagnosis()

    assert result["status"] == "passed"
    assert all(result["checks"].values())
    assert result["source_excerpts_persisted"] == 0
    assert result["candidate_identities_disclosed"] == 0
    assert result["production_store"]["before_sha256"] == result["production_store"]["after_sha256"]
