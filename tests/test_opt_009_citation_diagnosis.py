from __future__ import annotations

from repoauditor.detect.ensemble import LensCandidate
from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.eval.novelty_citation_diagnosis import (
    ANCHOR,
    FIXTURE_ROOT,
    POSITIVE_REL,
    _classify_candidate,
    _region_and_requests,
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


def test_historical_offline_diagnosis_is_not_rerun_against_extended_ensemble():
    # OPT-036 changed an input that the 2026-08-13 helper deliberately digest-bound.
    # The historical outcome remains in its immutable result document; current behavior
    # is covered by the scanner-registry tests rather than replaying the old helper.
    from pathlib import Path
    import json

    result = json.loads((
        Path(__file__).parents[1]
        / "docs/optimizations/opt-009-citation-diagnosis-result-2026-08-13.json"
    ).read_text(encoding="utf-8"))
    assert result["offline_diagnosis"]["status"] == "passed"
    assert result["isolation_and_resources"]["production_store_unchanged"] is True
    assert result["isolation_and_resources"]["raw_provider_output_bytes_persisted"] == 0
