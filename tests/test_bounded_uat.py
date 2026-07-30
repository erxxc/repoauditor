"""Fast contract tests for the bounded public-corpus UAT presentation layer."""

from __future__ import annotations

from repoauditor.detect.ensemble import CandidateFinding
from repoauditor.store.models import Severity

from conftest import benchmark_corpus_ids
from fixtures.run_bounded_uat import build_pair_deltas, evaluate_candidates
from fixtures.measure_opt029_bounded_uat import measure


def _candidate(**updates) -> CandidateFinding:
    values = {
        "title": "Path traversal",
        "file": "pkg/storage.py",
        "line_start": 10,
        "line_end": 10,
        "citation_snippet": "unsafe_join(user_path)",
        "source_tool": "sast",
        "producer": "semgrep",
        "confidence": 0.8,
        "severity": Severity.HIGH,
    }
    values.update(updates)
    return CandidateFinding(**values)


def _expected(variant: str) -> dict:
    target = {
        "title": "Path traversal",
        "file": "pkg/storage.py",
        "line_start": 10,
        "citation_contains": "unsafe_join(user_path)",
        "cve": "CVE-2099-0001",
    }
    return {
        "source": {
            "project_id": "example",
            "project": "Example",
            "language": "Python",
            "kind": "independent",
            "variant": variant,
            "pinned_commit": "abc123",
        },
        "findings": [target] if variant == "pre_fix" else [],
        "expected_absent": [target] if variant == "post_fix" else [],
    }


def test_bounded_uat_reports_target_hit_and_keeps_other_candidates_unadjudicated():
    result = evaluate_candidates(
        repo_id="example_pre",
        expected=_expected("pre_fix"),
        candidates=[_candidate(), _candidate(file="other.py", title="Possibly real issue")],
    )

    assert result["target_detected_count"] == 1
    assert result["target_signals"][0]["matches"][0]["match_basis"] == "file+citation"
    assert result["unadjudicated_candidate_count"] == 1
    assert "precision" not in result


def test_bounded_uat_flags_target_signal_that_persists_after_patch():
    result = evaluate_candidates(
        repo_id="example_post",
        expected=_expected("post_fix"),
        candidates=[_candidate()],
    )

    assert result["patched_target_reappeared"] is True
    assert result["target_detected_count"] == 1


def test_opt029_bounded_replay_is_deterministic_and_ground_truth_blind():
    candidate = {
        "producer": "semgrep",
        "source_tool": "semgrep oss",
        "title": "rule",
        "file": "src/app.py",
        "line_start": 3,
        "line_end": 3,
        "severity": "medium",
        "confidence": 0.8,
        "citation_snippet": "sink(value)",
    }
    report = {
        "results": [
            {
                "repo_id": "project-pre",
                "project_id": "project",
                "variant": "pre_fix",
                "candidates": [candidate],
            },
            {
                "repo_id": "project-post",
                "project_id": "project",
                "variant": "post_fix",
                "candidates": [candidate],
            },
        ]
    }

    first = measure(report, limit=32, max_per_engagement=4)
    report["results"].reverse()
    second = measure(report, limit=32, max_per_engagement=4)

    assert first == second
    assert first["funnel"]["counts"] == {
        "raw": 2,
        "after_pre_post_collapse": 1,
        "after_exact_duplicate_collapse": 1,
        "after_path_policy": 1,
        "after_family_cap": 1,
        "after_engagement_balance": 1,
        "selected": 1,
    }
    assert first["ground_truth_used"] is False
    assert first["candidate_outcomes_used"] is False


def test_corpus_selection_environment_is_bounded_and_rejects_unknown(monkeypatch):
    monkeypatch.setenv(
        "REPOAUDITOR_CORPUS_IDS", "independent_django_pre,independent_django_post"
    )
    assert benchmark_corpus_ids() == ["independent_django_pre", "independent_django_post"]

    monkeypatch.setenv("REPOAUDITOR_CORPUS_IDS", "not-a-fixture")
    try:
        benchmark_corpus_ids()
    except ValueError as exc:
        assert "not-a-fixture" in str(exc)
    else:
        raise AssertionError("unknown corpus selection must fail closed")


def test_pair_deltas_collapse_stable_candidates_without_discarding_raw_counts():
    stable = _candidate().model_dump()
    stable["producer"] = "semgrep"
    pre_only = _candidate(file="pre_only.py", line_start=20, line_end=20).model_dump()
    pre_only["producer"] = "semgrep"
    rows = [
        {
            "project_id": "example", "variant": "pre_fix",
            "candidates": [stable, pre_only],
        },
        {
            "project_id": "example", "variant": "post_fix",
            "candidates": [stable],
        },
    ]

    delta = build_pair_deltas(rows)[0]
    assert delta["stable_candidate_count"] == 1
    assert delta["pre_fix_only_candidate_count"] == 1
    assert delta["post_fix_only_candidate_count"] == 0
    assert delta["pair_collapsed_candidate_count"] == 2
