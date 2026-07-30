"""Contract tests for mechanism-specific scanner pre/post qualification."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.detect.ensemble import CandidateFinding
from repoauditor.eval.scanner_differential import (
    AdvisoryTargetSpec,
    DifferentialClassification,
    classify_advisory_pair,
)
from repoauditor.store.models import Severity


RULE_ID = "repoauditor.javascript.security.dynamic-shell-execution"
CONTROL_ROOT = (
    Path(__file__).parent / "fixtures" / "semgrep_supplemental_shell_controls"
)
TARGET = AdvisoryTargetSpec(
    file="lib/codecov.js",
    rule_ids=(RULE_ID,),
    citation_contains="execSync(gcov)",
    line_start=386,
    line_end=417,
)


def _candidate(**updates) -> CandidateFinding:
    values = {
        "title": RULE_ID,
        "file": "lib/codecov.js",
        "line_start": 417,
        "line_end": 417,
        "citation_snippet": "execSync(gcov)",
        "source_tool": "sast",
        "producer": "semgrep-supplemental",
        "confidence": 0.7,
        "severity": Severity.HIGH,
    }
    values.update(updates)
    return CandidateFinding(**values)


@pytest.mark.parametrize(
    ("pre", "post", "expected"),
    [
        ([_candidate()], [], DifferentialClassification.VULNERABLE_ONLY_RECOVERY),
        (
            [_candidate()],
            [_candidate()],
            DifferentialClassification.STABLE_PRE_POST_MECHANISM_SIGNAL,
        ),
        ([], [_candidate()], DifferentialClassification.PATCHED_ONLY_SIGNAL),
        ([], [], DifferentialClassification.COMPLETE_MISS),
    ],
)
def test_classifies_all_target_differential_outcomes(pre, post, expected):
    result = classify_advisory_pair(
        pre_candidates=pre,
        post_candidates=post,
        target=TARGET,
    )

    assert result.classification is expected


def test_requires_rule_file_citation_and_line_to_count_as_target():
    near_misses = [
        _candidate(title="official.unrelated-rule"),
        _candidate(file="test/codecov.test.js"),
        _candidate(citation_snippet="execSync(constantCommand)"),
        _candidate(line_start=500, line_end=500),
    ]

    result = classify_advisory_pair(
        pre_candidates=near_misses,
        post_candidates=[],
        target=TARGET,
    )

    assert result.classification is DifferentialClassification.COMPLETE_MISS
    assert result.unrelated_pre_only_count == 4


def test_accounts_for_unrelated_churn_without_calling_it_target_recovery():
    stable = _candidate(
        title="official.mutable-action",
        file=".github/workflows/nodejs.yml",
        line_start=15,
        line_end=15,
        citation_snippet="uses: actions/checkout@v2",
        producer="semgrep",
    )
    pre_only = _candidate(
        title="official.pre-only",
        file="lib/legacy.js",
        line_start=20,
        line_end=20,
        citation_snippet="legacy()",
        producer="semgrep",
    )
    post_only = _candidate(
        title="official.post-only",
        file="lib/replacement.js",
        line_start=21,
        line_end=21,
        citation_snippet="replacement()",
        producer="semgrep",
    )

    result = classify_advisory_pair(
        pre_candidates=[_candidate(), stable, pre_only],
        post_candidates=[stable, post_only],
        target=TARGET,
    )

    assert result.classification is DifferentialClassification.VULNERABLE_ONLY_RECOVERY
    assert result.pre_candidate_count == 3
    assert result.post_candidate_count == 2
    assert result.unrelated_stable_count == 1
    assert result.unrelated_pre_only_count == 1
    assert result.unrelated_post_only_count == 1
    assert "unadjudicated" in result.claim_boundary


def test_manufactured_control_manifest_has_balanced_citation_valid_cases():
    manifest = json.loads((CONTROL_ROOT / "manifest.json").read_text())
    cases = manifest["cases"]

    assert manifest["rule_id"] == RULE_ID
    assert {case["expected_detection"] for case in cases} == {"raised", "absent"}
    assert len(cases) == 4
    assert len({case["id"] for case in cases}) == len(cases)
    for case in cases:
        source = CONTROL_ROOT / "snapshot" / case["file"]
        lines = source.read_text().splitlines()
        cited = "\n".join(lines[case["line_start"] - 1:case["line_end"]])
        assert case["citation_snippet"] in cited
