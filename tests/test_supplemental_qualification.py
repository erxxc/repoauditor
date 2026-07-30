"""Frozen OPT-027/028 qualification receipt and runner contracts."""

from __future__ import annotations

import json
from pathlib import Path

from repoauditor.detect.ensemble import CandidateFinding
from repoauditor.store.models import Severity

from fixtures.run_supplemental_semgrep_qualification import (
    PROTOCOL_PATH,
    _control_results,
    tree_digest,
)


REPO_ROOT = Path(__file__).parent.parent
RESULTS = (
    REPO_ROOT
    / "docs"
    / "optimizations"
    / "opt-027-028-supplemental-differential-results-2026-07-29.json"
)


def test_runner_reproduces_frozen_manufactured_control_digest():
    protocol = json.loads(PROTOCOL_PATH.read_text())
    control = protocol["manufactured_controls"]
    snapshot = (PROTOCOL_PATH.parent / control["snapshot"]).resolve()

    assert tree_digest(snapshot) == control["snapshot_tree_sha256"]


def test_control_evaluation_requires_expected_file_and_range():
    manifest = {
        "rule_id": "owned.rule",
        "cases": [{
            "id": "positive",
            "file": "service.js",
            "line_start": 4,
            "line_end": 4,
            "expected_detection": "raised",
        }],
    }
    candidate = CandidateFinding(
        title="owned.rule",
        file="service.js",
        line_start=4,
        line_end=4,
        citation_snippet="execSync(command)",
        source_tool="sast",
        producer="semgrep-supplemental",
        confidence=0.7,
        severity=Severity.HIGH,
    )

    assert _control_results(manifest, [candidate]) == [{
        "id": "positive",
        "expected": "raised",
        "observed": "raised",
        "passed": True,
        "match_count": 1,
    }]


def test_committed_qualification_receipt_preserves_evidence_boundary():
    receipt = json.loads(RESULTS.read_text())
    codecov = next(
        pair for pair in receipt["pairs"]
        if pair["slug"] == "codecov_node_cve_2020_15123"
    )

    assert receipt["status"] == "qualified"
    assert receipt["manufactured_controls"]["passed"] is True
    assert (
        codecov["advisory_target_classification"]["classification"]
        == "vulnerable_only_recovery"
    )
    assert receipt["promotion"] == {
        "criteria_passed": True,
        "production_integration_enabled": True,
    }
    assert receipt["isolation"]["automatic_labels_added"] == 0
    assert receipt["isolation"]["review_pool_candidates_added"] == 0
    assert receipt["prior_failed_attempt"]["sha256"]
