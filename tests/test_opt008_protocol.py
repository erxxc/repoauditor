"""Frozen OPT-008 Ruby certificate scope remains bound to its reviewed evidence."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
PROTOCOL_PATH = (
    ROOT / "docs" / "optimizations"
    / "opt-008-ruby-deserialization-protocol-2026-08-01.json"
)
MANIFEST_PATH = (
    ROOT / "tests" / "fixtures" / "manufactured_certificate_controls" / "manifest.json"
)


def test_opt008_protocol_is_bound_to_reviewed_pinned_target():
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    source_path = (PROTOCOL_PATH.parent / protocol["evidence_gate"]["target_source"]).resolve()
    cohort = json.loads(source_path.read_text(encoding="utf-8"))
    target = next(
        item for item in cohort["targets"]
        if item["mechanism"] == "unsafe-deserialization"
    )

    assert protocol["optimization"] == "OPT-008"
    assert protocol["evidence_gate"]["status"] == "satisfied"
    assert target["pinned_commit"] == protocol["evidence_gate"]["target_commit"]
    assert target["citation_contains"] == "Marshal.load(Base64.decode64(params[:user]))"


def test_opt008_frozen_controls_match_external_answer_key():
    protocol = json.loads(PROTOCOL_PATH.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    expected = {
        case["id"]: case["expected_verification"]
        for case in manifest["cases"] if case["id"].startswith("ruby-marshal-")
    }

    assert {item["id"]: item["expected"] for item in protocol["controls"]} == expected
    assert len(protocol["acceptance"]) == 4
    assert len(protocol["non_claims"]) == 3
