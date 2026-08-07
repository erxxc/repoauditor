"""OPT-002 independent acquisition is frozen before any outcome is observed."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = (
    ROOT
    / "docs/optimizations/opt-002-independent-acquisition-protocol-2026-08-07.json"
)


def _protocol() -> dict:
    return json.loads(PROTOCOL.read_text(encoding="utf-8"))


def test_sources_are_immutable_independent_and_reserve_is_conditional():
    payload = _protocol()
    sources = payload["frozen_sources"]

    assert payload["status"] == "protocol-frozen-execution-not-authorized"
    assert [source["role"] for source in sources] == [
        "primary",
        "primary",
        "reserve-only",
    ]
    assert len({source["evaluation_family"] for source in sources}) == 3
    assert all(len(source["commit"]) == 40 for source in sources)
    assert all(not source["public_metadata_at_freeze"]["fork"] for source in sources)
    assert all(not source["public_metadata_at_freeze"]["archived"] for source in sources)
    assert sources[-1]["activation_condition"]

    for source in sources:
        identity = f'{source["url"]}@{source["commit"]}'.encode()
        assert source["source_identity_digest"] == (
            f"sha256:{hashlib.sha256(identity).hexdigest()}"
        )


def test_protocol_freezes_compatible_scoring_before_blind_review():
    payload = _protocol()
    identity = payload["frozen_scoring_identity"]
    selection = payload["review_selection"]

    assert identity == {
        "source_model_run_id": 32,
        "model_name": "xgboost",
        "model_version": "3.3.0",
        "feature_schema_version": "sha256:89450a98dd4cdc1c",
        "calibration": "isotonic",
        "scanner_versions": {"Semgrep OSS": "1.170.0"},
        "compatibility_rule": identity["compatibility_rule"],
    }
    assert payload["execution_sequence"].index(
        "Extract features and score every eligible finding with the frozen scoring identity before any human sees a review packet."
    ) < payload["execution_sequence"].index(
        "Have analysts review bounded source evidence with abstention available and without classifier scores or expected outcomes."
    )
    assert selection["packet_size_minimum"] == 8
    assert selection["packet_size_maximum"] == 12
    assert selection["abstentions_preserved"] is True
    assert {"score", "predicted class", "human or scanner outcome"} <= set(
        selection["forbidden_selection_fields"]
    )


def test_protocol_authorizes_no_execution_or_provider_transfer():
    boundary = _protocol()["authorization_boundary"]

    assert "repository materialization" in boundary["not_authorized"]
    assert "fresh scanning" in boundary["not_authorized"]
    assert "provider or LLM calls" in boundary["not_authorized"]
    assert "store mutation" in boundary["not_authorized"]
    assert "model training or tuning" in boundary["not_authorized"]


def test_protocol_retains_the_live_gate_and_fails_closed():
    payload = _protocol()
    gate = payload["current_gate"]

    assert gate["compatible_scored_human_labels"] == 36
    assert gate["compatible_positive"] > 0
    assert gate["compatible_negative"] > 0
    assert gate["minimum_compatible_labels"] == 40
    assert gate["minimum_evaluation_families"] == 8
    assert any(
        "fewer than eight eligible candidates" in rule
        for rule in payload["fail_closed_rules"]
    )
    assert any("keep OPT-002 gated" in rule for rule in payload["fail_closed_rules"])
