from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.config import AgentReadOnlyToolsConfig, load_config


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "docs/agentic-escalation-gate.md"
PROTOCOL = ROOT / (
    "docs/optimizations/opt-010-baseline-comparison-protocol-2026-08-18.json"
)
ARTIFACT = ROOT / (
    "docs/optimizations/opt-010-offline-containment-foundation-artifact-2026-08-18.json"
)
RESULT = ROOT / (
    "docs/optimizations/opt-010-offline-containment-foundation-result-2026-08-18.json"
)


def test_current_config_is_disabled_and_carries_exact_containment_bounds():
    tools = load_config(ROOT / "config.toml").falsify.agent_tools

    assert tools == AgentReadOnlyToolsConfig(
        enabled=False,
        allowlist=[
            "indexed_source_excerpt",
            "structural_slice",
            "callers",
            "references",
            "architecture_evidence",
        ],
        maximum_calls=12,
        maximum_results_per_call=5,
        maximum_context_lines=12,
        maximum_query_characters=256,
        maximum_response_bytes=32768,
    )


def test_allowlist_rejects_duplicates_and_unknown_tools():
    with pytest.raises(ValueError, match="unique"):
        AgentReadOnlyToolsConfig(
            allowlist=["callers", "callers"]
        )
    with pytest.raises(ValueError):
        AgentReadOnlyToolsConfig(allowlist=["shell"])


def test_g03a_protocol_is_frozen_while_g03b_remains_unauthorized():
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))

    assert protocol["status"] == "frozen-protocol-only-no-qualification-authority"
    assert set(protocol["arms"]) == {
        "current-bounded-falsifier",
        "proposed-read-only-tool-agent",
    }
    assert len(protocol["fixed_metrics"]) == 8
    assert protocol["current_authority"] == {
        "provider_calls": 0,
        "agentic_runs": 0,
        "baseline_executions": 0,
        "cohort_selections": 0,
        "outcomes_read": 0,
        "thresholds_selected": 0,
        "production_policy_changes": 0,
    }
    assert any("later exact qualification receipt" in item for item in protocol[
        "qualification_preconditions"
    ])


def test_gate_document_records_split_and_nonintegration_boundary():
    text = GATE.read_text(encoding="utf-8")

    assert "G03a protocol readiness" in text
    assert "G03b qualification" in text
    assert "grants no provider or experiment authority" in text
    assert "disabled-by-default" in text
    assert "not wired\n   into the challenger or CLI" in text


def test_aggregate_artifact_qualifies_only_g03a_and_g06():
    if not ARTIFACT.exists():
        return
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))

    assert artifact["gate_states_after"] == {
        "G01": "documented-pass",
        "G02": "partial",
        "G03a": "documented-pass",
        "G03b": "pending-separate-authorization",
        "G04": "partial",
        "G05": "partial",
        "G06": "documented-pass",
        "G07": "partial",
    }
    assert artifact["containment_qualification"]["all_required_tests_passed"] is True
    assert artifact["authority"]["agent_enabled"] is False
    assert artifact["authority"]["provider_calls"] == 0


def test_result_preserves_open_status_and_prohibits_g03b():
    if not RESULT.exists():
        return
    result = json.loads(RESULT.read_text(encoding="utf-8"))

    assert result["decision"]["opt_010_status"] == "open-deferred"
    assert result["decision"]["G03b_authorized"] is False
    assert result["decision"]["agentic_experiment_permitted"] is False
    assert result["store"]["before_sha256"] == result["store"]["after_sha256"]
