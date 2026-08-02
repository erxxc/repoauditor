"""OPT-004 repeatability protocol stays frozen and measurement-specific."""

import json
from pathlib import Path


PROTOCOL = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-004-repeatability-protocol-2026-08-01.json"
)


def test_repeatability_protocol_is_identical_input_and_budget_gated():
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))

    assert protocol["optimization"] == "OPT-004"
    assert protocol["status"] == "protocol-frozen-budget-pending"
    assert protocol["subjects"]["count"] == 2
    assert protocol["repetitions_per_subject"] == 3
    assert protocol["budget_gate"]["observations"] == 6
    assert protocol["budget_gate"]["approval_required_before_calls"] is True
    assert protocol["instrument"] == {
        "profile": "standard",
        "max_iterations": 2,
        "local_context_lines": 10,
        "related_result_base": 2,
        "module_context_lines": 18,
        "max_evidence_chars": 12000,
        "self_critique": True,
        "minimum_iterations": 2,
        "persist_production_verdict": False,
        "fresh_pipeline_run_per_observation": True,
    }


def test_repeatability_protocol_has_no_success_threshold_or_production_effect():
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))

    assert protocol["interpretation"]["descriptive_only"] is True
    assert protocol["interpretation"]["pass_threshold"] is None
    assert "None" in protocol["interpretation"]["production_change"]
    assert any(
        "authoritative provider usage" in blocker for blocker in protocol["blockers"]
    )
