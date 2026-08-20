from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.eval.opt010_paired_foundation import (
    ContractError,
    PairedObservation,
    SyntheticOutcome,
    TerminalState,
    build_eval_tool_session,
    eval_tool_config,
    evaluate_paired,
    validate_complete_pairs,
)
from repoauditor.falsify.read_only_tools import ToolBoundaryError
from repoauditor.map import ArchitectureMap, EntryPoint
from repoauditor.store.models import Finding, Severity


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-010-offline-paired-evaluation-foundation-result-2026-08-20.json"


def _pair(
    identity: str,
    *,
    outcome: SyntheticOutcome,
    baseline: TerminalState,
    agent: TerminalState,
    family: str = "family-a",
    language: str = "Python",
    mechanism: str | None = "ssrf",
    detector: str = "semgrep",
    baseline_cost: float | None = 1.0,
    agent_cost: float | None = 0.8,
    usage_available: bool = True,
) -> list[PairedObservation]:
    common = {
        "identity": identity,
        "source_family": family,
        "language": language,
        "mechanism": mechanism,
        "detector": detector,
        "outcome": outcome,
        "usage_available": usage_available,
        "provider_tokens": 100 if usage_available else None,
        "provider_latency_ms": 20 if usage_available else None,
    }
    return [
        PairedObservation(arm="baseline", terminal_state=baseline, known_cost_usd=baseline_cost, **common),
        PairedObservation(arm="agent", terminal_state=agent, known_cost_usd=agent_cost, **common),
    ]


def _balanced_pairs() -> list[PairedObservation]:
    rows: list[PairedObservation] = []
    rows += _pair("a1", outcome=SyntheticOutcome.ACTIONABLE, baseline=TerminalState.CONFIRMED, agent=TerminalState.CONFIRMED)
    rows += _pair("a2", outcome=SyntheticOutcome.NON_ACTIONABLE, baseline=TerminalState.CONFIRMED, agent=TerminalState.KILLED)
    rows += _pair("a3", outcome=SyntheticOutcome.NON_ACTIONABLE, baseline=TerminalState.KILLED, agent=TerminalState.KILLED)
    return rows


def test_eval_tool_configuration_is_exact_and_local():
    config = eval_tool_config()
    assert config.enabled is True
    assert config.maximum_calls == 12
    assert config.maximum_results_per_call == 5
    assert config.maximum_context_lines == 12


def test_existing_read_only_facade_is_the_only_tool_surface(tmp_path: Path):
    source = tmp_path / "app.py"
    source.write_text("def fetch(url):\n    return requests.get(url)\n", encoding="utf-8")
    index = RetrievalIndex().build(tmp_path)
    finding = Finding(
        repo_id="synthetic", title="synthetic ssrf", file="app.py",
        line_start=2, line_end=2, citation_snippet="return requests.get(url)",
        source_tool="synthetic", confidence=0.5, severity=Severity.HIGH,
    )
    architecture = ArchitectureMap(
        repo_id="synthetic", commit="abc123",
        entry_points=[EntryPoint(name="fetch", location="app.py:1")],
    )
    session = build_eval_tool_session(
        index=index, finding=finding, architecture=architecture,
        snapshot_commit="abc123", expected_index_digest=index.content_digest(),
    )
    result = session.request("indexed_source_excerpt", file="app.py", line_start=2, line_end=2)
    assert result.provenance["surface_version"] == "agent_read_only_tools_v1"
    with pytest.raises(ToolBoundaryError, match="allowlist"):
        session.request("filesystem", path="app.py")


def test_tool_session_fails_closed_on_index_digest_drift(tmp_path: Path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    index = RetrievalIndex().build(tmp_path)
    finding = Finding(
        repo_id="synthetic", title="synthetic", file="app.py", line_start=1,
        line_end=1, citation_snippet="value = 1", source_tool="synthetic",
        confidence=0.5, severity=Severity.LOW,
    )
    session = build_eval_tool_session(
        index=index, finding=finding,
        architecture=ArchitectureMap(repo_id="synthetic", commit="abc123"),
        snapshot_commit="abc123", expected_index_digest="sha256:drift",
    )
    with pytest.raises(ToolBoundaryError, match="digest drift"):
        session.request("structural_slice")


def test_pairing_rejects_missing_and_duplicate_arm_observations():
    rows = _pair("a1", outcome=SyntheticOutcome.ACTIONABLE, baseline=TerminalState.CONFIRMED, agent=TerminalState.CONFIRMED)
    with pytest.raises(ContractError, match="missing arm"):
        validate_complete_pairs(rows[:1])
    with pytest.raises(ContractError, match="duplicate arm"):
        validate_complete_pairs([*rows, rows[1]])


def test_unsupported_languages_remain_paired_outer_denominator_states():
    rows = _pair(
        "go1", outcome=SyntheticOutcome.NON_ACTIONABLE,
        baseline=TerminalState.VERIFIER_UNSUPPORTED,
        agent=TerminalState.VERIFIER_UNSUPPORTED,
        language="Go", mechanism=None,
    )
    assert validate_complete_pairs(rows) == 1
    bad = [rows[0], PairedObservation(**{
        **rows[1].__dict__, "terminal_state": TerminalState.KILLED
    })]
    with pytest.raises(ContractError, match="verifier_unsupported"):
        validate_complete_pairs(bad)


def test_outcomes_are_required_for_empirical_evaluation():
    rows = _pair("a1", outcome=SyntheticOutcome.ACTIONABLE, baseline=TerminalState.CONFIRMED, agent=TerminalState.CONFIRMED)
    rows = [PairedObservation(**{**item.__dict__, "outcome": None}) for item in rows]
    with pytest.raises(ContractError, match="outcomes remain unavailable"):
        evaluate_paired(rows)


def test_monotonic_recall_rule_blocks_a_silent_agent_kill():
    rows = _pair("a1", outcome=SyntheticOutcome.ACTIONABLE, baseline=TerminalState.CONFIRMED, agent=TerminalState.KILLED)
    rows += _pair("a2", outcome=SyntheticOutcome.NON_ACTIONABLE, baseline=TerminalState.KILLED, agent=TerminalState.KILLED)
    result = evaluate_paired(rows)
    assert result["G04_pass"] is False
    assert result["monotonic_recall_failures"] == ["a1"]


def test_pareto_improvement_can_pass_on_balanced_reportable_data():
    result = evaluate_paired(_balanced_pairs())
    assert result["G04_pass"] is True
    assert result["G03b_pass"] is True
    assert result["agent"].precision == 1.0
    assert result["baseline"].precision == 0.5


def test_unknown_usage_blocks_g03b_without_becoming_zero():
    rows = _balanced_pairs()
    rows[0] = PairedObservation(**{
        **rows[0].__dict__, "usage_available": False,
        "provider_tokens": None, "provider_latency_ms": None, "known_cost_usd": None,
    })
    result = evaluate_paired(rows)
    assert result["G03b_pass"] is False
    assert result["baseline"].known_cost_usd is None


def test_zero_positive_or_confirmed_denominators_block_a_pass():
    rows = _pair("n1", outcome=SyntheticOutcome.NON_ACTIONABLE, baseline=TerminalState.KILLED, agent=TerminalState.KILLED)
    result = evaluate_paired(rows)
    assert result["baseline"].recall is None
    assert result["G03b_pass"] is False


def test_one_class_subgroups_are_explicitly_unavailable():
    rows = _balanced_pairs()
    rows += _pair(
        "b1", outcome=SyntheticOutcome.ACTIONABLE,
        baseline=TerminalState.CONFIRMED, agent=TerminalState.CONFIRMED,
        family="family-b",
    )
    result = evaluate_paired(rows)
    assert result["unavailable_subgroups"]["source_family"] == ["family-b"]
    assert result["G03b_pass"] is False


def test_result_documents_only_offline_foundation_readiness():
    if not RESULT.exists():
        pytest.skip("result is generated after the initial synthetic qualification")
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    assert payload["status"] == "complete-offline-paired-evaluation-foundation"
    assert payload["gate_assessment"]["G03b"] == "pending-prospective-packet-run-review-outcomes"
    assert payload["gate_assessment"]["G04_empirical"] == "pending-blinded-human-outcomes"
    assert payload["gate_assessment"]["OPT_010_status"] == "open-deferred"
    assert payload["store"]["before_sha256"] == payload["store"]["after_sha256"]
