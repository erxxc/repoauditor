"""Tests for the triage->falsify budget seam in the repo-level `challenge()` runner.

Covers: the LLM budget caps how many candidates get the loop per run; candidates beyond
the cap are persisted `deferred` (not dropped) and resumed by a later run; a resumed run
never re-examines a finding it already challenged; deferred findings are unreachable by
the analyze gate; and the ordering is triage-first (highest P(actionable)) with an
untriaged severity fallback.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from repoauditor.detect import run_ensemble
from repoauditor.falsify import challenge
from repoauditor.falsify.challenger import (
    _budget_order,
    _budget_partition,
    _grouped_queue,
)
from repoauditor.ingest import ingest_repo
from repoauditor.map import recover_architecture
from repoauditor.llm import model_usage_scope
from repoauditor.store import db
from repoauditor.store.models import (
    FalsificationStatus,
    Finding,
    Severity,
    TriageModelRun,
    TriageResult,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _budget_config(tmp_config, n: int):
    return tmp_config.model_copy(update={
        "falsify": tmp_config.falsify.model_copy(update={"max_findings_per_run": n})})


def _detect(cfg, scripted_llm, repo_id="command_injection_svc") -> str:
    """Ingest -> map -> detect a fixture; returns the repo_id with unresolved findings."""
    result = ingest_repo(str(FIXTURES / repo_id / "snapshot"), cfg, repo_id=repo_id)
    recover_architecture(result.snapshot_path, result.repo_id, result.commit,
                         cfg, scripted_llm)
    run_ensemble(result.repo_id, cfg, llm=scripted_llm)
    return result.repo_id


def _status(cfg, repo_id, status):
    return [f for f in db.list_findings(repo_id, cfg) if f.falsification_status is status]


def _persist_triage_result(result, repo_id, cfg):
    run_id = db.insert_triage_model_run(TriageModelRun(
        repo_id=repo_id, model_name=result.model_name, model_version="test-fixture",
        feature_schema_version="test-fixture", training_label_count=0,
        evaluation_label_count=0, synthetic_share=1.0, synthetic_dropped=False,
        calibration="test-fixture", evaluation_basis="test-fixture",
        split_strategy="test-fixture", split_detail="test-only score fixture",
    ), cfg)
    return db.upsert_triage_result(result.model_copy(update={"triage_run_id": run_id}), cfg)


# --------------------------------------------------------------------------- #
# Budget defers the overflow (not drops it) and a later run resumes it.
# --------------------------------------------------------------------------- #
def test_budget_challenges_within_cap_and_defers_the_rest(
    tmp_config, scripted_llm, stub_deterministic_tools
):
    cfg = _budget_config(tmp_config, 1)
    db.init_db(cfg)
    repo_id = _detect(cfg, scripted_llm)
    assert len(db.list_findings(repo_id, cfg)) == 3  # 3 lens candidates, no tool noise

    out1 = challenge(repo_id, cfg, llm=scripted_llm)
    assert len(out1) == 1                              # only one within budget
    deferred = _status(cfg, repo_id, FalsificationStatus.DEFERRED)
    assert len(deferred) == 2
    for f in deferred:                                 # deferred, not dropped
        assert f.falsification_reason and "budget" in f.falsification_reason.lower()
        assert db.list_falsification_iterations(f.id, cfg) == []  # never examined

    # Deferred findings are unreachable by the analyze gate — not mistaken for a verdict.
    analyzable = {f.id for f in db.list_analyzable_findings(repo_id, cfg)}
    assert all(d.id not in analyzable for d in deferred)

    # Resume: the next run picks up a deferred one and does not re-examine the first.
    examined_after_run1 = db.finding_ids_with_iterations(repo_id, cfg)
    out2 = challenge(repo_id, cfg, llm=scripted_llm)
    assert len(out2) == 1
    assert examined_after_run1 < db.finding_ids_with_iterations(repo_id, cfg)  # grew by one
    assert len(_status(cfg, repo_id, FalsificationStatus.DEFERRED)) == 1

    # A third run drains the backlog completely.
    challenge(repo_id, cfg, llm=scripted_llm)
    assert _status(cfg, repo_id, FalsificationStatus.DEFERRED) == []


def test_unlimited_budget_challenges_everything_in_one_run(
    tmp_config, scripted_llm, stub_deterministic_tools
):
    cfg = _budget_config(tmp_config, 0)   # 0 = unlimited (pre-budget behavior)
    db.init_db(cfg)
    repo_id = _detect(cfg, scripted_llm)
    challenge(repo_id, cfg, llm=scripted_llm)
    assert _status(cfg, repo_id, FalsificationStatus.DEFERRED) == []
    assert db.finding_ids_with_iterations(repo_id, cfg)  # everything examined


def test_pipeline_call_capacity_safely_bounds_an_unlimited_falsify_queue(
    tmp_config, scripted_llm, stub_deterministic_tools
):
    # Default self-critique, three iterations, and two retries reserve 18 provider
    # attempts per finding. An 18-call run can safely schedule exactly one.
    cfg = _budget_config(tmp_config, 0).model_copy(update={
        "llm": tmp_config.llm.model_copy(update={
            "max_calls_per_pipeline_run": 18,
            "max_tokens_per_pipeline_run": 0,
        }),
    })
    db.init_db(cfg)
    repo_id = _detect(cfg, scripted_llm)
    pipeline = db.start_pipeline_run("fixture", cfg)

    with model_usage_scope(pipeline.id):
        result = challenge(repo_id, cfg, llm=scripted_llm)

    assert len(result) == 1
    assert result.pending_count == 3
    assert result.minimum_calls_per_finding == 2
    assert result.reserved_calls_per_finding == 18
    assert result.remaining_call_capacity == 18
    assert result.deferred_count == 2


# --------------------------------------------------------------------------- #
# Ordering: triaged (highest P(actionable)) first, then untriaged by severity.
# --------------------------------------------------------------------------- #
def test_budget_prioritizes_triaged_high_p_over_untriaged_severity(
    tmp_config, scripted_llm, stub_deterministic_tools
):
    cfg = _budget_config(tmp_config, 1)
    db.init_db(cfg)
    repo_id = _detect(cfg, scripted_llm)
    findings = db.list_findings(repo_id, cfg)

    # Give the *lowest-severity* finding a high P(actionable); leave the rest untriaged.
    low = next(f for f in findings if f.severity is Severity.LOW)
    _persist_triage_result(TriageResult(
        finding_id=low.id, p_actionable=0.95, rank=1, model_name="xgboost"), repo_id, cfg)

    challenge(repo_id, cfg, llm=scripted_llm)
    # Despite its low severity, the triaged finding is falsified first (tier 0 wins).
    assert db.finding_ids_with_iterations(repo_id, cfg) == {low.id}


def test_untriaged_findings_fall_back_to_severity_order(
    tmp_config, scripted_llm, stub_deterministic_tools
):
    cfg = _budget_config(tmp_config, 1)
    db.init_db(cfg)
    repo_id = _detect(cfg, scripted_llm)   # nothing triaged
    findings = db.list_findings(repo_id, cfg)

    challenge(repo_id, cfg, llm=scripted_llm)
    # With no triage, the highest-severity candidate is falsified first.
    critical = next(f for f in findings if f.severity is Severity.CRITICAL)
    assert db.finding_ids_with_iterations(repo_id, cfg) == {critical.id}


def _candidate(fid: int, *, severity=Severity.HIGH, lens="owasp", tool=None) -> Finding:
    return Finding(
        id=fid, repo_id="r", title=f"finding-{fid}", file="app.py",
        line_start=fid, line_end=fid, citation_snippet=f"code-{fid}",
        source_lens=lens if tool is None else None, source_tool=tool,
        confidence=0.8, severity=severity,
    )


def test_bounded_queue_reserves_a_slot_for_untriaged_novel_finding():
    deterministic = [_candidate(i, lens=None, tool="sast") for i in range(1, 5)]
    novel = _candidate(5, severity=Severity.CRITICAL)
    triage = {
        finding.id: TriageResult(
            finding_id=finding.id, p_actionable=1.0 - finding.id / 10,
            rank=finding.id, suppressed=(finding.id == 4), model_name="xgboost",
        )
        for finding in deterministic
    }
    ordered = _budget_order([*deterministic, novel], triage)

    selected, deferred = _budget_partition(ordered, triage, budget=3, min_untriaged=1)

    assert [finding.id for finding in selected] == [1, 2, 5]
    assert {finding.id for finding in deferred} == {3, 4}
    # Suppression remains an annotation: the suppressed candidate is deferred/resumable,
    # not deleted or excluded from the pending set.
    assert any(finding.id == 4 for finding in deferred)


def test_single_slot_budget_retains_existing_best_first_priority():
    deterministic = _candidate(1, lens=None, tool="sast")
    novel = _candidate(2, severity=Severity.CRITICAL)
    triage = {
        1: TriageResult(
            finding_id=1, p_actionable=0.9, rank=1, model_name="xgboost"
        )
    }
    ordered = _budget_order([novel, deterministic], triage)

    selected, deferred = _budget_partition(ordered, triage, budget=1, min_untriaged=1)

    assert [finding.id for finding in selected] == [1]
    assert [finding.id for finding in deferred] == [2]


def test_grouped_queue_uses_one_priority_aware_representative_per_issue():
    lower = _candidate(1, tool="sast")
    lower.identity_key = "advisory:pkg:CVE-2026-0001"
    higher = _candidate(2, tool="sca")
    higher.identity_key = lower.identity_key
    distinct = _candidate(3, tool="sca")
    distinct.identity_key = "advisory:pkg:CVE-2026-0002"
    triage = {
        2: TriageResult(
            finding_id=2, p_actionable=0.95, rank=1, model_name="xgboost"
        )
    }

    groups = _grouped_queue([lower, distinct, higher], triage)

    assert [representative.id for representative, _members in groups] == [2, 3]
    assert {member.id for member in groups[0][1]} == {1, 2}


def test_one_challenge_propagates_to_conservative_duplicate_group(
    tmp_config, scripted_llm, stub_deterministic_tools
):
    cfg = _budget_config(tmp_config, 1)
    db.init_db(cfg)
    repo_id = _detect(cfg, scripted_llm)
    original = db.list_findings(repo_id, cfg)[0]
    duplicate = original.model_copy(update={
        "id": None,
        "source_lens": "supply_chain",
        "source_tool": None,
        "confidence": max(0.0, original.confidence - 0.1),
    })
    duplicate_id = db.insert_finding(duplicate, cfg)
    _persist_triage_result(TriageResult(
        finding_id=original.id, p_actionable=0.99, rank=1, model_name="xgboost"
    ), repo_id, cfg)

    result = challenge(repo_id, cfg, llm=scripted_llm)

    challenged_id = next(iter(db.finding_ids_with_iterations(repo_id, cfg)))
    grouped_id = duplicate_id if challenged_id == original.id else original.id
    grouped = db.get_finding(grouped_id, cfg)
    assert len(result) == 1
    assert result.pending_count == 4
    assert result.pending_group_count == 3
    assert grouped.falsification_status is not FalsificationStatus.DEFERRED
    assert f"representative finding #{challenged_id}" in grouped.falsification_reason
    assert db.list_falsification_iterations(grouped_id, cfg) == []


def test_interrupted_examined_finding_is_not_stranded_as_deferred(
    tmp_config, scripted_llm, stub_deterministic_tools, monkeypatch
):
    from repoauditor.falsify import challenger
    from repoauditor.store.models import FalsificationIteration

    cfg = _budget_config(tmp_config, 1)
    db.init_db(cfg)
    repo_id = _detect(cfg, scripted_llm)
    interrupted_ids = []

    def interrupted(candidate, *_args, **_kwargs):
        interrupted_ids.append(candidate.id)
        db.insert_falsification_iteration(FalsificationIteration(
            finding_id=candidate.id,
            iteration=1,
            evidence="partial evidence",
            verdict_status=FalsificationStatus.UNRESOLVED,
            verdict_rationale="partial",
            verdict_confidence=0.4,
            critique_upholds=False,
            critique_note="provider interrupted",
            committed=False,
        ), cfg)
        raise KeyboardInterrupt()

    monkeypatch.setattr(challenger, "challenge_finding", interrupted)

    with pytest.raises(KeyboardInterrupt):
        challenge(repo_id, cfg, llm=scripted_llm)

    repaired = db.get_finding(interrupted_ids[0], cfg)
    assert repaired.falsification_status is FalsificationStatus.UNRESOLVED
    assert "Interrupted after persisted falsification iteration" in repaired.falsification_reason
    assert repaired.id not in {item.id for item in db.list_deferred_findings(repo_id, cfg)}
