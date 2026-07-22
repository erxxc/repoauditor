"""Tests for the review stage — the blocking human-review checkpoint + audit trail.

Covers the definition of done: an `unresolved` finding produces a `ReviewRequest` and
is unreachable by any analyze-style query until a `ReviewDecision` is recorded; the
decision trail is append-only (corrections are new rows, never edits).
"""

from __future__ import annotations

import pytest

from repoauditor.review import (
    analyzable_findings,
    correct_decision,
    decision_history,
    effective_decision,
    is_blocked,
    open_review_requests,
    raise_review_requests,
    record_decision,
)
from repoauditor.store import db
from repoauditor.store.models import (
    FalsificationIteration,
    FalsificationStatus,
    Finding,
    ReviewDisposition,
    Severity,
    TriageModelRun,
    TriageResult,
)


def _finding(cfg, title, status=FalsificationStatus.UNRESOLVED, severity="high",
             file="app.py", line=10, tb_id=None):
    return db.insert_finding(
        Finding(
            repo_id="r", title=title, file=file, line_start=line, line_end=line,
            citation_snippet="dangerous(user_input)", source_tool="semgrep",
            confidence=0.6, severity=severity, falsification_status=status,
            trust_boundary_id=tb_id,
        ),
        cfg,
    )


def _persist_triage_result(result, cfg):
    run_id = db.insert_triage_model_run(TriageModelRun(
        repo_id="r", model_name=result.model_name, model_version="test-fixture",
        feature_schema_version="test-fixture", training_label_count=0,
        evaluation_label_count=0, synthetic_share=1.0, synthetic_dropped=False,
        calibration="test-fixture", evaluation_basis="test-fixture",
        split_strategy="test-fixture", split_detail="test-only score fixture",
    ), cfg)
    return db.upsert_triage_result(result.model_copy(update={"triage_run_id": run_id}), cfg)


# --------------------------------------------------------------------------- #
# The blocking checkpoint (DoD): unresolved -> request -> blocked until decision
# --------------------------------------------------------------------------- #
def test_unresolved_finding_is_blocked_until_a_decision_is_recorded(tmp_config):
    db.init_db(tmp_config)
    confirmed_id = _finding(tmp_config, "SQLi", status=FalsificationStatus.CONFIRMED)
    unresolved_id = _finding(tmp_config, "Maybe SSRF", status=FalsificationStatus.UNRESOLVED)

    # Before the checkpoint runs, nothing is held; both non-killed findings are analyzable.
    assert {f.id for f in analyzable_findings("r", tmp_config)} == {confirmed_id, unresolved_id}

    requests = raise_review_requests("r", tmp_config)
    assert [r.finding_id for r in requests] == [unresolved_id]

    # Now the unresolved finding is unreachable by the analyze-style query; the
    # confirmed one (no review request) still flows through.
    analyzable_ids = {f.id for f in analyzable_findings("r", tmp_config)}
    assert analyzable_ids == {confirmed_id}
    assert is_blocked(unresolved_id, tmp_config) is True
    assert is_blocked(confirmed_id, tmp_config) is False

    # A human confirms it -> the gate opens for that finding.
    request = db.get_review_request(unresolved_id, tmp_config)
    record_decision(request.id, reviewer="alice", disposition="confirm",
                    rationale="Traced the sink manually; it is reachable.", config=tmp_config)

    assert is_blocked(unresolved_id, tmp_config) is False
    assert {f.id for f in analyzable_findings("r", tmp_config)} == {confirmed_id, unresolved_id}


def test_dismiss_decision_keeps_finding_out_of_analysis(tmp_config):
    db.init_db(tmp_config)
    fid = _finding(tmp_config, "Noise", status=FalsificationStatus.UNRESOLVED)
    raise_review_requests("r", tmp_config)
    request = db.get_review_request(fid, tmp_config)

    record_decision(request.id, reviewer="bob", disposition="dismiss",
                    rationale="False positive; input is a constant.", config=tmp_config)

    # A recorded decision exists, but a dismissal does not release the finding — like a
    # killed candidate it stays in the store yet never reaches analysis.
    assert is_blocked(fid, tmp_config) is True
    assert analyzable_findings("r", tmp_config) == []
    assert len(db.list_findings("r", tmp_config)) == 1  # never deleted


def test_request_is_idempotent_and_carries_the_falsification_trace(tmp_config):
    db.init_db(tmp_config)
    fid = _finding(tmp_config, "Ambiguous", status=FalsificationStatus.UNRESOLVED)
    # A falsification iteration trace exists for the finding -> attached as evidence.
    for i in (1, 2, 3):
        db.insert_falsification_iteration(
            FalsificationIteration(
                finding_id=fid, iteration=i, evidence="no mitigating control found",
                verdict_status=FalsificationStatus.CONFIRMED, verdict_rationale="maybe",
                verdict_confidence=0.3, critique_upholds=False,
                critique_note="reachability not established", committed=False,
            ),
            tmp_config,
        )

    raise_review_requests("r", tmp_config)
    raise_review_requests("r", tmp_config)  # re-run must not duplicate
    requests = db.list_review_requests("r", tmp_config)
    assert len(requests) == 1
    req = requests[0]
    assert req.stage == "falsify"
    assert len(req.evidence["falsification_trace"]) == 3
    assert req.evidence["citation"]


# --------------------------------------------------------------------------- #
# Triage uncertainty routes to review
# --------------------------------------------------------------------------- #
def test_uncertain_triage_result_creates_a_review_request(tmp_config):
    db.init_db(tmp_config)
    uncertain_id = _finding(tmp_config, "Uncertain", status=FalsificationStatus.CONFIRMED)
    confident_id = _finding(tmp_config, "Confident", status=FalsificationStatus.CONFIRMED,
                            line=20)
    _persist_triage_result(TriageResult(
        finding_id=uncertain_id, p_actionable=0.5, rank=1, model_name="xgboost",
        attributions=[{"feature": "cwe_is_injection", "value": 0.0, "contribution": 0.1}],
    ), tmp_config)
    _persist_triage_result(TriageResult(
        finding_id=confident_id, p_actionable=0.96, rank=2, model_name="xgboost",
    ), tmp_config)

    requests = raise_review_requests("r", tmp_config)
    held = {r.finding_id: r for r in requests}
    assert set(held) == {uncertain_id}                 # only the uncertain one
    assert held[uncertain_id].stage == "triage"
    assert held[uncertain_id].evidence["triage"]["p_actionable"] == 0.5
    # The confident finding is analyzable; the uncertain one is blocked.
    assert {f.id for f in analyzable_findings("r", tmp_config)} == {confident_id}


def test_unresolved_status_takes_precedence_over_triage_uncertainty(tmp_config):
    db.init_db(tmp_config)
    fid = _finding(tmp_config, "Both", status=FalsificationStatus.UNRESOLVED)
    _persist_triage_result(TriageResult(
        finding_id=fid, p_actionable=0.5, rank=1, model_name="randomforest",
    ), tmp_config)

    requests = raise_review_requests("r", tmp_config)
    assert len(requests) == 1
    assert requests[0].stage == "falsify"  # unresolved wins over the triage-uncertainty


def test_suppressed_quality_control_sample_is_deterministic_and_auditable(tmp_config):
    db.init_db(tmp_config)
    ids = [
        _finding(
            tmp_config, f"Suppressed {index}", status=FalsificationStatus.CONFIRMED,
            line=20 + index,
        )
        for index in range(3)
    ]
    for rank, finding_id in enumerate(ids, start=1):
        _persist_triage_result(TriageResult(
            finding_id=finding_id, p_actionable=0.1 * rank, rank=rank,
            suppressed=True, model_name="xgboost",
        ), tmp_config)

    first = raise_review_requests("r", tmp_config, sampling_run_id=42)
    second = raise_review_requests("r", tmp_config, sampling_run_id=42)

    assert len(first) == len(second) == 1
    assert first[0].finding_id == second[0].finding_id
    assert first[0].stage == "triage-sample"
    assert first[0].evidence["sampling"] == {
        "kind": "low_rank_quality_control",
        "seed": 0,
        "pipeline_run_id": 42,
        "selection_scope": "r",
    }
    assert first[0].evidence["triage"]["suppressed"] is True
    assert len(db.list_review_requests("r", tmp_config)) == 1


def test_standalone_checkpoint_does_not_open_a_new_sampling_batch(tmp_config):
    db.init_db(tmp_config)
    finding_id = _finding(
        tmp_config, "Suppressed", status=FalsificationStatus.CONFIRMED
    )
    _persist_triage_result(TriageResult(
        finding_id=finding_id, p_actionable=0.1, rank=1, suppressed=True,
        model_name="xgboost",
    ), tmp_config)

    assert raise_review_requests("r", tmp_config) == []
    assert db.list_review_requests("r", tmp_config) == []


def test_quality_control_sample_does_not_create_killed_review_override_conflict(tmp_config):
    db.init_db(tmp_config)
    finding_id = _finding(tmp_config, "Killed", status=FalsificationStatus.KILLED)
    _persist_triage_result(TriageResult(
        finding_id=finding_id, p_actionable=0.1, rank=1, suppressed=True,
        model_name="xgboost",
    ), tmp_config)

    assert raise_review_requests("r", tmp_config, sampling_run_id=7) == []


# --------------------------------------------------------------------------- #
# Append-only audit trail: corrections are new rows, never edits
# --------------------------------------------------------------------------- #
def test_decision_trail_is_append_only_and_corrections_supersede(tmp_config):
    db.init_db(tmp_config)
    fid = _finding(tmp_config, "Reconsidered", status=FalsificationStatus.UNRESOLVED)
    raise_review_requests("r", tmp_config)
    request = db.get_review_request(fid, tmp_config)

    first = record_decision(request.id, reviewer="alice", disposition="dismiss",
                            rationale="Looks like a false positive.", config=tmp_config)
    # Later, a second reviewer overrides — a NEW row that supersedes, not an edit.
    second = correct_decision(first.id, reviewer="carol", disposition="confirm",
                              rationale="On closer look the sink is reachable.",
                              config=tmp_config)

    history = decision_history(request.id, tmp_config)
    assert [d.id for d in history] == [first.id, second.id]      # both rows survive
    assert history[0].disposition is ReviewDisposition.DISMISS   # original untouched
    assert history[1].supersedes_id == first.id                  # correction linked
    # The effective ruling is the latest, and it releases the finding.
    assert effective_decision(request.id, tmp_config).id == second.id
    assert is_blocked(fid, tmp_config) is False


def test_record_decision_requires_a_rationale_and_a_real_request(tmp_config):
    db.init_db(tmp_config)
    with pytest.raises(ValueError):
        record_decision(999, reviewer="x", disposition="confirm",
                        rationale="ok", config=tmp_config)  # no such request

    fid = _finding(tmp_config, "R", status=FalsificationStatus.UNRESOLVED)
    raise_review_requests("r", tmp_config)
    request = db.get_review_request(fid, tmp_config)
    with pytest.raises(ValueError):
        record_decision(request.id, reviewer="x", disposition="confirm",
                        rationale="   ", config=tmp_config)  # blank rationale


def test_open_review_requests_lists_only_undecided(tmp_config):
    db.init_db(tmp_config)
    a = _finding(tmp_config, "A", status=FalsificationStatus.UNRESOLVED, line=1)
    b = _finding(tmp_config, "B", status=FalsificationStatus.UNRESOLVED, line=2)
    raise_review_requests("r", tmp_config)
    req_a = db.get_review_request(a, tmp_config)

    record_decision(req_a.id, reviewer="alice", disposition="confirm",
                    rationale="reachable", config=tmp_config)

    pending = open_review_requests("r", tmp_config)
    assert [p.finding_id for p in pending] == [b]  # only the still-undecided one
