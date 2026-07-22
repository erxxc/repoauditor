"""Tests for the triage->falsify budget seam in the repo-level `challenge()` runner.

Covers: the LLM budget caps how many candidates get the loop per run; candidates beyond
the cap are persisted `deferred` (not dropped) and resumed by a later run; a resumed run
never re-examines a finding it already challenged; deferred findings are unreachable by
the analyze gate; and the ordering is triage-first (highest P(actionable)) with an
untriaged severity fallback.
"""

from __future__ import annotations

from pathlib import Path

from repoauditor.detect import run_ensemble
from repoauditor.falsify import challenge
from repoauditor.ingest import ingest_repo
from repoauditor.map import recover_architecture
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, Severity, TriageResult

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


# --------------------------------------------------------------------------- #
# Budget defers the overflow (not drops it) and a later run resumes it.
# --------------------------------------------------------------------------- #
def test_budget_challenges_within_cap_and_defers_the_rest(tmp_config, scripted_llm):
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


def test_unlimited_budget_challenges_everything_in_one_run(tmp_config, scripted_llm):
    cfg = _budget_config(tmp_config, 0)   # 0 = unlimited (pre-budget behavior)
    db.init_db(cfg)
    repo_id = _detect(cfg, scripted_llm)
    challenge(repo_id, cfg, llm=scripted_llm)
    assert _status(cfg, repo_id, FalsificationStatus.DEFERRED) == []
    assert db.finding_ids_with_iterations(repo_id, cfg)  # everything examined


# --------------------------------------------------------------------------- #
# Ordering: triaged (highest P(actionable)) first, then untriaged by severity.
# --------------------------------------------------------------------------- #
def test_budget_prioritizes_triaged_high_p_over_untriaged_severity(tmp_config, scripted_llm):
    cfg = _budget_config(tmp_config, 1)
    db.init_db(cfg)
    repo_id = _detect(cfg, scripted_llm)
    findings = db.list_findings(repo_id, cfg)

    # Give the *lowest-severity* finding a high P(actionable); leave the rest untriaged.
    low = next(f for f in findings if f.severity is Severity.LOW)
    db.upsert_triage_result(TriageResult(
        finding_id=low.id, p_actionable=0.95, rank=1, model_name="xgboost"), cfg)

    challenge(repo_id, cfg, llm=scripted_llm)
    # Despite its low severity, the triaged finding is falsified first (tier 0 wins).
    assert db.finding_ids_with_iterations(repo_id, cfg) == {low.id}


def test_untriaged_findings_fall_back_to_severity_order(tmp_config, scripted_llm):
    cfg = _budget_config(tmp_config, 1)
    db.init_db(cfg)
    repo_id = _detect(cfg, scripted_llm)   # nothing triaged
    findings = db.list_findings(repo_id, cfg)

    challenge(repo_id, cfg, llm=scripted_llm)
    # With no triage, the highest-severity candidate is falsified first.
    critical = next(f for f in findings if f.severity is Severity.CRITICAL)
    assert db.finding_ids_with_iterations(repo_id, cfg) == {critical.id}
