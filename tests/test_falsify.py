"""Tests for the falsification challenger's bounded observe-think-act-reflect loop.

Covers the definition of done: a confident, self-critique-upheld verdict commits early;
a deliberately-ambiguous case runs multiple iterations, logs each one, and degrades to
`unresolved` at the configured limit rather than forcing a verdict; and the self-critique
step can veto a shaky verdict the confidence gate alone would have accepted.
"""

from __future__ import annotations

from repoauditor.config import FalsifyConfig
from repoauditor.falsify import challenge_finding
from repoauditor.falsify.outcome import FalsificationOutcome, SelfCritique
from repoauditor.llm import LLMClient, ScriptedBackend
from repoauditor.map import ArchitectureMap
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, Finding

ARCH = ArchitectureMap(repo_id="r", commit="deadbeef")


def _handler(verdict_status, verdict_conf, upholds, critique_conf=0.9):
    def handler(system, user, schema, context):
        if schema is SelfCritique:
            return SelfCritique(upholds=upholds, concern="scripted critique",
                                confidence=critique_conf)
        return FalsificationOutcome(status=verdict_status, rationale="scripted verdict",
                                    reachable=True, confidence=verdict_conf)
    return handler


def _persist_unresolved(cfg, title="Candidate") -> Finding:
    finding = Finding(
        repo_id="r", title=title, file="svc.py", line_start=21, line_end=21,
        citation_snippet='os.popen("ping " + host)', source_tool="semgrep",
        confidence=0.6, severity="critical",
        falsification_status=FalsificationStatus.UNRESOLVED,
    )
    fid = db.insert_finding(finding, cfg)
    return finding.model_copy(update={"id": fid})


def _challenge(cfg, handler, finding):
    return challenge_finding(finding, ARCH, LLMClient(ScriptedBackend(handler), cfg),
                             index=None, config=cfg)


# --------------------------------------------------------------------------- #
# Early commit on a confident, self-critique-upheld verdict
# --------------------------------------------------------------------------- #
def test_confident_upheld_verdict_commits_on_first_iteration(tmp_config):
    db.init_db(tmp_config)
    finding = _persist_unresolved(tmp_config, "Command injection")
    outcome = _challenge(tmp_config, _handler(FalsificationStatus.CONFIRMED, 0.9, True), finding)

    assert outcome.status is FalsificationStatus.CONFIRMED
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert len(trace) == 1                  # committed early, did not burn the budget
    assert trace[0].committed is True
    assert trace[0].critique_upholds is True


def test_confident_kill_commits_and_is_logged(tmp_config):
    db.init_db(tmp_config)
    finding = _persist_unresolved(tmp_config, "False positive")
    outcome = _challenge(tmp_config, _handler(FalsificationStatus.KILLED, 0.9, True), finding)

    assert outcome.status is FalsificationStatus.KILLED
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert len(trace) == 1 and trace[0].committed is True


# --------------------------------------------------------------------------- #
# Degrade to unresolved at the limit (DoD): logs every iteration, forces nothing
# --------------------------------------------------------------------------- #
def test_low_confidence_verdict_exhausts_budget_and_degrades_to_unresolved(tmp_config):
    db.init_db(tmp_config)
    finding = _persist_unresolved(tmp_config, "Ambiguous input")
    # Verdict is a confident-sounding CONFIRMED, but confidence stays below threshold.
    outcome = _challenge(tmp_config, _handler(FalsificationStatus.CONFIRMED, 0.3, True), finding)

    assert outcome.status is FalsificationStatus.UNRESOLVED
    assert "unresolved" in outcome.rationale.lower()
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert len(trace) == 3                       # ran the full (default) budget
    assert all(it.committed is False for it in trace)   # never forced a verdict


def test_iteration_limit_is_config_driven(tmp_config):
    cfg = tmp_config.model_copy(update={"falsify": FalsifyConfig(max_iterations=2)})
    db.init_db(cfg)
    finding = _persist_unresolved(cfg, "Ambiguous")
    outcome = _challenge(cfg, _handler(FalsificationStatus.CONFIRMED, 0.3, True), finding)

    assert outcome.status is FalsificationStatus.UNRESOLVED
    assert len(db.list_falsification_iterations(finding.id, cfg)) == 2


# --------------------------------------------------------------------------- #
# Self-critique can veto a verdict the confidence gate alone would have accepted
# --------------------------------------------------------------------------- #
def test_self_critique_veto_blocks_a_confident_but_unsupported_verdict(tmp_config):
    db.init_db(tmp_config)
    finding = _persist_unresolved(tmp_config, "Over-reaching confirm")
    # High-confidence verdict, but the self-critique never upholds it -> must NOT commit.
    outcome = _challenge(tmp_config, _handler(FalsificationStatus.CONFIRMED, 0.95, False), finding)

    assert outcome.status is FalsificationStatus.UNRESOLVED
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert len(trace) == 3
    assert all(it.critique_upholds is False for it in trace)
    assert all(it.committed is False for it in trace)


def test_shaky_self_critique_confidence_also_blocks_commit(tmp_config):
    db.init_db(tmp_config)
    finding = _persist_unresolved(tmp_config, "Shaky critique")
    # Verdict confident and critique 'upholds', but the critique itself is low-confidence.
    outcome = _challenge(
        tmp_config,
        _handler(FalsificationStatus.CONFIRMED, 0.95, True, critique_conf=0.2),
        finding,
    )
    assert outcome.status is FalsificationStatus.UNRESOLVED
    assert len(db.list_falsification_iterations(finding.id, tmp_config)) == 3
