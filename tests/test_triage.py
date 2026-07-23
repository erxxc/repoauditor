"""Tests for the triage stage — SARIF ingestion, Beta-Binomial priors, and the
calibrated classifier eval harness (precision-recall + Brier score, never accuracy)."""

from __future__ import annotations

import json

import numpy as np
import pytest

from repoauditor.config import load_priors
from repoauditor.store import db
from repoauditor.store.models import (
    FalsificationStatus,
    Finding,
    ReviewDecision,
    ReviewDisposition,
    ReviewRequest,
    Severity,
    TriageLabel,
    TriageLabelSource,
    TriageAssessmentOutcome,
    TriageDisposition,
)
from repoauditor.triage import assess_finding, derive_labels, label_finding
from repoauditor.triage import priors as triage_priors
from repoauditor.triage import synthetic, triage_repo
from repoauditor.triage.classifier import MIN_GROUPED_ENGAGEMENTS, _discover_sarif, _holdout_split
from repoauditor.triage.classifier import TriageClassifier
from repoauditor.triage.features import (
    FEATURE_NAMES,
    build_repo_context,
    extract_feature_vector,
    load_sarif,
)
from repoauditor.triage.training import assemble_training_data, synthetic_share


@pytest.fixture
def cfg(tmp_config):
    """tmp_config with the real repo-root priors.yaml loaded (triage prior + sources)."""
    return tmp_config.model_copy(update={"priors": load_priors()})


def _sarif(rules, results) -> str:
    return json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "semgrep", "rules": rules}},
                  "results": results}],
    })


def _result(rule_id, uri, line, level="warning", snippet="x", flows=0):
    r = {"ruleId": rule_id, "level": level, "message": {"text": f"{rule_id} hit"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": uri},
             "region": {"startLine": line, "endLine": line,
                        "snippet": {"text": snippet}}}}]}
    if flows:
        r["codeFlows"] = [{"threadFlows": [{"locations": [{}] * flows}]}]
    return r


# --------------------------------------------------------------------------- #
# SARIF ingestion + features
# --------------------------------------------------------------------------- #
def test_load_sarif_reads_rule_metadata_cwe_and_dataflow():
    doc = _sarif(
        rules=[{"id": "py.sqli", "name": "SQL Injection",
                "properties": {"tags": ["security", "CWE-89"], "security-severity": "8.8"}}],
        results=[_result("py.sqli", "app/db.py", 10, level="error", flows=3)],
    )
    findings = load_sarif(doc)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "py.sqli"
    assert f.cwe == 89
    assert f.security_severity == 8.8
    assert f.dataflow_length == 3          # source->sink distance from codeFlows
    assert f.rule_name == "SQL Injection"
    assert f.fingerprint  # stable, non-empty


def test_feature_vector_matches_schema_width_and_flags_paths():
    doc = _sarif(
        rules=[{"id": "r1", "name": "x", "properties": {"tags": ["CWE-78"], "security-severity": "9.0"}}],
        results=[_result("r1", "node_modules/pkg/index.js", 1, flows=2)],
    )
    findings = load_sarif(doc)
    ctx = build_repo_context(
        findings, rule_prior_mean={"r1": 0.4}, rule_fp_rate={}, rule_label_count={}
    )
    vec = extract_feature_vector(findings[0], ctx)
    assert len(vec) == len(FEATURE_NAMES)
    feats = dict(zip(FEATURE_NAMES, vec))
    assert feats["cwe_is_injection"] == 1.0        # CWE-78
    assert feats["is_vendor_dependency"] == 1.0    # node_modules
    assert feats["has_dataflow"] == 1.0
    assert feats["rule_prior_mean"] == 0.4


# --------------------------------------------------------------------------- #
# Beta-Binomial prior with Bayesian shrinkage
# --------------------------------------------------------------------------- #
def test_rule_prior_starts_at_sourced_global_mean(cfg):
    db.init_db(cfg)
    prior = triage_priors.compute_rule_prior("never.seen.rule", cfg)
    # No labels -> pure prior. priors.yaml ships Beta(3,7) -> mean 0.30.
    assert prior.observed_total == 0
    assert prior.posterior_mean == pytest.approx(0.30, abs=1e-9)
    assert prior.prior_source  # provenance carried, not a magic number


def test_rule_prior_shrinks_toward_observed_rate_as_labels_accumulate(cfg):
    db.init_db(cfg)
    # 20 labels, 18 actionable (0.90 observed) — posterior mean pulls up from 0.30
    # toward 0.90 but stays below it (shrinkage): (3+18)/(10+20) = 21/30 = 0.70.
    for i in range(20):
        db.upsert_triage_label(
            TriageLabel(engagement="e1", rule_id="hot.rule",
                        finding_fingerprint=f"fp{i}", actionable=(i < 18)),
            cfg,
        )
    prior = triage_priors.compute_rule_prior("hot.rule", cfg)
    assert prior.observed_total == 20
    assert prior.posterior_mean == pytest.approx(21 / 30, abs=1e-9)
    assert 0.30 < prior.posterior_mean < 0.90     # between prior and observed

    fp_rate, n = triage_priors.historical_fp_rate("hot.rule", cfg)
    assert n == 20 and fp_rate == pytest.approx(2 / 20)


# --------------------------------------------------------------------------- #
# Classifier eval harness: PR + Brier (NOT accuracy), both models compared
# --------------------------------------------------------------------------- #
@pytest.mark.integration
def test_classifier_compares_both_models_and_calibrates():
    ds = synthetic.generate(n=2000, seed=7)
    clf = TriageClassifier.train(ds.X, ds.y, seed=7)
    names = {e.model_name for e in clf.evaluations}
    assert names == {"randomforest", "xgboost"}         # both compared
    assert clf.model_name in names                       # a winner was chosen
    assert all(e.calibration in ("isotonic", "sigmoid") for e in clf.evaluations)


@pytest.mark.integration
def test_classifier_eval_uses_precision_recall_and_brier_not_accuracy():
    ds = synthetic.generate(n=3000, seed=11)
    clf = TriageClassifier.train(ds.X, ds.y, seed=11)
    best = min(clf.evaluations, key=lambda e: e.brier)
    # PR-AUC well above the ~0.30 base rate (a no-skill classifier scores ~base rate).
    assert best.average_precision > 0.6
    # Calibrated Brier beats the constant-base-rate baseline (~0.21 at p=0.3).
    assert best.brier < 0.20


def test_synthetic_dataset_is_marked_synthetic():
    ds = synthetic.generate(n=50)
    assert ds.synthetic is True
    assert "SYNTHETIC" in ds.marker
    assert ds.X.shape == (50, len(FEATURE_NAMES))


# --------------------------------------------------------------------------- #
# End-to-end: ranks, suppresses, and NEVER deletes
# --------------------------------------------------------------------------- #
def test_triage_repo_ranks_persists_and_never_deletes(cfg, tmp_path):
    db.init_db(cfg)
    sp = tmp_path / "scan.sarif"
    sp.write_text(_sarif(
        rules=[
            {"id": "py.cmdi", "name": "Command Injection",
             "properties": {"tags": ["CWE-78"], "security-severity": "9.5"}},
            {"id": "py.note", "name": "Style note",
             "properties": {"tags": ["CWE-200"], "security-severity": "1.0"}},
        ],
        results=[
            _result("py.cmdi", "svc/run.py", 21, level="error", flows=3),
            _result("py.note", "tests/test_x.py", 4, level="note"),
        ],
    ))
    outcome = triage_repo("acme", cfg, sarif_path=sp, action_threshold=0.5, seed=3)

    assert len(outcome.ranked) == 2
    ranks = [r.rank for r in outcome.ranked]
    assert ranks == [1, 2]                               # dense ranking
    probs = [r.p_actionable for r in outcome.ranked]
    assert probs[0] >= probs[1]                          # sorted by P(actionable)
    assert all(0.0 <= p <= 1.0 for p in probs)           # calibrated probabilities
    assert all(r.attributions for r in outcome.ranked)   # top-k attributions present

    # Findings persisted; triage results attached; nothing deleted on re-run.
    assert len(db.list_findings("acme", cfg)) == 2
    results = db.list_triage_results("acme", cfg)
    assert len(results) == 2
    # Suppressed findings remain in the store (ranking layer never deletes).
    triage_repo("acme", cfg, sarif_path=sp, action_threshold=0.99, seed=3)
    assert len(db.list_findings("acme", cfg)) == 2       # still 2, not deleted
    after = db.list_triage_results("acme", cfg)
    assert any(r.suppressed for r in after)              # now some are suppressed
    assert len(after) == 2                               # suppressed rows kept
    runs = db.list_triage_model_runs("acme", cfg)
    assert len(runs) == 2                                # each scoring pass is versioned
    assert all(result.triage_run_id == runs[-1].id for result in after)
    assert all(result.scored_at for result in after)
    assert runs[-1].feature_schema_version.startswith("sha256:")
    assert runs[-1].training_label_count == 0
    label_finding(after[0].finding_id, True, "audit score history", cfg)
    score_history = db.list_scored_triage_labels(cfg, repo_id="acme")
    assert len(score_history) == 2
    assert {score.triage_run_id for score in score_history} == {runs[0].id, runs[1].id}
    assert all(score.scored_at for score in score_history)


def test_triage_repo_raises_cleanly_without_sarif(cfg):
    db.init_db(cfg)
    with pytest.raises(FileNotFoundError):
        triage_repo("missing", cfg)


def test_triage_discovers_detect_artifact(cfg):
    commit = "abc123"
    (cfg.raw_dir / "acme" / commit).mkdir(parents=True)
    artifact = (
        cfg.resolve(cfg.paths.data_dir) / "artifacts" / "acme" / commit
        / "detect" / "semgrep.sarif"
    )
    artifact.parent.mkdir(parents=True)
    artifact.write_text('{"version":"2.1.0","runs":[]}')

    assert _discover_sarif("acme", cfg) == artifact


# --------------------------------------------------------------------------- #
# Real TriageLabel training loop: derived labels, manual override, blend, eval
# --------------------------------------------------------------------------- #
def _triage_three(cfg, tmp_path, engagement="eng1"):
    """Triage a 3-finding SARIF so each finding has a persisted feature row."""
    sp = tmp_path / "scan.sarif"
    sp.write_text(_sarif(
        rules=[
            {"id": "py.a", "name": "A", "properties": {"tags": ["CWE-89"], "security-severity": "8.0"}},
            {"id": "py.b", "name": "B", "properties": {"tags": ["CWE-78"], "security-severity": "9.0"}},
            {"id": "py.c", "name": "C", "properties": {"tags": ["CWE-79"], "security-severity": "7.0"}},
        ],
        results=[
            _result("py.a", "a.py", 1, level="error"),
            _result("py.b", "b.py", 2, level="error"),
            _result("py.c", "c.py", 3, level="error"),
        ],
    ))
    triage_repo(engagement, cfg, sarif_path=sp, seed=1)
    return {f.file: f for f in db.list_findings(engagement, cfg)}


def test_derived_labels_from_falsify_and_review_override(cfg, tmp_path):
    db.init_db(cfg)
    findings = _triage_three(cfg, tmp_path)

    # falsify verdicts: a confirmed (TP), b killed (FP).
    db.update_falsification(findings["a.py"].id, FalsificationStatus.CONFIRMED, "reachable", cfg)
    db.update_falsification(findings["b.py"].id, FalsificationStatus.KILLED, "mitigated", cfg)
    # c confirmed by falsify, but a human dismisses it in review -> review overrides.
    db.update_falsification(findings["c.py"].id, FalsificationStatus.CONFIRMED, "reachable", cfg)
    rid = db.upsert_review_request(
        ReviewRequest(repo_id="eng1", finding_id=findings["c.py"].id, stage="falsify",
                      reason="edge case"), cfg)
    db.insert_review_decision(
        ReviewDecision(review_request_id=rid, disposition=ReviewDisposition.DISMISS,
                       reviewer="analyst", rationale="accepted risk"), cfg)

    summary = derive_labels(cfg)
    labels = {label.rule_id: label for label in db.list_triage_labels(config=cfg)}

    assert labels["py.a"].actionable is True
    assert labels["py.a"].source is TriageLabelSource.DERIVED_FALSIFY
    assert labels["py.b"].actionable is False
    assert labels["py.b"].source is TriageLabelSource.DERIVED_FALSIFY
    # Human review (dismiss) overrides the falsify CONFIRMED verdict.
    assert labels["py.c"].actionable is False
    assert labels["py.c"].source is TriageLabelSource.DERIVED_REVIEW
    assert summary.from_falsify == 2 and summary.from_review == 1
    corpus = assemble_training_data(cfg, seed=1)
    assert corpus.label_source_counts == {"derived_falsify": 2, "derived_review": 1}
    assert int(corpus.evaluation_mask.sum()) == 1  # human review only; no circular eval


def test_unresolved_and_deferred_yield_no_label(cfg, tmp_path):
    db.init_db(cfg)
    findings = _triage_three(cfg, tmp_path)
    # a stays UNRESOLVED (default), b is DEFERRED — neither is evidence either way.
    db.update_falsification(findings["b.py"].id, FalsificationStatus.DEFERRED, "over budget", cfg)
    db.update_falsification(findings["c.py"].id, FalsificationStatus.CONFIRMED, "reachable", cfg)
    summary = derive_labels(cfg)
    labelled_rules = {label.rule_id for label in db.list_triage_labels(config=cfg)}
    assert labelled_rules == {"py.c"}                 # only the confirmed one
    assert summary.skipped_ambiguous == 2             # unresolved + deferred, no fabrication


def test_manual_label_overrides_derived_and_persists(cfg, tmp_path):
    db.init_db(cfg)
    findings = _triage_three(cfg, tmp_path)
    db.update_falsification(findings["a.py"].id, FalsificationStatus.CONFIRMED, "reachable", cfg)

    # Analyst disagrees with the automated CONFIRMED verdict and marks it a false positive.
    label = label_finding(findings["a.py"].id, actionable=False, note="analyst: not exploitable",
                          config=cfg)
    assert label.source is TriageLabelSource.MANUAL

    # A later derivation pass must NOT overwrite the manual call.
    derive_labels(cfg)
    got = {label.rule_id: label for label in db.list_triage_labels(config=cfg)}
    assert got["py.a"].actionable is False
    assert got["py.a"].source is TriageLabelSource.MANUAL
    assert got["py.a"].created_at and got["py.a"].updated_at


def test_manual_label_requires_an_existing_triaged_finding(cfg):
    db.init_db(cfg)
    with pytest.raises(ValueError):
        label_finding(999, True, None, cfg)          # no such finding
    # A finding that was never triaged has no feature row -> not labellable yet.
    fid = db.insert_finding(
        Finding(repo_id="e", title="t", file="f.py", line_start=1, line_end=1,
                citation_snippet="x", source_lens="owasp", confidence=0.5,
                severity=Severity.LOW), cfg)
    with pytest.raises(ValueError):
        label_finding(fid, True, None, cfg)


def test_analyst_assessment_is_append_only_and_uncertain_abstains(cfg, tmp_path):
    db.init_db(cfg)
    finding = _triage_three(cfg, tmp_path)["a.py"]

    first, label = assess_finding(
        finding.id, TriageAssessmentOutcome.UNCERTAIN,
        "runtime authorization context unavailable", "alice",
        ["authorization", "business-logic"], cfg,
    )
    second, label = assess_finding(
        finding.id, TriageAssessmentOutcome.TRUE_POSITIVE,
        "owner confirmed cross-tenant reachability", "bob",
        ["authorization", "tenant-isolation"], cfg,
    )

    assert first.id != second.id
    assert label is not None and label.actionable is True
    history = db.list_triage_assessments("eng1", cfg)
    assert [item.outcome for item in history] == [
        TriageAssessmentOutcome.UNCERTAIN,
        TriageAssessmentOutcome.TRUE_POSITIVE,
    ]
    assert len(db.list_triage_labels(config=cfg)) == 1


@pytest.mark.parametrize(
    ("disposition", "actionable"),
    [
        (TriageDisposition.CONFIRMED_ACTIONABLE, True),
        (TriageDisposition.TOOL_INCORRECT, False),
        (TriageDisposition.UNREACHABLE, False),
        (TriageDisposition.NOT_ATTACKER_CONTROLLED, False),
        (TriageDisposition.MITIGATED, False),
        (TriageDisposition.DUPLICATE, False),
        (TriageDisposition.VALID_NOT_ACTIONABLE, False),
    ],
)
def test_detailed_disposition_persists_and_projects_to_binary(
    cfg, tmp_path, disposition, actionable
):
    db.init_db(cfg)
    finding = _triage_three(cfg, tmp_path)["a.py"]

    assessment, label = assess_finding(
        finding.id, disposition, "human-reviewed rationale", "alice", [], cfg
    )

    assert assessment.disposition is disposition
    assert label is not None and label.actionable is actionable
    assert db.list_triage_assessments("eng1", cfg)[0].disposition is disposition


def test_insufficient_evidence_persists_without_training_label(cfg, tmp_path):
    db.init_db(cfg)
    finding = _triage_three(cfg, tmp_path)["a.py"]

    assessment, label = assess_finding(
        finding.id,
        TriageDisposition.INSUFFICIENT_EVIDENCE,
        "runtime context unavailable",
        "alice",
        [],
        cfg,
    )

    assert assessment.outcome is TriageAssessmentOutcome.UNCERTAIN
    assert label is None
    assert db.list_triage_labels(config=cfg) == []


def test_synthetic_share_shrinks_as_real_labels_accumulate(cfg):
    # Documented shrinkage: pseudocount / (pseudocount + n_real), 0 past the cutoff.
    assert synthetic_share(0, cfg) == 1.0
    assert synthetic_share(0, cfg) > synthetic_share(100, cfg) > synthetic_share(1000, cfg) > 0.0
    # At n_real == pseudocount, synthetic and real carry equal mass (share 0.5).
    assert synthetic_share(int(cfg.triage.synthetic_pseudocount), cfg) == pytest.approx(0.5)
    # Hard cutoff: synthetic is retired entirely.
    assert synthetic_share(cfg.triage.synthetic_cutoff_labels, cfg) == 0.0


def test_assemble_training_data_blends_real_with_downweighted_synthetic(cfg, tmp_path):
    db.init_db(cfg)
    findings = _triage_three(cfg, tmp_path)
    label_finding(findings["a.py"].id, True, None, cfg)
    label_finding(findings["b.py"].id, False, None, cfg)

    corpus = assemble_training_data(cfg, seed=1)
    assert corpus.n_real == 2
    assert int(corpus.real_mask.sum()) == 2
    assert corpus.X.shape[0] == corpus.n_synthetic + corpus.n_real
    assert 0.0 < corpus.synthetic_share < 1.0 and not corpus.synthetic_dropped
    # Real rows carry weight 1.0; the synthetic pool shares `pseudocount`.
    assert corpus.sample_weight[corpus.real_mask].tolist() == [1.0, 1.0]
    expected_syn_w = cfg.triage.synthetic_pseudocount / corpus.n_synthetic
    assert corpus.sample_weight[~corpus.real_mask][0] == pytest.approx(expected_syn_w)
    assert corpus.label_source_counts == {"manual": 2}
    assert int(corpus.evaluation_mask.sum()) == 2


def test_holdout_eval_flags_real_vs_synthetic_split():
    ds = synthetic.generate(n=1200, seed=5)
    # No real labels -> eval on a synthetic split, honestly flagged.
    clf = TriageClassifier.train(ds.X, ds.y, seed=5)
    assert all(e.eval_on == "synthetic" for e in clf.evaluations)

    # Enough "real" rows (stand-in features) -> held-out eval carved from real rows.
    mask = np.zeros(len(ds.y), dtype=bool)
    mask[:200] = True
    clf2 = TriageClassifier.train(ds.X, ds.y, seed=5, real_mask=mask, min_real_holdout=40)
    assert all(e.eval_on == "real" for e in clf2.evaluations)
    assert clf2.evaluations[0].n_eval == 50          # 25% of the 200 real rows


def test_grouped_holdout_activates_only_with_enough_distinct_engagements():
    y = np.tile([0, 1], 40)
    mask = np.ones(80, dtype=bool)
    groups = np.repeat([f"repo-{i}" for i in range(MIN_GROUPED_ENGAGEMENTS)], 10)

    train, test, eval_on, strategy, detail = _holdout_split(
        y, mask, min_real_holdout=40, seed=3, engagement_groups=groups
    )

    assert eval_on == "real" and strategy == "engagement_grouped"
    assert set(groups[train]).isdisjoint(set(groups[test]))
    assert "active" in detail


def test_grouped_holdout_reports_clear_fallback_when_repo_breadth_is_insufficient():
    y = np.tile([0, 1], 20)
    mask = np.ones(40, dtype=bool)
    groups = np.repeat(["repo-a", "repo-b"], 20)

    _train, _test, eval_on, strategy, detail = _holdout_split(
        y, mask, min_real_holdout=40, seed=3, engagement_groups=groups
    )

    assert eval_on == "real" and strategy == "real_row_random"
    assert "2 engagements, need 8" in detail
