"""Tests for the triage stage — SARIF ingestion, Beta-Binomial priors, and the
calibrated classifier eval harness (precision-recall + Brier score, never accuracy)."""

from __future__ import annotations

import json

import numpy as np
import pytest

from repoauditor.config import load_priors
from repoauditor.store import db
from repoauditor.store.models import TriageLabel
from repoauditor.triage import priors as triage_priors
from repoauditor.triage import synthetic, triage_repo
from repoauditor.triage.classifier import TriageClassifier
from repoauditor.triage.features import (
    FEATURE_NAMES,
    build_repo_context,
    extract_feature_vector,
    load_sarif,
)


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
def test_classifier_compares_both_models_and_calibrates():
    ds = synthetic.generate(n=2000, seed=7)
    clf = TriageClassifier.train(ds.X, ds.y, seed=7)
    names = {e.model_name for e in clf.evaluations}
    assert names == {"randomforest", "xgboost"}         # both compared
    assert clf.model_name in names                       # a winner was chosen
    assert all(e.calibration in ("isotonic", "sigmoid") for e in clf.evaluations)


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


def test_triage_repo_raises_cleanly_without_sarif(cfg):
    db.init_db(cfg)
    with pytest.raises(FileNotFoundError):
        triage_repo("missing", cfg)
