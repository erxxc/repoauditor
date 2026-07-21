"""Tests for the closed-loop eval regression gate (eval/regression.py)."""

from __future__ import annotations

import pytest

from repoauditor.eval import RegressionError, record_and_check
from repoauditor.store import db

_PV = {"map": "architecture_recovery_v2", "detect": "owasp_v1"}


def _record(tmp_config, precision, recall, lineage="golden"):
    return record_and_check(
        lineage=lineage, precision=precision, recall=recall,
        prompt_versions=_PV, config=tmp_config,
    )


def test_first_run_never_regresses(tmp_config):
    db.init_db(tmp_config)
    run = _record(tmp_config, 0.9, 0.9)
    assert run.regressed_from_prior is False


def test_regression_on_precision_drop_raises_and_is_recorded(tmp_config):
    db.init_db(tmp_config)
    _record(tmp_config, 1.0, 1.0)  # prior good run

    with pytest.raises(RegressionError):
        _record(tmp_config, 0.8, 1.0)  # precision regressed

    # The regressed run is still persisted, flagged — it cannot quietly ship.
    last = db.last_eval_run("golden", tmp_config)
    assert last.regressed_from_prior is True
    assert last.precision == 0.8


def test_regression_on_recall_drop_raises(tmp_config):
    db.init_db(tmp_config)
    _record(tmp_config, 1.0, 1.0)
    with pytest.raises(RegressionError):
        _record(tmp_config, 1.0, 0.5)


def test_equal_or_improved_metrics_do_not_regress(tmp_config):
    db.init_db(tmp_config)
    _record(tmp_config, 0.8, 0.8)
    # Equal is fine.
    assert _record(tmp_config, 0.8, 0.8).regressed_from_prior is False
    # Improvement is fine.
    assert _record(tmp_config, 0.95, 0.9).regressed_from_prior is False


def test_lineages_are_independent(tmp_config):
    db.init_db(tmp_config)
    _record(tmp_config, 1.0, 1.0, lineage="repo_a")
    # A low first run on a different lineage is a first run, not a regression.
    assert _record(tmp_config, 0.5, 0.5, lineage="repo_b").regressed_from_prior is False
