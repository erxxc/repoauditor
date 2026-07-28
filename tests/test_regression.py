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


def test_falsify_provenance_records_both_the_verdict_and_self_critique_prompts():
    """The falsify stage runs two prompts; a regression in the reflect step must remain
    attributable, so the recorded provenance carries the self-critique version too."""
    from repoauditor.eval.regression import STAGE_PROMPT_VERSIONS
    from repoauditor.falsify.challenger import (
        CONTEXT_VERSION, CRITIQUE_PROMPT_VERSION, PROMPT_VERSION,
    )

    recorded = STAGE_PROMPT_VERSIONS["falsify"]
    assert PROMPT_VERSION in recorded
    assert CRITIQUE_PROMPT_VERSION in recorded  # was previously omitted
    assert CONTEXT_VERSION in recorded


def test_detect_provenance_records_citation_integrity_version():
    from repoauditor.detect.ensemble import (
        CITATION_INTEGRITY_VERSION,
        DETECTION_CONTEXT_VERSION,
        PROMPT_VERSION,
    )
    from repoauditor.eval.regression import STAGE_PROMPT_VERSIONS

    recorded = STAGE_PROMPT_VERSIONS["detect"]
    assert PROMPT_VERSION in recorded
    assert CITATION_INTEGRITY_VERSION in recorded
    assert DETECTION_CONTEXT_VERSION in recorded


def test_default_recorded_run_carries_the_self_critique_prompt_version(tmp_config):
    """A run recorded with the default provenance (no explicit prompt_versions) attributes
    the self-critique prompt — so the golden harness now benchmarks it going forward."""
    from repoauditor.falsify.challenger import CONTEXT_VERSION, CRITIQUE_PROMPT_VERSION

    db.init_db(tmp_config)
    run = record_and_check(lineage="prov", precision=1.0, recall=1.0, config=tmp_config)
    assert CRITIQUE_PROMPT_VERSION in run.prompt_versions["falsify"]
    assert CONTEXT_VERSION in run.prompt_versions["falsify"]
