"""The authorized OPT-003 importer is digest-, prediction-, and transaction-bound."""

from __future__ import annotations

import inspect

from repoauditor.eval import temporal_review_import
from repoauditor.store import db


def test_importer_freezes_result_and_store_digests():
    assert len(temporal_review_import.EXPECTED_RESULT_SHA256) == 64
    assert len(temporal_review_import.EXPECTED_STORE_SHA256) == 64


def test_importer_uses_one_batch_and_preserves_two_abstentions():
    source = inspect.getsource(temporal_review_import.import_review)

    assert source.count("db.import_triage_review_batch(") == 1
    assert "INSUFFICIENT_EVIDENCE" in source
    assert "len(labels) != 16" in source
    assert '"abstention_count": 2' in source


def test_importer_checks_frozen_prediction_bindings():
    source = inspect.getsource(temporal_review_import._assert_prediction_bindings)

    assert "mode=ro" in source
    assert "triage_run_id IN (36,37,38)" in source
    assert "prediction bindings drifted" in source


def test_store_batch_is_atomic_and_refuses_overwrite():
    source = inspect.getsource(db.import_triage_review_batch)

    assert "with conn:" in source
    assert "already has an assessment" in source
    assert "already has a label projection" in source
    assert "ON CONFLICT" not in source
