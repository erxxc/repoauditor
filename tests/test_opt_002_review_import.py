"""The authorized OPT-002 importer is digest-bound and transaction-bounded."""

from __future__ import annotations

import inspect

from repoauditor.eval import review_import
from repoauditor.store import db


def test_importer_freezes_result_and_store_digests():
    assert len(review_import.EXPECTED_RESULT_SHA256) == 64
    assert len(review_import.EXPECTED_STORE_SHA256) == 64


def test_importer_uses_one_store_batch_and_preserves_abstention():
    source = inspect.getsource(review_import.import_review)
    assert source.count("db.import_triage_review_batch(") == 1
    assert "INSUFFICIENT_EVIDENCE" in source
    assert "len(labels) != 11" in source


def test_store_batch_is_atomic_and_refuses_overwrite():
    source = inspect.getsource(db.import_triage_review_batch)
    assert "with conn:" in source
    assert "already has an assessment" in source
    assert "already has a label projection" in source
    assert "ON CONFLICT" not in source
