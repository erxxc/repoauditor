"""OPT-003 wave scoring reuses one digest-frozen pre-outcome model."""

from __future__ import annotations

import inspect

from repoauditor.eval import temporal_wave


def test_wave_helper_freezes_store_and_label_identities():
    assert len(temporal_wave.EXPECTED_STORE_SHA256) == 64
    assert len(temporal_wave.EXPECTED_LABEL_SHA256) == 64


def test_freeze_trains_once_and_refuses_overwrite():
    source = inspect.getsource(temporal_wave.freeze_model)
    assert source.count("TriageClassifier.train(") == 1
    assert "refusing to overwrite" in source
    assert "joblib.dump" in source


def test_scoring_reuses_model_and_guards_labels_before_and_after():
    source = inspect.getsource(temporal_wave.score_repo)
    assert "joblib.load" in source
    assert "classifier=classifier" in source
    assert source.count("effective_label_digest()") == 2
    assert "scoring changed the frozen label corpus" in source
