"""OPT-003 wave-two scoring reuses one post-import frozen model."""

from __future__ import annotations

import inspect

from repoauditor.eval import temporal_wave_two


def test_wave_two_helper_freezes_store_and_label_identities():
    assert len(temporal_wave_two.EXPECTED_STORE_SHA256) == 64
    assert temporal_wave_two.EXPECTED_LABEL_COUNT == 138
    assert len(temporal_wave_two.EXPECTED_LABEL_SHA256) == 64


def test_wave_two_freeze_trains_once_and_refuses_overwrite():
    source = inspect.getsource(temporal_wave_two.freeze_model)
    assert source.count("TriageClassifier.train(") == 1
    assert "refusing to overwrite" in source
    assert "joblib.dump" in source


def test_wave_two_scoring_reuses_model_and_guards_labels():
    source = inspect.getsource(temporal_wave_two.score_repo)
    assert "joblib.load" in source
    assert "classifier=classifier" in source
    assert "_assert_labels()" in source
    assert "scoring changed the frozen label corpus" in source
