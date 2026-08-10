"""Real-label threshold transparency; descriptive only, never auto-tuning."""

from repoauditor.triage.stats import render_threshold_stats, threshold_stats
from repoauditor.store.models import ScoredTriageLabel, TriageLabelSource


def _scored(score, actionable, engagement, source=TriageLabelSource.MANUAL, run_id=1,
            model_version=None):
    return ScoredTriageLabel(
        p_actionable=score, actionable=actionable, engagement=engagement,
        label_source=source, triage_run_id=run_id,
        model_name="xgboost" if model_version else None,
        model_version=model_version,
        feature_schema_version="schema-1" if model_version else None,
        calibration="sigmoid" if model_version else None,
    )


def test_threshold_curve_is_withheld_below_existing_real_label_gate(tmp_config, monkeypatch):
    monkeypatch.setattr(
        "repoauditor.triage.stats.db.list_scored_triage_labels",
        lambda config, repo_id=None: [_scored(0.9, True, "r1"), _scored(0.2, False, "r2")],
    )
    stats = threshold_stats(config=tmp_config)
    rendered = render_threshold_stats(stats)

    assert not stats.available and stats.rows == []
    assert ">=40 label gate" in rendered
    assert "Synthetic-heavy data is not substituted" in rendered


def test_threshold_curve_reports_tradeoff_without_recommending_cutoff(tmp_config, monkeypatch):
    observations = []
    for index in range(40):
        actionable = index < 20
        score = (index + 1) / 41
        observations.append(_scored(score, actionable, f"repo-{index % 8}"))
    monkeypatch.setattr(
        "repoauditor.triage.stats.db.list_scored_triage_labels",
        lambda config, repo_id=None: observations,
    )

    stats = threshold_stats(config=tmp_config)
    rendered = render_threshold_stats(stats)

    assert stats.available and len(stats.rows) == 11
    assert "precision" in rendered and "recall" in rendered
    assert "no threshold is recommended" in rendered
    assert "optimal" not in rendered.lower()
    assert stats.bootstrap_available
    assert stats.bootstrap_resamples == 2000
    assert all(row.recall_lower is not None for row in stats.rows)


def test_family_bootstrap_is_deterministic_and_honors_family_overrides(tmp_config, monkeypatch):
    observations = [
        _scored((index + 1) / 49, index % 2 == 0, f"repo-{index % 9}",
                model_version="3.3.0")
        for index in range(47)
    ]
    monkeypatch.setattr(
        "repoauditor.triage.stats.db.list_scored_triage_labels",
        lambda config, repo_id=None: observations,
    )
    first = threshold_stats(config=tmp_config)
    second = threshold_stats(config=tmp_config)
    assert first.rows == second.rows
    assert first.n_evaluation_families == 9

    triage = tmp_config.triage.model_copy(update={
        "evaluation_family_overrides": {"repo-8": "repo-7"}
    })
    grouped = tmp_config.model_copy(update={"triage": triage})
    collapsed = threshold_stats(config=grouped)
    assert collapsed.n_evaluation_families == 8
    assert collapsed.bootstrap_available


def test_threshold_stats_defaults_to_human_labels_and_can_select_a_run(tmp_config, monkeypatch):
    observations = [
        *[_scored(0.8, True, f"human-{i % 8}", run_id=2) for i in range(40)],
        *[_scored(
            0.1, False, f"derived-{i % 8}",
            source=TriageLabelSource.DERIVED_FALSIFY, run_id=1,
        ) for i in range(40)],
    ]
    monkeypatch.setattr(
        "repoauditor.triage.stats.db.list_scored_triage_labels",
        lambda config, repo_id=None: observations,
    )

    human = threshold_stats(config=tmp_config)
    derived = threshold_stats(config=tmp_config, label_cohort="derived", triage_run_id=1)

    assert human.n_labels == 40 and human.n_positive == 40
    assert derived.n_labels == 40 and derived.n_negative == 40
    assert derived.triage_run_id == 1


def test_threshold_stats_does_not_pool_incompatible_model_versions(tmp_config, monkeypatch):
    observations = [
        *[_scored(0.9, True, f"old-{i % 8}", run_id=1, model_version="1.0")
          for i in range(40)],
        *[_scored(0.2, False, f"new-{i % 8}", run_id=2, model_version="2.0")
          for i in range(40)],
    ]
    monkeypatch.setattr(
        "repoauditor.triage.stats.db.list_scored_triage_labels",
        lambda config, repo_id=None: observations,
    )

    stats = threshold_stats(config=tmp_config)

    assert stats.n_labels == 40
    assert stats.n_positive == 0
    assert stats.n_negative == 40
