"""Offline usage calibration is descriptive, complete, and fail-closed."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from repoauditor import cli
from repoauditor.eval import build_usage_calibration, render_usage_calibration
from repoauditor.store import db
from repoauditor.store.models import ModelUsage, RunStatus


runner = CliRunner()


def _run(tmp_config, source: str, *, unknown: bool = False, completed: bool = True) -> int:
    pipeline = db.start_pipeline_run(source, tmp_config)
    db.insert_model_usage(
        ModelUsage(
            pipeline_run_id=pipeline.id,
            stage="detect",
            module="detect",
            prompt_version="lens_v1",
            provider="anthropic",
            model="test-model",
            usage_available=not unknown,
            input_tokens=None if unknown else 100,
            output_tokens=None if unknown else 20,
            cache_read_tokens=None if unknown else 10,
            cache_write_tokens=None if unknown else 5,
            latency_ms=250,
        ),
        tmp_config,
    )
    if completed:
        db.finish_pipeline_run(pipeline.id, RunStatus.COMPLETED, config=tmp_config)
    return pipeline.id


def test_complete_three_cohort_calibration_is_ready_and_non_prescriptive(tmp_config):
    db.init_db(tmp_config)
    ids = {
        "lightweight": _run(tmp_config, "uat_lightweight_app"),
        "independent_pre": _run(tmp_config, "independent_serialize_javascript_pre"),
        "independent_post": _run(tmp_config, "independent_serialize_javascript_post"),
    }

    report = build_usage_calibration(ids, tmp_config)
    rendered = render_usage_calibration(report)

    assert report.ready is True
    assert report.blockers == []
    assert len(report.observations) == 3
    assert report.peak_call_utilization == 1 / 75
    assert report.peak_token_utilization == 135 / 250_000
    assert "No limit change is recommended automatically" in rendered


def test_unknown_usage_and_incomplete_run_block_calibration(tmp_config):
    db.init_db(tmp_config)
    ids = {
        "lightweight": _run(tmp_config, "uat_lightweight_app"),
        "independent_pre": _run(
            tmp_config, "independent_serialize_javascript_pre", unknown=True
        ),
        "independent_post": _run(
            tmp_config, "independent_serialize_javascript_post", completed=False
        ),
    }

    report = build_usage_calibration(ids, tmp_config)

    assert report.ready is False
    assert any("without token metadata" in blocker for blocker in report.blockers)
    assert any("status is running" in blocker for blocker in report.blockers)


def test_wrong_or_reused_cohort_run_cannot_satisfy_protected_roles(tmp_config):
    db.init_db(tmp_config)
    lightweight = _run(tmp_config, "uat_lightweight_app")
    unrelated = _run(tmp_config, "independent_django_pre")

    report = build_usage_calibration({
        "lightweight": lightweight,
        "independent_pre": unrelated,
        "independent_post": unrelated,
    }, tmp_config)

    assert report.ready is False
    assert "each calibration role must use a distinct pipeline run" in report.blockers
    assert any("independent_serialize_javascript_pre" in item for item in report.blockers)
    assert any("independent_serialize_javascript_post" in item for item in report.blockers)


def test_usage_calibration_cli_json_is_offline_and_structured(tmp_config, monkeypatch):
    db.init_db(tmp_config)
    ids = [
        _run(tmp_config, "uat_lightweight_app"),
        _run(tmp_config, "independent_serialize_javascript_pre"),
        _run(tmp_config, "independent_serialize_javascript_post"),
    ]
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)

    result = runner.invoke(cli.app, [
        "usage-calibration",
        "--lightweight-run-id", str(ids[0]),
        "--independent-pre-run-id", str(ids[1]),
        "--independent-post-run-id", str(ids[2]),
        "--format", "json",
    ])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["ready"] is True
    assert [item["role"] for item in payload["observations"]] == [
        "lightweight", "independent_pre", "independent_post",
    ]
