"""Structured and human-readable CLI presentation contracts."""

from __future__ import annotations

import json

from repoauditor.presentation import (
    ndjson_event,
    repos_json,
    repos_table,
    review_requests_json,
)
from repoauditor.store import db
from repoauditor.store.models import IngestedRepo, ReviewRequest


def test_repo_presentations_are_structured_and_aligned():
    repos = [
        IngestedRepo(repo_id="a", source="/short", commit_hash="abc", ingested_at="2026-01-01"),
        IngestedRepo(repo_id="long-name", source="https://example.test/repo", commit_hash="def"),
    ]

    payload = json.loads(repos_json(repos))
    assert payload[0] == {
        "repo_id": "a", "source": "/short", "commit_hash": "abc",
        "ingested_at": "2026-01-01",
    }
    lines = repos_table(repos).splitlines()
    assert lines[0].startswith("REPO ID")
    assert len(lines) == 4
    # Every source begins at the same aligned column; output no longer relies on tabs.
    assert lines[0].index("SOURCE") == lines[2].index("/short") == lines[3].index("https://")
    assert "\t" not in repos_table(repos)


def test_empty_repo_presentations_remain_useful():
    assert repos_table([]) == "No ingested repositories."
    assert json.loads(repos_json([])) == []


def test_review_json_preserves_nested_evidence():
    request = ReviewRequest(
        id=4, repo_id="acme", finding_id=9, stage="triage", reason="uncertain",
        evidence={"triage": {"p_actionable": 0.51}, "citation": "danger(x)"},
    )
    assert json.loads(review_requests_json([request])) == [request.model_dump(mode="json")]


def test_ndjson_event_is_one_timestamped_json_object():
    rendered = ndjson_event("detect", "completed", findings=7)
    assert "\n" not in rendered
    event = json.loads(rendered)
    assert event["stage"] == "detect"
    assert event["status"] == "completed"
    assert event["findings"] == 7
    assert event["timestamp"].endswith("Z")


def test_latest_ingested_snapshot_is_selected_per_source(tmp_config):
    db.init_db(tmp_config)
    db.record_ingested_repo(
        IngestedRepo(repo_id="acme", source="https://example.test/acme", commit_hash="old"),
        tmp_config,
    )
    db.record_ingested_repo(
        IngestedRepo(repo_id="acme", source="https://example.test/acme", commit_hash="new"),
        tmp_config,
    )
    db.record_ingested_repo(
        IngestedRepo(repo_id="other", source="/work/other", commit_hash="only"),
        tmp_config,
    )

    latest = db.list_ingested_repos(tmp_config, all_snapshots=False)
    assert {(repo.source, repo.commit_hash) for repo in latest} == {
        ("https://example.test/acme", "new"), ("/work/other", "only"),
    }
    assert len(db.list_ingested_repos(tmp_config, all_snapshots=True)) == 3
