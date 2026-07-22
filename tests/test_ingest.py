"""Tests for the ingest stage — hash-keyed, idempotent snapshots."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from repoauditor import cli
from repoauditor.ingest import ingest_repo, snapshot_manifests
from repoauditor.store import db


runner = CliRunner()


def test_ingest_directory_snapshot_is_idempotent(tmp_config, fixture_repo):
    first = ingest_repo(str(fixture_repo.snapshot_path), tmp_config)
    assert first.reused is False
    assert first.snapshot_path.exists()
    assert any(first.snapshot_path.glob("*.py")), "snapshot should contain source files"

    # Re-ingesting the same unchanged content is a no-op keyed by the same hash.
    second = ingest_repo(str(fixture_repo.snapshot_path), tmp_config)
    assert second.reused is True
    assert second.commit == first.commit
    assert second.snapshot_path == first.snapshot_path


def test_manifest_snapshot_finds_requirements(tmp_config, fixture_repo):
    result = ingest_repo(str(fixture_repo.snapshot_path), tmp_config)
    manifests = snapshot_manifests(result.snapshot_path, result.repo_id, result.commit)
    paths = {m.path for m in manifests.manifests}
    assert "requirements.txt" in paths


def test_ingest_cli_prints_identity_and_repos_list(
    tmp_config, fixture_repo, monkeypatch
):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    source = str(fixture_repo.snapshot_path)

    ingested = runner.invoke(cli.app, ["ingest", source])
    assert ingested.exit_code == 0, ingested.output
    record = db.list_ingested_repos(tmp_config)[0]
    assert f"repo-id: {record.repo_id}" in ingested.stdout
    assert f"commit: {record.commit_hash}" in ingested.stdout

    listed = runner.invoke(cli.app, ["repos", "list"])
    assert listed.exit_code == 0, listed.output
    assert record.repo_id in listed.stdout
    assert source in listed.stdout
    assert record.commit_hash in listed.stdout
    assert record.ingested_at in listed.stdout


def _same_named_source(root: Path, parent: str, content: str) -> Path:
    source = root / parent / "service"
    source.mkdir(parents=True)
    (source / "app.py").write_text(content)
    return source


def test_same_basename_sources_receive_distinct_stable_engagement_ids(tmp_config, tmp_path):
    first_source = _same_named_source(tmp_path, "owner-a", "print('a')")
    second_source = _same_named_source(tmp_path, "owner-b", "print('b')")

    first = ingest_repo(str(first_source), tmp_config)
    second = ingest_repo(str(second_source), tmp_config)
    second_again = ingest_repo(str(second_source), tmp_config)

    assert first.repo_id == "service"
    assert second.repo_id.startswith("service-") and second.repo_id != first.repo_id
    assert second_again.repo_id == second.repo_id
    assert second_again.reused is True


def test_explicit_repo_id_cannot_merge_different_source_repositories(tmp_config, tmp_path):
    first_source = _same_named_source(tmp_path, "owner-a", "print('a')")
    second_source = _same_named_source(tmp_path, "owner-b", "print('b')")
    ingest_repo(str(first_source), tmp_config, repo_id="engagement")

    with pytest.raises(ValueError, match="already belongs to a different source"):
        ingest_repo(str(second_source), tmp_config, repo_id="engagement")
