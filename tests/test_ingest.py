"""Tests for the ingest stage — hash-keyed, idempotent snapshots."""

from __future__ import annotations

from repoauditor.ingest import ingest_repo, snapshot_manifests


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
