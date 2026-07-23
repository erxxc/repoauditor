"""Architecture recovery behavior for snapshots with and without source evidence."""

from pathlib import Path

from repoauditor.map import recover_architecture


class _ForbiddenLLM:
    def call(self, **_kwargs):
        raise AssertionError("manifest-only architecture recovery must not call a model")


def test_manifest_only_snapshot_returns_empty_map_without_model_call(
    tmp_config, tmp_path: Path,
):
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")

    architecture = recover_architecture(
        tmp_path,
        "manifest-only",
        "commit-abc",
        tmp_config,
        _ForbiddenLLM(),
    )

    assert architecture.repo_id == "manifest-only"
    assert architecture.commit == "commit-abc"
    assert architecture.trust_boundaries == []
    assert architecture.entry_points == []
    assert architecture.data_stores == []
    assert architecture.integrations == []
