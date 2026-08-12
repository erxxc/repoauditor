"""Semgrep runtime preparation stays local and fail closed."""

from __future__ import annotations

import json

import pytest

from repoauditor.eval.semgrep_runtime import seed_version_cache


def test_seed_version_cache_writes_fresh_empty_mapping(tmp_path):
    output = tmp_path / "semgrep-version-cache"
    seed_version_cache(output, timestamp=1234567890)
    lines = output.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "1234567890"
    assert json.loads(lines[1]) == {}


def test_seed_version_cache_refuses_missing_parent(tmp_path):
    with pytest.raises(RuntimeError, match="parent does not exist"):
        seed_version_cache(tmp_path / "missing" / "cache", timestamp=1234567890)


def test_seed_version_cache_refuses_overwrite(tmp_path):
    output = tmp_path / "semgrep-version-cache"
    output.write_text("retained", encoding="utf-8")
    with pytest.raises(RuntimeError, match="refusing to overwrite"):
        seed_version_cache(output, timestamp=1234567890)
    assert output.read_text(encoding="utf-8") == "retained"
