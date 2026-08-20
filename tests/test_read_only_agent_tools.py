from __future__ import annotations

import json
import socket
import subprocess
import urllib.request
from pathlib import Path

import pytest

from repoauditor.config import AgentReadOnlyToolsConfig
from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.falsify.read_only_tools import AgentReadOnlyTools, ToolBoundaryError
from repoauditor.map import ArchitectureMap, EntryPoint, TrustBoundary
from repoauditor.store import db
from repoauditor.store.models import Finding, Severity


SOURCE = """\
from flask import request

def run_query(user_id):
    return execute("SELECT * FROM users WHERE id = " + user_id)

def handler():
    user_id = request.args.get("id")
    return run_query(user_id)
"""


def _session(
    tmp_path: Path,
    *,
    enabled: bool = True,
    source: str = SOURCE,
    **bounds,
) -> AgentReadOnlyTools:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    index = RetrievalIndex().build(tmp_path)
    finding = Finding(
        repo_id="synthetic",
        title="SQL injection",
        file="app.py",
        line_start=4,
        line_end=4,
        citation_snippet='return execute("SELECT * FROM users WHERE id = " + user_id)',
        source_tool="synthetic",
        confidence=0.8,
        severity=Severity.HIGH,
    )
    architecture = ArchitectureMap(
        repo_id="synthetic",
        commit="commit-abc",
        trust_boundaries=[TrustBoundary(name="public")],
        entry_points=[
            EntryPoint(
                name="handler", location="app.py:6", trust_boundary="public"
            )
        ],
    )
    config = AgentReadOnlyToolsConfig(enabled=enabled, **bounds)
    return AgentReadOnlyTools(
        index=index,
        finding=finding,
        architecture=architecture,
        snapshot_commit="commit-abc",
        expected_index_digest=index.content_digest(),
        config=config,
    )


def test_default_is_disabled_and_allowlist_is_exact(tmp_path):
    session = _session(tmp_path, enabled=False)

    with pytest.raises(ToolBoundaryError, match="disabled"):
        session.request("architecture_evidence")

    config = AgentReadOnlyToolsConfig()
    assert config.enabled is False
    assert config.allowlist == [
        "indexed_source_excerpt",
        "structural_slice",
        "callers",
        "references",
        "architecture_evidence",
    ]


def test_all_five_typed_tools_return_bounded_provenance(tmp_path):
    session = _session(tmp_path)
    calls = [
        session.request(
            "indexed_source_excerpt", file="app.py", line_start=3, line_end=4
        ),
        session.request("structural_slice"),
        session.request("callers", symbol="run_query"),
        session.request("references", token="request"),
        session.request("architecture_evidence"),
    ]

    assert session.attempts == 5
    for ordinal, result in enumerate(calls, start=1):
        payload = result.model_dump()
        assert payload["provenance"]["ordinal"] == ordinal
        assert payload["provenance"]["snapshot_commit"] == "commit-abc"
        assert payload["provenance"]["index_digest"].startswith("sha256:")
        assert payload["provenance"]["request_digest"].startswith("sha256:")
        assert payload["provenance"]["response_digest"].startswith("sha256:")
        assert payload["provenance"]["response_bytes"] <= 32_768
        json.dumps(payload, sort_keys=True)


@pytest.mark.parametrize(
    "path",
    [
        "../app.py",
        "nested/../../app.py",
        "/tmp/app.py",
        "C:/tmp/app.py",
        "./app.py",
        "app.py\x00outside.py",
        "nested/app.py",
    ],
)
def test_paths_fail_closed_before_index_suffix_matching(tmp_path, path):
    session = _session(tmp_path)

    with pytest.raises(ToolBoundaryError, match="path"):
        session.request(
            "indexed_source_excerpt", file=path, line_start=1, line_end=1
        )


def test_unindexed_symlink_escape_attempt_is_rejected(tmp_path):
    session = _session(tmp_path)
    outside = tmp_path.parent / "outside.py"
    outside.write_text("SECRET = True\n", encoding="utf-8")
    link = tmp_path / "escape.py"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(ToolBoundaryError, match="indexed source path"):
        session.request(
            "indexed_source_excerpt", file="escape.py", line_start=1, line_end=1
        )


def test_unknown_tool_bad_arguments_queries_and_ranges_consume_no_evidence(tmp_path):
    session = _session(tmp_path, maximum_query_characters=8)

    with pytest.raises(ToolBoundaryError, match="allowlist"):
        session.request("shell", command="id")
    with pytest.raises(ToolBoundaryError, match="arguments"):
        session.request("callers", symbol="handler", command="id")
    with pytest.raises(ToolBoundaryError, match="character ceiling"):
        session.request("callers", symbol="a" * 9)
    with pytest.raises(ToolBoundaryError, match="line range"):
        session.request(
            "indexed_source_excerpt", file="app.py", line_start=0, line_end=1
        )
    with pytest.raises(ToolBoundaryError, match="exceeds"):
        session.request(
            "indexed_source_excerpt", file="app.py", line_start=1, line_end=999
        )


def test_snapshot_repository_and_index_drift_fail_before_evidence(tmp_path):
    session = _session(tmp_path)
    session._architecture.commit = "commit-drift"  # deliberate tamper sentinel
    with pytest.raises(ToolBoundaryError, match="snapshot commit drift"):
        session.request("architecture_evidence")

    session = _session(tmp_path / "repo-drift")
    session._architecture.repo_id = "other"  # deliberate tamper sentinel
    with pytest.raises(ToolBoundaryError, match="repository drift"):
        session.request("architecture_evidence")

    session = _session(tmp_path / "index-drift")
    session._index._file_texts["app.py"] += "\n# tampered"  # deliberate tamper sentinel
    with pytest.raises(ToolBoundaryError, match="index digest drift"):
        session.request("architecture_evidence")


def test_result_and_call_ceilings_fail_closed(tmp_path):
    large = SOURCE + "\n# " + ("x" * 4000)
    session = _session(tmp_path / "bytes", source=large, maximum_response_bytes=1024)
    with pytest.raises(ToolBoundaryError, match="byte ceiling"):
        session.request(
            "indexed_source_excerpt", file="app.py", line_start=9, line_end=9
        )

    session = _session(tmp_path / "calls", maximum_calls=1)
    session.request("architecture_evidence")
    with pytest.raises(ToolBoundaryError, match="budget exhausted"):
        session.request("architecture_evidence")


def test_no_filesystem_store_network_subprocess_or_write_interface_is_reached(
    tmp_path, monkeypatch
):
    session = _session(tmp_path)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("excluded side-effect interface reached")

    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(db, "get_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)

    assert session.request("callers", symbol="run_query").evidence["returned"] == 1
    assert session.request("references", token="request").evidence["returned"] >= 1
    assert session.request("structural_slice").evidence["status"] in {
        "local", "incomplete"
    }


def test_identical_frozen_sessions_are_byte_repeatable(tmp_path):
    first = _session(tmp_path / "first")
    second = _session(tmp_path / "second")

    first_payload = first.request("callers", symbol="run_query").model_dump()
    second_payload = second.request("callers", symbol="run_query").model_dump()

    assert json.dumps(first_payload, sort_keys=True) == json.dumps(
        second_payload, sort_keys=True
    )
