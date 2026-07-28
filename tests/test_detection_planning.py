"""Zero-cost tests for bounded, ground-truth-blind detection planning."""

from __future__ import annotations

from pathlib import Path

import pytest

from repoauditor.detect.ensemble import CandidateFinding, _retrieval_context
from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.detect.planning import (
    plan_detection_regions,
    project_detection_work,
    validate_detection_projection,
)
from repoauditor.map import ArchitectureMap, EntryPoint
from repoauditor.store.models import Severity


def _sources(root: Path, count: int) -> None:
    for index in range(count):
        (root / f"module_{index}.py").write_text(f"value_{index} = {index}\n")


def test_detection_context_prioritizes_external_callers_over_same_file_similarity(
    tmp_path,
):
    (tmp_path / "library.py").write_text(
        "def prepare(value):\n"
        "    return normalize(value)\n\n"
        "def helper(value):\n"
        "    return normalize(value)\n"
    )
    (tmp_path / "runtime.py").write_text(
        "from library import prepare\n\n"
        "def verify(untrusted):\n"
        "    return prepare(untrusted)\n"
    )
    index = RetrievalIndex().build(tmp_path)
    primary = (tmp_path / "library.py").read_text()

    context = _retrieval_context(index, "library.py", primary)

    assert "# RELATED CALL-NAME MATCH: verify (runtime.py:3)" in context
    assert "return prepare(untrusted)" in context
    assert "RELATED CALL-NAME MATCH: helper" not in context
    assert "RELATED SIMILAR PATTERN: helper" not in context


def test_projection_reports_unbounded_and_bounded_work(tmp_config, tmp_path):
    _sources(tmp_path, 10)
    projection = project_detection_work(tmp_path, tmp_config, lens_count=3)

    assert projection.source_files == 10
    assert projection.unbounded_base_calls == 30
    assert projection.planned_regions == 6
    assert projection.planned_base_calls == 18
    assert projection.omitted_regions == 4


def test_projection_fails_before_calls_when_configured_cap_cannot_fit(
    tmp_config, tmp_path
):
    _sources(tmp_path, 10)
    llm = tmp_config.llm.model_copy(update={"max_calls_per_pipeline_run": 10})
    config = tmp_config.model_copy(update={"llm": llm})
    projection = project_detection_work(tmp_path, config, lens_count=3)

    with pytest.raises(ValueError, match="minimum base calls=20"):
        validate_detection_projection(projection, config, preceding_map_calls=2)


def test_region_plan_prefers_independent_signals_and_reserves_stable_sample(
    tmp_config, tmp_path
):
    _sources(tmp_path, 8)
    tool = CandidateFinding(
        title="scanner candidate",
        file="module_6.py",
        line_start=1,
        line_end=1,
        citation_snippet="value_6 = 6",
        source_tool="sast",
        producer="semgrep",
        confidence=0.9,
        severity=Severity.HIGH,
    )
    architecture = ArchitectureMap(
        repo_id="repo",
        commit="commit",
        entry_points=[EntryPoint(name="HTTP", location="module_7.py:1")],
    )
    first = plan_detection_regions(
        tmp_path,
        tmp_config,
        commit="commit",
        architecture=architecture,
        tool_candidates=[tool],
    )
    second = plan_detection_regions(
        tmp_path,
        tmp_config,
        commit="commit",
        architecture=architecture,
        tool_candidates=[tool],
    )

    assert first == second
    by_file = {item.relative_path: item.selection_basis for item in first}
    assert by_file["module_6.py"] == "deterministic:semgrep"
    assert by_file["module_7.py"] == "architecture-map"
    assert sum(
        item.selection_basis == "stable-coverage-sample" for item in first
    ) >= 2
    assert len(first) == tmp_config.detect.max_llm_regions_per_run
