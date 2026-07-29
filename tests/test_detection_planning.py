"""Zero-cost tests for bounded, ground-truth-blind detection planning."""

from __future__ import annotations

from pathlib import Path

import pytest

from repoauditor.detect.ensemble import (
    CandidateFinding,
    _retrieval_context,
    _retrieval_context_with_provenance,
)
from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.detect.planning import (
    plan_detection_regions,
    project_detection_work,
    validate_detection_projection,
)
from repoauditor.map import ArchitectureMap, EntryPoint
from repoauditor.map.domain_map import _build_context
from repoauditor.sourcefiles import (
    is_test_source,
    iter_source_files,
    select_diverse_source_files,
)
from repoauditor.store.models import Severity


def _sources(root: Path, count: int) -> None:
    for index in range(count):
        (root / f"module_{index}.py").write_text(f"value_{index} = {index}\n")


def _deep_sources(root: Path) -> None:
    for directory in ("api/routes", "core/auth", "storage/sql", "workers/jobs"):
        target = root / directory
        target.mkdir(parents=True)
        for index in range(8):
            (target / f"module_{index}.py").write_text(
                f"value_{directory.replace('/', '_')}_{index} = {index}\n"
            )
    for directory in ("tests/api", "spec/integration"):
        target = root / directory
        target.mkdir(parents=True)
        for index in range(8):
            (target / f"test_module_{index}.py").write_text(
                f"def test_{index}():\n    assert True\n"
            )


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


def test_cross_file_context_records_path_blind_expansion_provenance(tmp_path):
    """A related file stays distinct from the primary selection; no target name is used."""
    (tmp_path / "component_a.py").write_text(
        "def transform(value):\n"
        "    return normalize(value)\n"
    )
    (tmp_path / "component_b.py").write_text(
        "from component_a import transform\n\n"
        "def dispatch(payload):\n"
        "    return transform(payload)\n"
    )
    index = RetrievalIndex().build(tmp_path)
    primary = (tmp_path / "component_a.py").read_text()

    context, provenance = _retrieval_context_with_provenance(
        index, "component_a.py", primary
    )

    assert context == _retrieval_context(index, "component_a.py", primary)
    assert provenance == [{
        "basis": "call-name-match",
        "file": "component_b.py",
        "line_start": 3,
        "symbol": "dispatch",
    }]
    assert all(item["file"] != "component_a.py" for item in provenance)


def test_projection_reports_unbounded_and_bounded_work(tmp_config, tmp_path):
    _sources(tmp_path, 10)
    projection = project_detection_work(tmp_path, tmp_config, lens_count=3)

    assert projection.source_files == 10
    assert projection.unbounded_base_calls == 30
    assert projection.planned_regions == 6
    assert projection.planned_base_calls == 18
    assert projection.omitted_regions == 4


def test_kotlin_sources_are_visible_but_detection_work_remains_bounded(
    tmp_config, tmp_path,
):
    _sources(tmp_path, 8)
    (tmp_path / "Service.kt").write_text(
        "fun unpack(entry: String) = destination.resolve(entry)\n"
    )
    (tmp_path / "build.gradle.kts").write_text("plugins { kotlin(\"jvm\") }\n")

    visible = {
        path.relative_to(tmp_path).as_posix()
        for path in iter_source_files(tmp_path)
    }
    projection = project_detection_work(tmp_path, tmp_config, lens_count=3)

    assert {"Service.kt", "build.gradle.kts"} <= visible
    assert projection.source_files == 10
    assert projection.unbounded_base_calls == 30
    assert projection.planned_regions == tmp_config.detect.max_llm_regions_per_run
    assert projection.planned_base_calls == (
        tmp_config.detect.max_llm_regions_per_run * 3
    )


def test_architecture_signal_can_select_kotlin_without_expanding_region_cap(
    tmp_config, tmp_path,
):
    _sources(tmp_path, 8)
    target = tmp_path / "ArchiveService.kt"
    target.write_text("fun unpack(entry: String) = destination.resolve(entry)\n")
    architecture = ArchitectureMap(
        repo_id="repo",
        commit="commit",
        entry_points=[EntryPoint(name="archive upload", location="ArchiveService.kt:1")],
    )

    plan = plan_detection_regions(
        tmp_path,
        tmp_config,
        commit="commit",
        architecture=architecture,
        tool_candidates=[],
    )

    by_file = {item.relative_path: item.selection_basis for item in plan}
    assert by_file["ArchiveService.kt"] == "architecture-map"
    assert len(plan) == tmp_config.detect.max_llm_regions_per_run


def test_kotlin_participates_in_retrieval_via_logged_lexical_fallback(tmp_path):
    source = tmp_path / "ArchiveService.kt"
    source.write_text(
        "fun unpack(entry: String) {\n"
        "  val output = destination.resolve(entry)\n"
        "  Files.copy(stream, output)\n"
        "}\n"
    )

    index = RetrievalIndex().build(tmp_path)

    functions = index.functions_in_file("ArchiveService.kt")
    assert len(functions) == 1
    assert functions[0].language == "lexical"
    assert "resolve" in functions[0].calls


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


def test_source_selection_is_directory_diverse_and_bounds_test_share(tmp_path):
    _deep_sources(tmp_path)

    selected = select_diverse_source_files(tmp_path, 12)
    directories = {
        path.relative_to(tmp_path).parent.as_posix() for path in selected
    }
    test_count = sum(is_test_source(path, tmp_path) for path in selected)

    assert len(selected) == 12
    assert {"api/routes", "core/auth", "storage/sql", "workers/jobs"} <= directories
    assert test_count == 3


def test_source_selection_depends_on_paths_not_file_content(tmp_path):
    _deep_sources(tmp_path)
    first = [
        path.relative_to(tmp_path).as_posix()
        for path in select_diverse_source_files(tmp_path, 12)
    ]
    for path in iter_source_files(tmp_path):
        path.write_text("changed contents\n")

    second = [
        path.relative_to(tmp_path).as_posix()
        for path in select_diverse_source_files(tmp_path, 12)
    ]

    assert second == first


def test_map_context_allocates_bounded_space_across_selected_files(tmp_path):
    _deep_sources(tmp_path)
    selected = select_diverse_source_files(tmp_path, 40)

    context = _build_context(tmp_path, 8_000)

    assert len(context) <= 8_000
    assert len(selected) == 40
    for path in selected:
        rel = path.relative_to(tmp_path).as_posix()
        assert f"# FILE: {rel}\n" in context


def test_stable_coverage_plan_is_comparable_across_commits(tmp_config, tmp_path):
    _deep_sources(tmp_path)
    architecture = ArchitectureMap(repo_id="repo", commit="pre")

    before = plan_detection_regions(
        tmp_path,
        tmp_config,
        commit="pre-fix-commit",
        architecture=architecture,
        tool_candidates=[],
    )
    after = plan_detection_regions(
        tmp_path,
        tmp_config,
        commit="post-fix-commit",
        architecture=architecture,
        tool_candidates=[],
    )

    assert [item.relative_path for item in after] == [
        item.relative_path for item in before
    ]
