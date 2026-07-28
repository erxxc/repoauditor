import json
from pathlib import Path

import pytest

from repoauditor.map import ArchitectureMap, EntryPoint
from selection_evidence import (
    adjudicate_pair_selection,
    adjudicate_target_selection,
    capture_production_selection,
)

PLAN = (
    Path(__file__).parents[1]
    / "docs"
    / "untouched-production-selection-plan-2026-07-28.json"
)


def _sources(root: Path) -> None:
    for relative in (
        "app/main.py",
        "app/routes.py",
        "lib/parser.py",
        "services/billing.py",
        "tests/test_main.py",
        "target/vulnerable.py",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {relative}\n")


def test_capture_is_target_blind_and_later_adjudication_is_linked(
    tmp_path, tmp_config,
):
    _sources(tmp_path)
    architecture = ArchitectureMap(
        repo_id="repo",
        commit="abc",
        entry_points=[EntryPoint(name="route", location="app/routes.py")],
    )

    capture = capture_production_selection(
        tmp_path,
        repo_id="repo",
        commit="abc",
        architecture=architecture,
        tool_candidates=[],
        config=tmp_config,
    )

    assert capture["target_metadata_consulted"] is False
    assert capture["selected_count"] + capture["omitted_count"] == 6
    assert capture["capture_sha256"]
    adjudication = adjudicate_target_selection(
        capture, tmp_path, target_file="target/vulnerable.py"
    )
    assert adjudication["capture_sha256"] == capture["capture_sha256"]
    assert adjudication["target_in_source_inventory"] is True
    assert adjudication["target_selected"] == any(
        region["path"] == "target/vulnerable.py"
        for region in capture["selected_regions"]
    )


def test_adjudication_distinguishes_source_inventory_exclusion(
    tmp_path, tmp_config,
):
    _sources(tmp_path)
    (tmp_path / "config.yaml").write_text("unsafe: true\n")
    capture = capture_production_selection(
        tmp_path,
        repo_id="repo",
        commit="abc",
        architecture=ArchitectureMap(repo_id="repo", commit="abc"),
        tool_candidates=[],
        config=tmp_config,
    )

    adjudication = adjudicate_target_selection(
        capture, tmp_path, target_file="config.yaml"
    )

    assert adjudication["target_in_source_inventory"] is False
    assert adjudication["target_selected"] is False
    assert adjudication["omission_basis"] == "outside_source_inventory"


def test_adjudication_fails_closed_on_capture_or_snapshot_change(
    tmp_path, tmp_config,
):
    _sources(tmp_path)
    capture = capture_production_selection(
        tmp_path,
        repo_id="repo",
        commit="abc",
        architecture=ArchitectureMap(repo_id="repo", commit="abc"),
        tool_candidates=[],
        config=tmp_config,
    )

    changed_capture = {
        **capture,
        "selected_regions": [
            *capture["selected_regions"],
            {"path": "target/vulnerable.py", "selection_basis": "injected"},
        ],
    }
    with pytest.raises(ValueError, match="integrity"):
        adjudicate_target_selection(
            changed_capture, tmp_path, target_file="target/vulnerable.py"
        )

    (tmp_path / "app/main.py").write_text("# changed after capture\n")
    with pytest.raises(ValueError, match="snapshot differs"):
        adjudicate_target_selection(
            capture, tmp_path, target_file="target/vulnerable.py"
        )


def test_capture_rejects_architecture_from_another_snapshot(
    tmp_path, tmp_config,
):
    _sources(tmp_path)

    with pytest.raises(ValueError, match="architecture identity"):
        capture_production_selection(
            tmp_path,
            repo_id="repo",
            commit="abc",
            architecture=ArchitectureMap(repo_id="other", commit="def"),
            tool_candidates=[],
            config=tmp_config,
        )


def test_pair_adjudication_requires_matching_frozen_config(
    tmp_path, tmp_config,
):
    pre = tmp_path / "pre"
    post = tmp_path / "post"
    _sources(pre)
    _sources(post)
    architecture = ArchitectureMap(repo_id="pre", commit="abc")
    pre_capture = capture_production_selection(
        pre,
        repo_id="pre",
        commit="abc",
        architecture=architecture,
        tool_candidates=[],
        config=tmp_config,
    )
    post_capture = capture_production_selection(
        post,
        repo_id="post",
        commit="def",
        architecture=architecture.model_copy(update={"repo_id": "post", "commit": "def"}),
        tool_candidates=[],
        config=tmp_config,
    )

    result = adjudicate_pair_selection(
        pre_capture,
        post_capture,
        pre,
        post,
        target_file="target/vulnerable.py",
    )
    assert result["target_disclosed_after_both_captures"] is True

    post_capture["instrument"]["max_llm_regions_per_run"] += 1
    with pytest.raises(ValueError, match="config differs"):
        adjudicate_pair_selection(
            pre_capture,
            post_capture,
            pre,
            post,
            target_file="target/vulnerable.py",
        )


def test_untouched_selection_plan_requires_new_blind_acquisition():
    plan = json.loads(PLAN.read_text())

    assert plan["status"] == "instrument_ready_new_acquisition_required"
    assert plan["current_corpus_eligibility"]["eligible_pairs"] == 0
    assert "target path or lines" in plan["instrument"]["prohibited_capture_inputs"]
    assert plan["resource_boundary"]["later_provider_work"].startswith(
        "Architecture mapping only."
    )
    assert plan["interpretation"]["omitted"].endswith(
        "not a semantic detector false negative."
    )
