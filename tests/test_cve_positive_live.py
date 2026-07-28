"""Bounded live evaluation for the frozen CVE-positive acquisition pairs.

This is evaluation infrastructure, not training or pipeline logic. A pair must be selected
explicitly, its pre-fix snapshot always runs before its post-fix control, and the existing
pipeline call/token/batch limits remain authoritative. Detector output never becomes a
label, and scoring covers only the advisory-derived target declared before execution.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from repoauditor import cli
from repoauditor.detect import ensemble
from repoauditor.detect.planning import PlannedRegion
from repoauditor.map import ArchitectureMap, EntryPoint
from repoauditor.store import db
from test_benchmark_corpus import (
    _append_live_uat_result,
    _live_prompt_versions,
    _pipeline_evidence,
    _run_live_pipeline,
)
from uat_scoring import score_independent_target


FIXTURES = Path(__file__).parent / "fixtures"
MANIFEST = FIXTURES / "cve_positive_acquisition_cohort.json"
TARGET_CONDITIONING_BASIS = "evaluation-target-conditioned"


def _project(slug: str) -> dict:
    manifest = json.loads(MANIFEST.read_text())
    matches = [item for item in manifest["projects"] if item["slug"] == slug]
    if len(matches) != 1:
        available = ", ".join(item["slug"] for item in manifest["projects"])
        raise ValueError(f"unknown CVE-positive pair {slug!r}; available: {available}")
    return matches[0]


def _pair(slug: str, root: Path) -> list[SimpleNamespace]:
    project = _project(slug)
    result = []
    for short_variant, source_variant, commit in (
        ("pre", "pre_fix", project["vulnerable_commit"]),
        ("post", "post_fix", project["fixed_commit"]),
    ):
        repo_id = f"acquisition_cve_{slug}_{short_variant}"
        target = {
            **project["target"],
            "cve": "/".join(project["cve_ids"]),
        }
        result.append(SimpleNamespace(
            repo_id=repo_id,
            snapshot_path=root / repo_id / "snapshot",
            expected={
                "source": {
                    "kind": "independent",
                    "evaluation_role": "cve_positive_acquisition",
                    "project_id": slug,
                    "project": project["project"],
                    "variant": source_variant,
                    "pinned_commit": commit,
                    "pre_fix_commit": project["vulnerable_commit"],
                    "post_fix_commit": project["fixed_commit"],
                    "license": project["license"],
                    "cve": "/".join(project["cve_ids"]),
                    "ground_truth": (
                        "Human-reviewed advisory and isolated security patch; never "
                        "inferred from repoauditor output."
                    ),
                },
                "findings": [target] if source_variant == "pre_fix" else [],
                "expected_absent": [target] if source_variant == "post_fix" else [],
            },
        ))
    return result


def _target_conditioned_planner(target_file: str, production_config):
    """Build an eval-only planner while retaining the production selection counterfactual.

    The target path comes from frozen, human-reviewed advisory metadata. It is never passed
    to the production planner. The wrapper first records that planner's ground-truth-blind
    selection, then returns only the declared target file for the paid semantic test.
    """
    production_plan = ensemble.plan_detection_regions
    observations: dict[str, dict] = {}

    def plan(
        snapshot_path: Path,
        _evaluation_config,
        *,
        commit: str,
        architecture: ArchitectureMap,
        tool_candidates,
    ) -> list[PlannedRegion]:
        planned = production_plan(
            snapshot_path,
            production_config,
            commit=commit,
            architecture=architecture,
            tool_candidates=tool_candidates,
        )
        production_files = [item.relative_path for item in planned]
        target_path = snapshot_path / target_file
        if not target_path.is_file():
            raise RuntimeError(
                f"pre-registered CVE target is absent from snapshot: {target_file}"
            )
        observations[commit] = {
            "mode": "target-conditioned",
            "target_file": target_file,
            "production_target_selected": target_file in production_files,
            "production_selected_regions": production_files,
            "evaluation_selected_regions": [target_file],
            "selection_basis": TARGET_CONDITIONING_BASIS,
            "interpretation": (
                "Semantic target recovery is conditioned on the reviewed target file. "
                "Production retrieval coverage is reported separately and receives no "
                "credit from this forced inclusion."
            ),
        }
        return [PlannedRegion(target_path, target_file, TARGET_CONDITIONING_BASIS)]

    return plan, observations


def test_cve_positive_pair_builder_preserves_pre_post_order_and_target():
    pair = _pair("pyjwt_cve_2022_29217", Path("/nonexistent"))

    assert [item.expected["source"]["variant"] for item in pair] == [
        "pre_fix", "post_fix",
    ]
    assert pair[0].expected["findings"][0]["file"] == "jwt/algorithms.py"
    assert pair[1].expected["expected_absent"][0]["cve"] == "CVE-2022-29217"
    assert all(
        item.expected["source"]["evaluation_role"] == "cve_positive_acquisition"
        for item in pair
    )


def test_simple_git_validation_pair_is_frozen_before_live_execution():
    pair = _pair("simple_git_cve_2026_28292", Path("/nonexistent"))

    assert [item.expected["source"]["variant"] for item in pair] == [
        "pre_fix", "post_fix",
    ]
    target = pair[0].expected["findings"][0]
    assert target["cve"] == "CVE-2026-28292"
    assert target["file"] == (
        "simple-git/src/lib/plugins/block-unsafe-operations-plugin.ts"
    )
    assert target["citation_contains"] == "protocol(.[a-z]+)?.allow"
    assert pair[1].expected["findings"] == []
    assert pair[1].expected["expected_absent"] == [target]


def test_reposilite_validation_pair_is_frozen_before_live_execution():
    pair = _pair("reposilite_cve_2024_36116", Path("/nonexistent"))

    assert [item.expected["source"]["variant"] for item in pair] == [
        "pre_fix", "post_fix",
    ]
    target = pair[0].expected["findings"][0]
    assert target["cve"] == "CVE-2024-36116"
    assert target["file"] == (
        "reposilite-backend/src/main/kotlin/com/reposilite/javadocs/"
        "JavadocContainerService.kt"
    )
    assert target["citation_contains"] == "javadocUnpackPath.toString()"
    assert pair[0].expected["source"]["pinned_commit"] == (
        "e172ae4b539c822d0d6e04cf090713c7202a79d6"
    )
    assert pair[1].expected["source"]["pinned_commit"] == (
        "848173738e4375482c70365db5cebae29f125eaa"
    )
    assert pair[1].expected["findings"] == []
    assert pair[1].expected["expected_absent"] == [target]


def test_ruby_saml_validation_pair_is_frozen_as_one_compound_target():
    pair = _pair("ruby_saml_cve_2025_25291_25292", Path("/nonexistent"))

    assert [item.expected["source"]["variant"] for item in pair] == [
        "pre_fix", "post_fix",
    ]
    target = pair[0].expected["findings"][0]
    assert target["cve"] == "CVE-2025-25291/CVE-2025-25292"
    assert target["file"] == "lib/xml_security.rb"
    assert target["citation_contains"] == "reference_nodes = document.xpath"
    assert pair[0].expected["source"]["pinned_commit"] == (
        "acac9e9cc0b9a507882c614f25d41f8b47be349a"
    )
    assert pair[1].expected["source"]["pinned_commit"] == (
        "e9c1cdbd0f9afa467b585de279db0cbd0fb8ae97"
    )
    assert pair[1].expected["findings"] == []
    assert pair[1].expected["expected_absent"] == [target]


def test_target_conditioned_planner_separates_semantic_eval_from_production_selection(
    tmp_config, tmp_path,
):
    target = "jwt/algorithms.py"
    target_path = tmp_path / target
    target_path.parent.mkdir(parents=True)
    target_path.write_text("invalid_strings = []\n")
    (tmp_path / "entry.py").write_text("def handler(): pass\n")
    architecture = ArchitectureMap(
        repo_id="repo",
        commit="abc",
        entry_points=[EntryPoint(name="handler", location="entry.py:1")],
    )
    production_config = tmp_config.model_copy(update={
        "detect": tmp_config.detect.model_copy(update={
            "max_llm_regions_per_run": 1,
            "reserved_sample_regions": 0,
        })
    })
    plan, observations = _target_conditioned_planner(target, production_config)

    selected = plan(
        tmp_path,
        tmp_config,
        commit="abc",
        architecture=architecture,
        tool_candidates=[],
    )

    assert [item.relative_path for item in selected] == [target]
    assert selected[0].selection_basis == TARGET_CONDITIONING_BASIS
    assert observations["abc"]["evaluation_selected_regions"] == [target]
    assert observations["abc"]["production_selected_regions"] == ["entry.py"]
    assert observations["abc"]["production_target_selected"] is False
    assert observations["abc"]["interpretation"].startswith(
        "Semantic target recovery is conditioned"
    )


@pytest.mark.live
def test_cve_positive_live_pair(tmp_config, monkeypatch):
    """Evaluate one explicitly selected pre/post pair and retain terminal evidence."""
    slug = os.environ.get("REPOAUDITOR_CVE_POSITIVE_PAIR", "").strip()
    if not slug:
        pytest.skip("REPOAUDITOR_CVE_POSITIVE_PAIR is required for paid pair evaluation")
    root = Path(os.environ.get(
        "REPOAUDITOR_CVE_POSITIVE_ROOT", str(FIXTURES)
    )).resolve()
    pair = _pair(slug, root)
    missing = [str(item.snapshot_path) for item in pair if not item.snapshot_path.is_dir()]
    if missing:
        raise RuntimeError(
            "CVE-positive pair is not materialized: " + ", ".join(missing)
        )

    data_dir = Path(os.environ.get(
        "REPOAUDITOR_UAT_DATA_DIR", "live-cve-positive-data"
    )).resolve()
    production_config = tmp_config
    tmp_config = tmp_config.model_copy(update={
        "paths": tmp_config.paths.model_copy(update={
            "data_dir": data_dir,
            "raw_dir": data_dir / "raw",
            "db_path": data_dir / "repoauditor.db",
        }),
        "detect": tmp_config.detect.model_copy(update={
            "max_llm_regions_per_run": 1,
            "reserved_sample_regions": 1,
        }),
    })
    target_file = pair[0].expected["findings"][0]["file"]
    target_plan, selection_observations = _target_conditioned_planner(
        target_file, production_config
    )
    monkeypatch.setattr(ensemble, "plan_detection_regions", target_plan)
    db.init_db(tmp_config)
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    artifact = Path(os.environ.get(
        "REPOAUDITOR_UAT_RESULTS", "live-cve-positive-results.json"
    ))
    max_batches = int(os.environ.get("REPOAUDITOR_UAT_MAX_BATCHES", "2"))
    if not 1 <= max_batches <= 6:
        raise ValueError("REPOAUDITOR_UAT_MAX_BATCHES must be between 1 and 6")

    for fixture in pair:
        repo_id: str | None = None
        selection_evidence: dict | None = None
        try:
            repo_id = _run_live_pipeline(
                fixture, tmp_config, max_batches=max_batches
            )
            _, commit = cli.latest_snapshot(tmp_config, repo_id)
            selection_evidence = selection_observations.get(commit)
            score = score_independent_target(
                db.list_findings(repo_id, tmp_config), fixture.expected
            )
        except BaseException as exc:
            if repo_id is None:
                matches = [
                    item for item in db.list_ingested_repos(tmp_config)
                    if Path(item.source).resolve() == fixture.snapshot_path.resolve()
                ]
                repo_id = matches[-1].repo_id if matches else fixture.repo_id
            if selection_evidence is None and selection_observations:
                selection_evidence = list(selection_observations.values())[-1]
            _append_live_uat_result(
                artifact,
                fixture,
                tmp_config,
                status="failed",
                pipeline=_pipeline_evidence(tmp_config, repo_id),
                failure_detail=f"{type(exc).__name__}: {exc}"[:4000],
                evaluation_design=selection_evidence,
            )
            raise
        _append_live_uat_result(
            artifact,
            fixture,
            tmp_config,
            status="completed",
            score=score,
            run=SimpleNamespace(prompt_versions=_live_prompt_versions()),
            pipeline=_pipeline_evidence(tmp_config, repo_id),
            evaluation_design=selection_evidence,
        )
