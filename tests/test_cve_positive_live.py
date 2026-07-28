"""Split-phase, bounded live evaluation for frozen CVE-positive acquisition pairs.

This is evaluation infrastructure, not training or pipeline logic. A pair must be selected
explicitly, its pre-fix snapshot always runs before its post-fix control, and the existing
pipeline call/token/batch limits remain authoritative. Detector output never becomes a
label. The harness executes the ground-truth-blind production screen and a separately
attributed advisory-target region, then spends falsification budget only on findings from
that target file. Unrelated output remains retained and unadjudicated. Scoring covers only
the advisory-derived target declared before execution.
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
from repoauditor.falsify import challenge as production_challenge
from repoauditor.map import ArchitectureMap, EntryPoint
from repoauditor.sourcefiles import iter_source_files
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
AIOHTTP_PLAN = (
    Path(__file__).parents[1]
    / "docs"
    / "aiohttp-owasp-v3-validation-plan-2026-07-28.json"
)
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


def _split_phase_planner(target_file: str, production_config):
    """Execute a production screen plus one advisory-conditioned semantic region.

    The target path comes from frozen, human-reviewed advisory metadata. It is never passed
    to the production planner. The wrapper retains that planner's bounded regions, then
    adds the target only when the blind plan omitted it. Selection bases stay distinct, so
    forced inclusion cannot receive production-coverage credit.
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
        all_source_files = [
            path.relative_to(snapshot_path).as_posix()
            for path in iter_source_files(snapshot_path)
        ]
        production_file_set = set(production_files)
        omitted_files = [
            path for path in all_source_files if path not in production_file_set
        ]
        target_path = snapshot_path / target_file
        if not target_path.is_file():
            raise RuntimeError(
                f"pre-registered CVE target is absent from snapshot: {target_file}"
            )
        target_was_selected = target_file in production_files
        evaluation_plan = list(planned)
        if not target_was_selected:
            evaluation_plan.append(
                PlannedRegion(target_path, target_file, TARGET_CONDITIONING_BASIS)
            )
        observations[commit] = {
            "mode": "production-screen+target-conditioned",
            "production_screen": {
                "selected_regions": production_files,
                "selected_count": len(production_files),
                "source_file_count": len(all_source_files),
                "omitted_regions": omitted_files,
                "omitted_count": len(omitted_files),
                "target_selected": target_was_selected,
                "target_omitted": not target_was_selected,
            },
            "semantic_phase": {
                "target_file": target_file,
                "selected_regions": [target_file],
                "forced_inclusion": not target_was_selected,
                "selection_basis": (
                    next(
                        item.selection_basis
                        for item in planned
                        if item.relative_path == target_file
                    )
                    if target_was_selected else TARGET_CONDITIONING_BASIS
                ),
            },
            "interpretation": (
                "The production screen and semantic target are evaluated in one bounded "
                "detect pass. Forced target inclusion receives no production-coverage "
                "credit; unrelated output is retained but excluded from target falsification."
            ),
        }
        return evaluation_plan

    return plan, observations


def _target_scoped_challenge(
    target_file: str,
    observations: dict[str, dict],
    challenge_fn=production_challenge,
):
    """Limit eval-only falsification spend while preserving unrelated store rows.

    The production challenger remains unchanged. During its candidate read only, this
    wrapper exposes findings from the pre-registered target file. All other detector
    output remains in SQLite with its existing unresolved status for unadjudicated review.
    """
    original_list_findings = db.list_findings

    def evidence(finding) -> dict:
        status = getattr(finding, "falsification_status", None)
        return {
            "id": finding.id,
            "title": getattr(finding, "title", None),
            "file": finding.file,
            "line_start": getattr(finding, "line_start", None),
            "line_end": getattr(finding, "line_end", None),
            "source_lens": getattr(finding, "source_lens", None),
            "source_tool": getattr(finding, "source_tool", None),
            "falsification_status": (
                status.value if hasattr(status, "value") else status
            ),
        }

    def challenge(repo_id: str, config):
        all_findings = original_list_findings(repo_id, config)
        target_findings = [
            finding for finding in all_findings if finding.file == target_file
        ]
        unrelated = [
            finding for finding in all_findings if finding.file != target_file
        ]
        matching_observation = next(
            (
                item for item in observations.values()
                if item["semantic_phase"]["target_file"] == target_file
                and "falsification_scope" not in item
            ),
            None,
        )
        if matching_observation is not None:
            matching_observation["falsification_scope"] = {
                "basis": "exact pre-registered target file",
                "detected_total": len(all_findings),
                "target_relevant_count": len(target_findings),
                "target_relevant": [evidence(finding) for finding in target_findings],
                "unrelated_unadjudicated_count": len(unrelated),
                "unrelated_unadjudicated": [
                    evidence(finding) for finding in unrelated
                ],
            }

        def target_only(
            requested_repo_id: str | None = None, requested_config=None
        ):
            if requested_repo_id in {None, repo_id}:
                return target_findings
            return original_list_findings(requested_repo_id, requested_config)

        db.list_findings = target_only
        try:
            return challenge_fn(repo_id, config)
        finally:
            db.list_findings = original_list_findings

    return challenge


def _validated_evaluation_design(observation: dict | None) -> dict:
    """Fail closed before a completed artifact can blur coverage and semantics."""
    if observation is None:
        raise RuntimeError("completed CVE evaluation has no selection observation")
    required = {"production_screen", "semantic_phase", "falsification_scope"}
    missing = required - observation.keys()
    if missing:
        raise RuntimeError(
            "completed CVE evaluation lacks phase evidence: "
            + ", ".join(sorted(missing))
        )
    production = observation["production_screen"]
    if production["selected_count"] + production["omitted_count"] != (
        production["source_file_count"]
    ):
        raise RuntimeError("production selection coverage does not close")
    semantic = observation["semantic_phase"]
    if semantic["target_file"] not in semantic["selected_regions"]:
        raise RuntimeError("semantic phase did not include its pre-registered target")
    return observation


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


def test_aiohttp_validation_pair_is_frozen_before_live_execution():
    pair = _pair("aiohttp_cve_2024_23334", Path("/nonexistent"))

    assert [item.expected["source"]["variant"] for item in pair] == [
        "pre_fix", "post_fix",
    ]
    target = pair[0].expected["findings"][0]
    assert target == {
        "title": "Directory traversal when static resources follow symlinks",
        "file": "aiohttp/web_urldispatcher.py",
        "line_start": 637,
        "line_end": 647,
        "citation_contains": "self._directory.joinpath(filename).resolve()",
        "cve": "CVE-2024-23334",
    }
    assert pair[0].expected["source"]["pinned_commit"] == (
        "33ccdfb0a12690af5bb49bda2319ec0907fa7827"
    )
    assert pair[1].expected["source"]["pinned_commit"] == (
        "1c335944d6a8b1298baf179b7c0b3069f10c514b"
    )
    assert pair[1].expected["findings"] == []
    assert pair[1].expected["expected_absent"] == [target]


def test_aiohttp_validation_plan_is_frozen_to_current_instrument():
    plan = json.loads(AIOHTTP_PLAN.read_text())

    assert plan["status"] == "ready_not_run"
    assert plan["project"]["slug"] == "aiohttp_cve_2024_23334"
    assert plan["evidence_classification"]["selection_holdout"] is False
    assert plan["execution"]["prompt_versions"] == _live_prompt_versions()
    assert plan["execution"]["production_region_cap"] == 6
    assert plan["execution"]["evaluation_target_region_allowance"] == 1
    assert plan["execution"]["pipeline_call_ceiling"] == 75
    assert plan["execution"]["pipeline_token_ceiling"] == 250000
    assert plan["execution"]["outer_timeout_minutes"] == 20
    assert plan["execution"][
        "requires_same-run_manufactured_archive_detection_qualification"
    ] is True
    assert len(plan["frozen_semantic_obligations"]["positive"]) == 3
    assert "follow_symlinks" in plan["frozen_semantic_obligations"]["positive"][1]


def test_split_phase_planner_executes_production_screen_and_semantic_target(
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
    plan, observations = _split_phase_planner(target, production_config)

    selected = plan(
        tmp_path,
        tmp_config,
        commit="abc",
        architecture=architecture,
        tool_candidates=[],
    )

    assert [item.relative_path for item in selected] == ["entry.py", target]
    assert selected[-1].selection_basis == TARGET_CONDITIONING_BASIS
    assert observations["abc"]["production_screen"]["selected_regions"] == ["entry.py"]
    assert observations["abc"]["production_screen"]["omitted_regions"] == [target]
    assert observations["abc"]["production_screen"]["target_selected"] is False
    assert observations["abc"]["production_screen"]["target_omitted"] is True
    assert observations["abc"]["semantic_phase"]["selected_regions"] == [target]
    assert observations["abc"]["semantic_phase"]["forced_inclusion"] is True
    assert observations["abc"]["interpretation"].startswith(
        "The production screen and semantic target"
    )


def test_split_phase_planner_does_not_duplicate_a_production_selected_target(
    tmp_config, tmp_path,
):
    target = "entry.py"
    (tmp_path / target).write_text("def handler(): pass\n")
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
    plan, observations = _split_phase_planner(target, production_config)

    selected = plan(
        tmp_path,
        tmp_config,
        commit="abc",
        architecture=architecture,
        tool_candidates=[],
    )

    assert [item.relative_path for item in selected] == [target]
    assert observations["abc"]["semantic_phase"]["forced_inclusion"] is False
    assert observations["abc"]["semantic_phase"]["selection_basis"] == "architecture-map"


def test_target_scoped_challenge_retains_unrelated_findings_unadjudicated(
    tmp_config, monkeypatch,
):
    findings = [
        SimpleNamespace(id=1, file="target.py"),
        SimpleNamespace(id=2, file="other.py"),
        SimpleNamespace(id=3, file="target.py"),
    ]
    monkeypatch.setattr(db, "list_findings", lambda repo_id=None, config=None: findings)
    observations = {
        "commit": {
            "semantic_phase": {"target_file": "target.py"},
        }
    }

    def fake_challenge(repo_id, config):
        return db.list_findings(repo_id, config)

    scoped = _target_scoped_challenge(
        "target.py", observations, challenge_fn=fake_challenge
    )
    selected = scoped("repo", tmp_config)

    assert [finding.id for finding in selected] == [1, 3]
    assert [finding.id for finding in db.list_findings("repo", tmp_config)] == [1, 2, 3]
    assert observations["commit"]["falsification_scope"] == {
        "basis": "exact pre-registered target file",
        "detected_total": 3,
        "target_relevant_count": 2,
        "target_relevant": [
            {
                "id": 1, "title": None, "file": "target.py",
                "line_start": None, "line_end": None,
                "source_lens": None, "source_tool": None,
                "falsification_status": None,
            },
            {
                "id": 3, "title": None, "file": "target.py",
                "line_start": None, "line_end": None,
                "source_lens": None, "source_tool": None,
                "falsification_status": None,
            },
        ],
        "unrelated_unadjudicated_count": 1,
        "unrelated_unadjudicated": [{
            "id": 2, "title": None, "file": "other.py",
            "line_start": None, "line_end": None,
            "source_lens": None, "source_tool": None,
            "falsification_status": None,
        }],
    }


def test_completed_evaluation_design_fails_closed_without_phase_evidence():
    with pytest.raises(RuntimeError, match="lacks phase evidence: falsification_scope"):
        _validated_evaluation_design({
            "production_screen": {},
            "semantic_phase": {},
        })


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
    evaluation_region_cap = production_config.detect.max_llm_regions_per_run + 1
    tmp_config = tmp_config.model_copy(update={
        "paths": tmp_config.paths.model_copy(update={
            "data_dir": data_dir,
            "raw_dir": data_dir / "raw",
            "db_path": data_dir / "repoauditor.db",
        }),
        "detect": tmp_config.detect.model_copy(update={
            # Evaluation-only allowance: normal bounded production screen plus at most
            # one pre-registered target region. Production configuration is unchanged.
            "max_llm_regions_per_run": evaluation_region_cap,
            "reserved_sample_regions": min(
                tmp_config.detect.reserved_sample_regions,
                evaluation_region_cap,
            ),
        }),
    })
    target_file = pair[0].expected["findings"][0]["file"]
    target_plan, selection_observations = _split_phase_planner(
        target_file, production_config
    )
    monkeypatch.setattr(ensemble, "plan_detection_regions", target_plan)
    monkeypatch.setattr(
        cli, "challenge",
        _target_scoped_challenge(target_file, selection_observations),
    )
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
            selection_evidence = _validated_evaluation_design(selection_evidence)
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
