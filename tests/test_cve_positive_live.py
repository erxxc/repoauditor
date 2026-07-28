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

import hashlib
import json
import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from repoauditor.detect import ensemble
from repoauditor.detect.planning import PlannedRegion
from repoauditor.falsify import challenge as production_challenge
from repoauditor.ingest import ingest_repo
from repoauditor.llm import model_usage_scope
from repoauditor.map import ArchitectureMap, EntryPoint, recover_architecture
from repoauditor.sourcefiles import iter_source_files
from repoauditor.store import db
from repoauditor.store.models import RunStatus
from test_benchmark_corpus import (
    _append_live_uat_result,
    _live_prompt_versions,
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


def _root_failure_detail(exc: BaseException) -> str:
    """Retain the attributable exception hidden behind a Click/Typer exit."""
    cause = exc
    seen: set[int] = set()
    while cause.__cause__ is not None and id(cause) not in seen:
        seen.add(id(cause))
        cause = cause.__cause__
    return f"{type(cause).__name__}: {cause}"[:4000]


def _phase_evidence(run_id: int, config) -> dict:
    run = db.get_pipeline_run(run_id, config)
    if run is None:
        raise RuntimeError(f"evaluation phase run #{run_id} disappeared")
    return {
        "run_id": run_id,
        "status": run.status.value,
        "failed_stage": run.failed_stage,
        "failure_detail": run.failure_detail,
        "usage": db.summarize_model_usage(run_id, config),
        "stages": [
            {
                "stage": stage.stage,
                "status": stage.status.value,
                "failure_detail": stage.failure_detail,
            }
            for stage in db.list_stage_runs(run_id, config)
        ],
    }


def _metered_phase(
    source: str,
    repo_id: str,
    commit: str,
    stage: str,
    fn,
    config,
    *,
    parent_run_id: int | None = None,
):
    """Run one evaluation phase with its own unchanged production budget."""
    pipeline = db.start_pipeline_run(
        source, config, parent_run_id=parent_run_id
    )
    db.update_pipeline_run_identity(pipeline.id, repo_id, commit, config)
    db.start_stage_run(pipeline.id, stage, config)
    try:
        with model_usage_scope(pipeline.id):
            value = fn()
    except BaseException as exc:
        detail = _root_failure_detail(exc)
        db.finish_stage_run(
            pipeline.id, stage, RunStatus.FAILED,
            failure_detail=detail, config=config,
        )
        db.finish_pipeline_run(
            pipeline.id, RunStatus.FAILED, failed_stage=stage,
            failure_detail=detail, config=config,
        )
        raise
    usage = db.summarize_model_usage(pipeline.id, config)
    db.finish_stage_run(
        pipeline.id, stage, RunStatus.COMPLETED,
        summary={"model_usage": usage}, config=config,
    )
    db.finish_pipeline_run(pipeline.id, RunStatus.COMPLETED, config=config)
    return value, pipeline


def _production_observation(
    snapshot_path: Path,
    target_file: str,
    detection,
) -> dict:
    selected = [item["file"] for item in detection.selected_regions]
    all_sources = [
        path.relative_to(snapshot_path).as_posix()
        for path in iter_source_files(snapshot_path)
    ]
    selected_set = set(selected)
    omitted = [path for path in all_sources if path not in selected_set]
    return {
        "mode": "separately-metered-production-screen+target-conditioned",
        "production_screen": {
            "selected_regions": selected,
            "selected_count": len(selected),
            "source_file_count": len(all_sources),
            "omitted_regions": omitted,
            "omitted_count": len(omitted),
            "target_selected": target_file in selected_set,
            "target_omitted": target_file not in selected_set,
        },
        "semantic_phase": {
            "target_file": target_file,
            "selected_regions": [target_file],
            "forced_inclusion": target_file not in selected_set,
            "selection_basis": (
                next(
                    item["basis"] for item in detection.selected_regions
                    if item["file"] == target_file
                )
                if target_file in selected_set else TARGET_CONDITIONING_BASIS
            ),
        },
        "interpretation": (
            "Production screening and OWASP target adjudication use separate metered "
            "pipeline runs. Forced inclusion receives no production-coverage credit."
        ),
    }


def _target_only_planner(target_file: str):
    def plan(
        snapshot_path: Path,
        _config,
        *,
        commit: str,
        architecture: ArchitectureMap,
        tool_candidates,
    ) -> list[PlannedRegion]:
        del commit, architecture, tool_candidates
        target = snapshot_path / target_file
        if not target.is_file():
            raise RuntimeError(
                f"pre-registered CVE target is absent from snapshot: {target_file}"
            )
        return [PlannedRegion(target, target_file, TARGET_CONDITIONING_BASIS)]

    return plan


@contextmanager
def _owasp_target_scope(target_file: str):
    """Evaluation-only one-region/one-lens scope; production globals are restored."""
    original_plan = ensemble.plan_detection_regions
    original_lenses = ensemble.LENSES
    original_prompts = ensemble._LENS_PROMPTS
    original_versions = ensemble.LENS_PROMPT_VERSIONS
    ensemble.plan_detection_regions = _target_only_planner(target_file)
    ensemble.LENSES = {"owasp": original_lenses["owasp"]}
    ensemble._LENS_PROMPTS = {"owasp": original_prompts["owasp"]}
    ensemble.LENS_PROMPT_VERSIONS = {"owasp": original_versions["owasp"]}
    try:
        yield
    finally:
        ensemble.plan_detection_regions = original_plan
        ensemble.LENSES = original_lenses
        ensemble._LENS_PROMPTS = original_prompts
        ensemble.LENS_PROMPT_VERSIONS = original_versions


def _run_fresh_split_fixture(
    fixture,
    config,
    target_file: str,
) -> tuple[str, dict, dict]:
    """Run map+production screen, then OWASP target detect+falsify under a fresh budget."""
    identity = ingest_repo(
        str(fixture.snapshot_path), config, repo_id=fixture.repo_id
    )

    def production():
        recover_architecture(
            identity.snapshot_path, identity.repo_id, identity.commit, config
        )
        return ensemble.run_ensemble(identity.repo_id, config)

    detection, production_run = _metered_phase(
        identity.source, identity.repo_id, identity.commit,
        "evaluation-production-screen", production, config,
    )
    observation = _production_observation(
        identity.snapshot_path, target_file, detection
    )
    semantic_config = config.model_copy(update={
        "detect": config.detect.model_copy(update={
            "run_deterministic_tools": False,
            "max_llm_regions_per_run": 1,
            "reserved_sample_regions": 1,
        })
    })

    def semantic():
        with _owasp_target_scope(target_file):
            ensemble.run_ensemble(identity.repo_id, semantic_config)
        scoped = _target_scoped_challenge(target_file, {
            identity.commit: observation
        })
        return scoped(identity.repo_id, semantic_config)

    _outcomes, semantic_run = _metered_phase(
        identity.source, identity.repo_id, identity.commit,
        "evaluation-target-owasp-falsify", semantic, semantic_config,
        parent_run_id=production_run.id,
    )
    design = _validated_evaluation_design(observation)
    phases = {
        "production_screen": _phase_evidence(production_run.id, config),
        "target_owasp_falsify": _phase_evidence(semantic_run.id, config),
    }
    return identity.repo_id, design, phases


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _snapshot_content_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if ".git" in path.relative_to(root).parts:
            continue
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()[:12]


def _available_phase_evidence(repo_id: str, config) -> dict:
    latest = db.get_latest_pipeline_run(repo_id, config)
    if latest is None or latest.id is None:
        return {}
    return {
        str(run.id): _phase_evidence(run.id, config)
        for run in db.list_pipeline_run_chain(latest.id, config)
        if run.id is not None
    }


def _validate_continuation(
    fixture,
    config,
    receipt_path: Path,
) -> tuple[str, str, dict]:
    """Validate the exact retained failed-run evidence before reusing any checkpoint."""
    plan = json.loads(AIOHTTP_PLAN.read_text())["continuation"]
    if _sha256(receipt_path) != plan["results_sha256"]:
        raise RuntimeError("continuation results digest does not match the frozen receipt")
    if _sha256(config.db_path) != plan["database_sha256"]:
        raise RuntimeError("continuation database digest does not match the frozen receipt")
    receipt = json.loads(receipt_path.read_text())
    results = receipt.get("results", [])
    if len(results) != 1 or results[0]["status"] != "failed":
        raise RuntimeError("continuation receipt is not the one-record failed baseline")
    result = results[0]
    if result["evaluation_design"]["semantic_phase"]["target_file"] != (
        fixture.expected["findings"][0]["file"]
    ):
        raise RuntimeError("continuation target differs from the frozen fixture")
    pipeline = result["pipeline"]
    if pipeline["terminal_run_id"] != plan["pipeline_run_id"]:
        raise RuntimeError("continuation pipeline id differs from the frozen receipt")
    if pipeline["aggregate_usage"] != plan["aggregate_usage"]:
        raise RuntimeError("continuation usage differs from the frozen receipt")

    run = db.get_pipeline_run(plan["pipeline_run_id"], config)
    if (
        run is None
        or run.status is not RunStatus.FAILED
        or run.failed_stage != "detect"
    ):
        raise RuntimeError("continuation database lacks the expected failed detect run")
    repo_id = run.repo_id
    commit = run.commit_hash
    if not repo_id or not commit:
        raise RuntimeError("continuation run lacks repository identity")
    regions = db.list_detection_regions(repo_id, commit, config)
    production_complete = [
        item for item in regions
        if item.selection_basis != TARGET_CONDITIONING_BASIS
        and item.status is RunStatus.COMPLETED
    ]
    target_complete = [
        item for item in regions
        if item.selection_basis == TARGET_CONDITIONING_BASIS
        and item.lens == "owasp"
        and item.status is RunStatus.COMPLETED
    ]
    if len(production_complete) != plan["completed_production_region_calls"]:
        raise RuntimeError("continuation production-screen checkpoint count differs")
    if len(target_complete) != 1:
        raise RuntimeError("continuation lacks one completed target OWASP checkpoint")
    findings = db.list_findings(repo_id, config)
    target_findings = [
        finding for finding in findings
        if finding.file == fixture.expected["findings"][0]["file"]
    ]
    if len(target_findings) != 1:
        raise RuntimeError("continuation lacks exactly one retained target finding")
    return repo_id, commit, result["evaluation_design"]


def _continue_retained_prefix(
    fixture,
    config,
    receipt_path: Path,
    target_file: str,
) -> tuple[str, dict, dict]:
    """Continue only target falsification from the frozen failed pre-fix baseline."""
    repo_id, commit, observation = _validate_continuation(
        fixture, config, receipt_path
    )
    snapshot = config.raw_dir / repo_id / commit
    if snapshot.exists():
        raise RuntimeError(f"continuation raw snapshot already exists: {snapshot}")
    if _snapshot_content_digest(fixture.snapshot_path) != commit:
        raise RuntimeError("materialized continuation snapshot differs from retained commit")
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(fixture.snapshot_path, snapshot)

    scoped = _target_scoped_challenge(target_file, {commit: observation})
    _outcomes, semantic_run = _metered_phase(
        str(fixture.snapshot_path), repo_id, commit,
        "evaluation-target-falsify-continuation",
        lambda: scoped(repo_id, config),
        config,
        parent_run_id=json.loads(AIOHTTP_PLAN.read_text())[
            "continuation"
        ]["pipeline_run_id"],
    )
    design = _validated_evaluation_design(observation)
    phases = {
        "retained_failed_baseline": {
            "workflow_run_id": json.loads(AIOHTTP_PLAN.read_text())[
                "continuation"
            ]["workflow_run_id"],
            "pipeline_run_id": json.loads(AIOHTTP_PLAN.read_text())[
                "continuation"
            ]["pipeline_run_id"],
            "usage": json.loads(AIOHTTP_PLAN.read_text())[
                "continuation"
            ]["aggregate_usage"],
            "reused_checkpoints": {
                "production_region_calls": 18,
                "target_owasp_calls": 1,
            },
        },
        "target_falsify_continuation": _phase_evidence(
            semantic_run.id, config
        ),
    }
    return repo_id, design, phases


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

    assert plan["status"] == "partial_failed_budget_isolation"
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
    assert plan["continuation"]["workflow_run_id"] == 30383181253
    assert plan["continuation"]["completed_production_region_calls"] == 18
    assert plan["continuation"]["aggregate_usage"]["calls"] == 22


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


def test_root_failure_detail_unwraps_cli_style_cause():
    try:
        try:
            raise RuntimeError("provider token ceiling reached")
        except RuntimeError as cause:
            raise ValueError("Exit: ") from cause
    except ValueError as exc:
        assert _root_failure_detail(exc) == (
            "RuntimeError: provider token ceiling reached"
        )


def test_owasp_target_scope_restores_ensemble_globals():
    original_plan = ensemble.plan_detection_regions
    original_lenses = ensemble.LENSES
    original_prompts = ensemble._LENS_PROMPTS
    original_versions = ensemble.LENS_PROMPT_VERSIONS

    with _owasp_target_scope("target.py"):
        assert set(ensemble.LENSES) == {"owasp"}
        assert set(ensemble._LENS_PROMPTS) == {"owasp"}
        assert set(ensemble.LENS_PROMPT_VERSIONS) == {"owasp"}
        assert ensemble.plan_detection_regions is not original_plan

    assert ensemble.plan_detection_regions is original_plan
    assert ensemble.LENSES is original_lenses
    assert ensemble._LENS_PROMPTS is original_prompts
    assert ensemble.LENS_PROMPT_VERSIONS is original_versions


def test_metered_phases_receive_independent_pipeline_runs(tmp_config):
    db.init_db(tmp_config)

    first_value, first = _metered_phase(
        "source", "repo", "commit", "production-screen",
        lambda: "first", tmp_config,
    )
    second_value, second = _metered_phase(
        "source", "repo", "commit", "target-owasp",
        lambda: "second", tmp_config, parent_run_id=first.id,
    )

    assert (first_value, second_value) == ("first", "second")
    assert first.id != second.id
    assert db.get_pipeline_run(second.id, tmp_config).parent_run_id == first.id
    assert _phase_evidence(first.id, tmp_config)["status"] == "completed"
    assert _phase_evidence(second.id, tmp_config)["status"] == "completed"


def test_continuation_rejects_results_digest_before_reuse(
    tmp_config, tmp_path,
):
    tmp_config.paths.db_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_config.paths.db_path.write_bytes(b"wrong database")
    receipt = tmp_path / "results.json"
    receipt.write_text("{}")
    fixture = SimpleNamespace(expected={"findings": [{
        "file": "aiohttp/web_urldispatcher.py"
    }]})

    with pytest.raises(RuntimeError, match="results digest"):
        _validate_continuation(fixture, tmp_config, receipt)


@pytest.mark.live
def test_cve_positive_live_pair(tmp_config):
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
    tmp_config = tmp_config.model_copy(update={
        "paths": tmp_config.paths.model_copy(update={
            "data_dir": data_dir,
            "raw_dir": data_dir / "raw",
            "db_path": data_dir / "repoauditor.db",
        }),
    })
    target_file = pair[0].expected["findings"][0]["file"]
    artifact = Path(os.environ.get(
        "REPOAUDITOR_UAT_RESULTS", "live-cve-positive-results.json"
    ))
    continuation_receipt_raw = os.environ.get(
        "REPOAUDITOR_CVE_CONTINUATION_RESULTS", ""
    ).strip()
    continuation_receipt = (
        Path(continuation_receipt_raw).resolve()
        if continuation_receipt_raw else None
    )
    if continuation_receipt is not None:
        if slug != "aiohttp_cve_2024_23334":
            raise RuntimeError("continuation is frozen to aiohttp_cve_2024_23334")
        if not continuation_receipt.is_file() or not tmp_config.db_path.is_file():
            raise RuntimeError("continuation requires the retained results JSON and database")
    else:
        db.init_db(tmp_config)

    for index, fixture in enumerate(pair):
        repo_id: str | None = None
        selection_evidence: dict | None = None
        phase_evidence: dict | None = None
        try:
            if index == 0 and continuation_receipt is not None:
                repo_id, selection_evidence, phase_evidence = (
                    _continue_retained_prefix(
                        fixture, tmp_config, continuation_receipt, target_file
                    )
                )
            else:
                repo_id, selection_evidence, phase_evidence = (
                    _run_fresh_split_fixture(fixture, tmp_config, target_file)
                )
            score = score_independent_target(
                db.list_findings(repo_id, tmp_config), fixture.expected
            )
        except BaseException as exc:
            if repo_id is None:
                if index == 0 and continuation_receipt is not None:
                    retained = db.get_pipeline_run(
                        json.loads(AIOHTTP_PLAN.read_text())[
                            "continuation"
                        ]["pipeline_run_id"],
                        tmp_config,
                    )
                    repo_id = (
                        retained.repo_id
                        if retained is not None and retained.repo_id
                        else fixture.repo_id
                    )
                else:
                    matches = [
                        item for item in db.list_ingested_repos(tmp_config)
                        if Path(item.source).resolve()
                        == fixture.snapshot_path.resolve()
                    ]
                    repo_id = matches[-1].repo_id if matches else fixture.repo_id
            if phase_evidence is None:
                phase_evidence = _available_phase_evidence(repo_id, tmp_config)
            _append_live_uat_result(
                artifact,
                fixture,
                tmp_config,
                status="failed",
                pipeline={"phases": phase_evidence} if phase_evidence else None,
                failure_detail=_root_failure_detail(exc),
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
            pipeline={"phases": phase_evidence},
            evaluation_design=selection_evidence,
        )
