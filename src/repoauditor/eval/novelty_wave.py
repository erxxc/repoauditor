"""Bounded prospective OWASP-only collection for OPT-009 wave one.

This helper deliberately stops after ingest, architecture recovery, deterministic
scanning, OWASP detection, and aggregate capacity measurement. It does not run the
pipeline's triage, falsification, normalization, review, or scoring stages.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ..analyze.provider_cost import calculate_provider_cost
from ..config import Config, REPO_ROOT, get_config
from ..detect import ensemble
from ..detect.deterministic.execution import ScannerExecution
from ..detect.retrieval import RetrievalIndex
from ..ingest import ingest_repo
from ..llm import model_usage_scope
from ..map import load_architecture, recover_architecture
from ..map.schema import ArchitectureMap, DataStore, Integration
from ..matching import find_matches
from ..presentation import architecture_ascii
from ..store import db
from ..store.models import Finding, RunStatus
from ..triage.acquisition_funnel import (
    ReviewPathTier,
    classify_review_path,
    review_path_tier,
)


POLICY = "opt009-prospective-owasp-capacity-v1"
RECEIPT = (
    REPO_ROOT
    / "docs/optimizations/opt-009-prospective-detection-wave-1-receipt-2026-08-12.json"
)
CORRECTED_RETRY_RECEIPT = (
    REPO_ROOT
    / "docs/optimizations/opt-009-prospective-detection-wave-1-serialization-retry-receipt-2026-08-13.json"
)
STOPPED_RESULT = (
    REPO_ROOT
    / "docs/optimizations/opt-009-prospective-detection-wave-1-result-2026-08-13.json"
)
STOPPED_STORE_SHA256 = "e3cb8e9b129dd92f357cb937d5a5775f442b29f50aac40e19f94e667053315b7"
STOPPED_PROVIDER_ATTEMPTS = 5
STOPPED_KNOWN_PROVIDER_TOKENS = 99_846
STOPPED_KNOWN_PROVIDER_COST_USD = 0.546170
ALLOWED_MUTATION_TABLES = frozenset({
    "ingested_repo",
    "pipeline_run",
    "stage_run",
    "trust_boundary",
    "entity",
    "finding",
    "detection_region_run",
    "validation_failure",
    "corroboration",
    "model_usage",
})
SOURCES = (
    {
        "repo_id": "opt009-wave1-vikunja",
        "repository": "go-vikunja/vikunja",
        "family": "independent-upstream:go-vikunja/vikunja",
        "url": "https://github.com/go-vikunja/vikunja.git",
        "commit": "9403ed15264e414605c523b0c16ef28703e9915e",
    },
    {
        "repo_id": "opt009-wave1-miniflux",
        "repository": "miniflux/v2",
        "family": "independent-upstream:miniflux/v2",
        "url": "https://github.com/miniflux/v2.git",
        "commit": "106cdd09e1557222303f3ed1376e1dadf0638621",
    },
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_digest(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    files = 0
    size = 0
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        payload = path.read_bytes()
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
        files += 1
        size += len(payload)
    return digest.hexdigest(), files, size


def _table_counts(config: Config) -> dict[str, int]:
    conn = sqlite3.connect(config.db_path)
    try:
        tables = [
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        return {
            table: int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in tables
        }
    finally:
        conn.close()


def _json_safe(value):
    """Convert stage evidence recursively before SQLite JSON persistence."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


@contextmanager
def owasp_only_scope():
    """Temporarily narrow the production ensemble to its frozen OWASP identity."""
    original_lenses = ensemble.LENSES
    original_prompts = ensemble._LENS_PROMPTS
    original_versions = ensemble.LENS_PROMPT_VERSIONS
    ensemble.LENSES = {"owasp": original_lenses["owasp"]}
    ensemble._LENS_PROMPTS = {"owasp": original_prompts["owasp"]}
    ensemble.LENS_PROMPT_VERSIONS = {"owasp": original_versions["owasp"]}
    try:
        yield
    finally:
        ensemble.LENSES = original_lenses
        ensemble._LENS_PROMPTS = original_prompts
        ensemble.LENS_PROMPT_VERSIONS = original_versions


def _assert_scanner_health(executions: list[dict]) -> None:
    expected = {"semgrep", "semgrep-supplemental", "pip-audit", "osv-scanner", "gitleaks"}
    records = [ScannerExecution.model_validate(item) for item in executions]
    if {item.scanner for item in records} != expected:
        raise RuntimeError("deterministic scanner execution inventory is incomplete")
    bad = [item.scanner for item in records if item.status not in {
        "complete", "empty", "not-applicable"
    }]
    if bad:
        raise RuntimeError("deterministic scanner coverage is not healthy: " + ", ".join(bad))


def _eligible_group_count(findings: list[Finding]) -> tuple[int, int]:
    eligible = [
        finding
        for finding in findings
        if finding.source_lens == "owasp"
        and review_path_tier(classify_review_path(finding.file)) is ReviewPathTier.PRIMARY
    ]
    return len(eligible), len(find_matches(eligible).groups)


def _known_tokens(usage: dict[str, int]) -> int:
    return sum(usage[key] for key in (
        "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens"
    ))


def _load_completed_architecture(
    repo_id: str, commit: str, config: Config
) -> ArchitectureMap:
    """Reload all planning entity classes without changing the frozen map module."""
    from ..store.models import EntityKind

    base = load_architecture(repo_id, commit, config)
    entities = db.list_entities(repo_id, config)
    return base.model_copy(update={
        "data_stores": [
            DataStore(name=item.name, location=item.location)
            for item in entities
            if item.kind is EntityKind.DATA_STORE
        ],
        "integrations": [
            Integration(name=item.name, location=item.location)
            for item in entities
            if item.kind is EntityKind.INTEGRATION
        ],
    })


def _assert_resume_plan(
    repo_id: str,
    commit: str,
    snapshot_path: Path,
    architecture,
    deterministic,
    index: RetrievalIndex,
    config: Config,
) -> None:
    """Require the corrected planner to preserve every attempted region identity."""
    planned = ensemble.plan_detection_regions(
        snapshot_path,
        config,
        commit=commit,
        architecture=architecture,
        tool_candidates=deterministic.candidates,
        index=index,
    )
    prior = db.list_detection_regions(repo_id, commit, config)
    if len(prior) != 4:
        raise RuntimeError("the stopped Vikunja region chronology drifted")
    if [item.relative_path for item in planned[:4]] != [item.file for item in prior]:
        raise RuntimeError("the corrected Vikunja region plan drifted")
    if [item.status for item in prior] != [
        RunStatus.COMPLETED,
        RunStatus.COMPLETED,
        RunStatus.COMPLETED,
        RunStatus.FAILED,
    ]:
        raise RuntimeError("the stopped Vikunja region statuses drifted")
    if any(
        item.lens != "owasp"
        or item.prompt_version != ensemble.LENS_PROMPT_VERSIONS["owasp"]
        for item in prior
    ):
        raise RuntimeError("the stopped Vikunja OWASP identity drifted")


def _stage(
    pipeline_id: int,
    name: str,
    function,
    config: Config,
    *,
    summary,
    artifacts,
):
    db.start_stage_run(pipeline_id, name, config)
    try:
        with model_usage_scope(pipeline_id):
            value = function()
        details = _json_safe(summary(value))
        details["model_usage"] = db.summarize_model_usage(
            pipeline_id, config, stage=name
        )
        paths = artifacts(value)
        db.finish_stage_run(
            pipeline_id,
            name,
            RunStatus.COMPLETED,
            summary=details,
            artifacts=paths,
            config=config,
        )
        return value
    except BaseException as exc:
        detail = f"{type(exc).__name__}: {exc}"[:4000]
        db.finish_stage_run(
            pipeline_id,
            name,
            RunStatus.FAILED,
            failure_detail=detail,
            config=config,
        )
        db.finish_pipeline_run(
            pipeline_id,
            RunStatus.FAILED,
            failed_stage=name,
            failure_detail=detail,
            config=config,
        )
        raise


def _assert_corrected_retry_state(config: Config) -> None:
    if not STOPPED_RESULT.is_file():
        raise RuntimeError("the stopped wave-one result is absent")
    if _sha256(config.db_path) != STOPPED_STORE_SHA256:
        raise RuntimeError("the stopped wave-one store identity drifted")
    prior = db.get_pipeline_run(114, config)
    if (
        prior is None
        or prior.repo_id != SOURCES[0]["repo_id"]
        or prior.commit_hash != SOURCES[0]["commit"][:12]
        or prior.status is not RunStatus.FAILED
        or prior.failed_stage != "detect"
    ):
        raise RuntimeError("the stopped Vikunja pipeline identity drifted")
    if db.list_triage_assessments(SOURCES[0]["repo_id"], config):
        raise RuntimeError("the stopped Vikunja source acquired assessment outcomes")
    serialization_attempt = db.get_pipeline_run(115, config)
    if (
        serialization_attempt is None
        or serialization_attempt.repo_id != SOURCES[0]["repo_id"]
        or serialization_attempt.commit_hash != SOURCES[0]["commit"][:12]
        or serialization_attempt.status is not RunStatus.FAILED
        or serialization_attempt.failed_stage != "scan"
        or db.summarize_model_usage(115, config)["calls"] != 0
    ):
        raise RuntimeError("the stopped scanner-summary pipeline identity drifted")
    if any(
        row.repo_id == SOURCES[1]["repo_id"]
        for row in db.list_ingested_repos(config)
    ):
        raise RuntimeError("Miniflux was materialized before corrected retry authorization")


def run_wave(
    config: Config | None = None,
    *,
    corrected_retry: bool = False,
    artifact_directory: Path | None = None,
) -> dict:
    """Execute the two frozen sources and return identity-free aggregate evidence."""
    config = config or get_config()
    if config.llm.provider != "anthropic" or config.model.name != "claude-opus-4-8":
        raise RuntimeError("provider/model identity drifted")
    if config.detect.max_llm_regions_per_run != 6:
        raise RuntimeError("the frozen six-region cap drifted")
    if config.llm.max_calls_per_pipeline_run != 75:
        raise RuntimeError("the frozen per-pipeline call ceiling drifted")
    if config.llm.max_tokens_per_pipeline_run != 250_000:
        raise RuntimeError("the frozen per-pipeline token ceiling drifted")
    active_receipt = CORRECTED_RETRY_RECEIPT if corrected_retry else RECEIPT
    if not active_receipt.is_file():
        raise RuntimeError("OPT-009 wave-one receipt is absent")

    db.init_db(config)
    if corrected_retry:
        _assert_corrected_retry_state(config)
    artifact_directory = artifact_directory or (
        config.resolve(config.paths.data_dir) / "artifacts" / "opt009-wave-1"
    )
    before = _table_counts(config)
    assessment_before = before.get("triage_assessment", 0)
    label_before = before.get("triage_label", 0)
    started = time.monotonic()
    repositories: list[dict] = []
    pipeline_ids: list[int] = []
    aggregate_cost = 0.0
    aggregate_calls = 0
    aggregate_tokens = 0

    for source in SOURCES:
        source_config = config
        if corrected_retry and source["repo_id"] == SOURCES[0]["repo_id"]:
            source_config = config.model_copy(update={
                "llm": config.llm.model_copy(update={
                    "max_calls_per_pipeline_run": 75 - STOPPED_PROVIDER_ATTEMPTS,
                    "max_tokens_per_pipeline_run": (
                        250_000 - STOPPED_KNOWN_PROVIDER_TOKENS
                    ),
                })
            })
        repo_started = time.monotonic()
        if corrected_retry and source["repo_id"] == SOURCES[0]["repo_id"]:
            pipeline = db.get_pipeline_run(115, source_config)
            if pipeline is None or pipeline.id is None:
                raise RuntimeError("stopped scanner-summary pipeline is absent")
            db.resume_pipeline_run(pipeline.id, source_config)
        else:
            pipeline = db.start_pipeline_run(source["url"], source_config)
        if pipeline.id is None:
            raise RuntimeError("pipeline run did not receive an id")
        pipeline_ids.append(pipeline.id)
        artifacts: list[str] = []

        ingested = _stage(
            pipeline.id,
            "ingest",
            lambda source=source: ingest_repo(
                source["url"],
                source_config,
                repo_id=source["repo_id"],
                expected_commit=source["commit"],
            ),
            source_config,
            summary=lambda value: {
                "repo_id": value.repo_id,
                "commit_hash": value.commit,
                "exact_commit_verified": value.commit == source["commit"][:12],
            },
            artifacts=lambda value: [str(value.snapshot_path)],
        )
        if ingested.commit != source["commit"][:12]:
            raise RuntimeError("materialized source commit drifted")
        db.update_pipeline_run_identity(
            pipeline.id, source["repo_id"], ingested.commit, source_config
        )
        tree_sha256, source_files, source_bytes = _tree_digest(ingested.snapshot_path)
        artifacts.append(str(ingested.snapshot_path))

        map_path = (
            artifact_directory
            / source["repo_id"]
            / f"architecture-{ingested.commit}.txt"
        )

        reuse_completed_map = (
            corrected_retry and source["repo_id"] == SOURCES[0]["repo_id"]
        )

        def map_source():
            architecture = (
                _load_completed_architecture(
                    source["repo_id"], ingested.commit, source_config
                )
                if reuse_completed_map
                else recover_architecture(
                    ingested.snapshot_path,
                    source["repo_id"],
                    ingested.commit,
                    source_config,
                )
            )
            map_path.parent.mkdir(parents=True, exist_ok=True)
            map_path.write_text(architecture_ascii(architecture), encoding="utf-8")
            return architecture

        architecture = _stage(
            pipeline.id,
            "map",
            map_source,
            source_config,
            summary=lambda value: {
                "entry_points": len(value.entry_points),
                "trust_boundaries": len(value.trust_boundaries),
                "data_stores": len(value.data_stores),
                "integrations": len(value.integrations),
                "provider": config.llm.provider,
                "model": config.model.name,
                "prompt_version": "architecture_recovery_v2",
                "reused_completed_map": reuse_completed_map,
            },
            artifacts=lambda _value: [str(map_path)],
        )
        artifacts.append(str(map_path))

        def scan_source():
            deterministic = ensemble.run_deterministic_detection(
                source["repo_id"],
                source_config,
                artifact_path=(
                    artifact_directory
                    / source["repo_id"]
                    / "scanners"
                    / "semgrep.sarif"
                ),
            )
            _assert_scanner_health(deterministic.scanner_executions)
            return deterministic

        deterministic = _stage(
            pipeline.id,
            "scan",
            scan_source,
            source_config,
            summary=lambda value: {
                "scanner_statuses": value.scanner_statuses,
                "scanner_failures": value.scanner_failures,
                "scanner_executions": value.scanner_executions,
                "finding_count": len(value.findings),
            },
            artifacts=lambda value: [str(value.sarif_path)] if value.sarif_path else [],
        )
        if deterministic.sarif_path:
            artifacts.append(str(deterministic.sarif_path))

        retrieval_index = RetrievalIndex().build(ingested.snapshot_path)
        if reuse_completed_map:
            _assert_resume_plan(
                source["repo_id"],
                ingested.commit,
                ingested.snapshot_path,
                architecture,
                deterministic,
                retrieval_index,
                source_config,
            )

        def detect_source():
            with owasp_only_scope():
                return ensemble.run_ensemble(
                    source["repo_id"],
                    source_config,
                    index=retrieval_index,
                    deterministic=deterministic,
                )

        detection = _stage(
            pipeline.id,
            "detect",
            detect_source,
            source_config,
            summary=lambda value: {
                "active_lenses": ["owasp"],
                "selected_region_count": len(value.selected_regions),
                "completed_region_calls": value.completed_region_calls,
                "reused_completed_region_calls": value.skipped_completed_region_calls,
                "source_counts": value.source_counts,
                "scanner_statuses": value.scanner_statuses,
                "scanner_failures": value.scanner_failures,
                "scanner_executions": value.scanner_executions,
                "provider": config.llm.provider,
                "model": config.model.name,
                "prompt_version": ensemble.LENS_PROMPT_VERSIONS["owasp"],
                "context_expansions": value.context_expansions,
            },
            artifacts=lambda value: [str(value.sarif_path)] if value.sarif_path else [],
        )
        if len(detection.selected_regions) > 6:
            raise RuntimeError("detection exceeded the frozen region ceiling")

        findings = db.list_findings(source["repo_id"], source_config)
        eligible_records, eligible_groups = _eligible_group_count(findings)
        if db.list_triage_assessments(source["repo_id"], source_config):
            raise RuntimeError("prospective source unexpectedly has assessment outcomes")

        usage = db.summarize_model_usage(pipeline.id, source_config)
        rows = db.list_model_usage(source_config, pipeline_run_id=pipeline.id)
        cost = calculate_provider_cost(rows)
        if usage["unknown_usage_calls"] or cost.status != "priced" or cost.usd is None:
            raise RuntimeError("pipeline lacks authoritative priced provider usage")
        known_tokens = _known_tokens(usage)
        if (
            usage["calls"] > source_config.llm.max_calls_per_pipeline_run
            or known_tokens > source_config.llm.max_tokens_per_pipeline_run
        ):
            raise RuntimeError("per-repository provider ceiling exceeded")
        elapsed = time.monotonic() - repo_started
        if elapsed > 180 * 60:
            raise RuntimeError("per-repository elapsed-time ceiling exceeded")

        aggregate_calls += usage["calls"]
        aggregate_tokens += known_tokens
        aggregate_cost += float(cost.usd)
        repositories.append({
            "repository": source["repository"],
            "evaluation_family": source["family"],
            "repo_id": source["repo_id"],
            "exact_commit": source["commit"],
            "stored_commit": ingested.commit,
            "snapshot_tree_sha256": tree_sha256,
            "snapshot_file_count": source_files,
            "snapshot_bytes": source_bytes,
            "pipeline_run_id": pipeline.id,
            "architecture_counts": {
                "entry_points": len(architecture.entry_points),
                "trust_boundaries": len(architecture.trust_boundaries),
                "data_stores": len(architecture.data_stores),
                "integrations": len(architecture.integrations),
            },
            "selected_region_count": len(detection.selected_regions),
            "completed_region_calls": detection.completed_region_calls,
            "reused_completed_region_calls": detection.skipped_completed_region_calls,
            "resume_plan_verified": reuse_completed_map,
            "evidence_bound": {
                "policy": ensemble.DETECTION_EVIDENCE_BOUND_VERSION,
                "maximum_region_bytes": ensemble.DETECTION_REGION_MAX_BYTES,
                "maximum_observed_region_bytes": max(
                    (
                        int(item["evidence_bound"]["region_sent_bytes"])
                        for item in detection.context_expansions
                    ),
                    default=0,
                ),
                "truncated_primary_regions": sum(
                    bool(item["evidence_bound"]["primary_truncated"])
                    for item in detection.context_expansions
                ),
                "truncated_retrieval_regions": sum(
                    bool(item["evidence_bound"]["retrieval_truncated"])
                    for item in detection.context_expansions
                ),
            },
            "scanner_statuses": dict(sorted(detection.scanner_statuses.items())),
            "eligible_owasp_records": eligible_records,
            "eligible_owasp_issue_groups": eligible_groups,
            "capacity_requirement": 8,
            "capacity_satisfied": eligible_groups >= 8,
            "provider_usage": usage,
            "provider_reported_tokens": known_tokens,
            "provider_cost_usd": float(cost.usd),
            "elapsed_seconds": round(elapsed, 3),
        })
        db.finish_pipeline_run(
            pipeline.id,
            RunStatus.COMPLETED,
            artifacts=artifacts,
            config=source_config,
        )

        aggregate_call_limit = 150 - (STOPPED_PROVIDER_ATTEMPTS if corrected_retry else 0)
        aggregate_token_limit = 500_000 - (
            STOPPED_KNOWN_PROVIDER_TOKENS if corrected_retry else 0
        )
        aggregate_cost_limit = 12.5 - (
            STOPPED_KNOWN_PROVIDER_COST_USD if corrected_retry else 0.0
        )
        if (
            aggregate_calls > aggregate_call_limit
            or aggregate_tokens > aggregate_token_limit
            or aggregate_cost > aggregate_cost_limit
        ):
            raise RuntimeError("aggregate provider ceiling exceeded")
        if time.monotonic() - started > 420 * 60:
            raise RuntimeError("aggregate elapsed-time ceiling exceeded")

    after = _table_counts(config)
    changed_tables = sorted(
        table for table in set(before) | set(after)
        if before.get(table, 0) != after.get(table, 0)
    )
    unexpected = sorted(set(changed_tables) - ALLOWED_MUTATION_TABLES)
    if unexpected:
        raise RuntimeError("unlisted store tables changed: " + ", ".join(unexpected))
    if after.get("triage_assessment", 0) != assessment_before:
        raise RuntimeError("assessment count changed")
    if after.get("triage_label", 0) != label_before:
        raise RuntimeError("classifier-label count changed")

    total_elapsed = time.monotonic() - started
    return {
        "schema_version": 1,
        "optimization": "OPT-009",
        "policy": POLICY,
        "status": (
            "complete-capacity-satisfied"
            if all(item["capacity_satisfied"] for item in repositories)
            else "complete-capacity-shortfall"
        ),
        "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "receipt": {
            "path": str(active_receipt.relative_to(REPO_ROOT)),
            "sha256": _sha256(active_receipt),
        },
        "corrected_retry": corrected_retry,
        "repositories": repositories,
        "aggregate": {
            "repositories_materialized": len(repositories),
            "pipeline_runs": len(pipeline_ids),
            "provider_calls": aggregate_calls,
            "provider_reported_tokens": aggregate_tokens,
            "provider_cost_usd": round(aggregate_cost, 6),
            "historical_provider_attempts": (
                STOPPED_PROVIDER_ATTEMPTS if corrected_retry else 0
            ),
            "historical_known_provider_reported_tokens": (
                STOPPED_KNOWN_PROVIDER_TOKENS if corrected_retry else 0
            ),
            "historical_known_provider_cost_usd": (
                STOPPED_KNOWN_PROVIDER_COST_USD if corrected_retry else 0.0
            ),
            "combined_provider_attempts": aggregate_calls + (
                STOPPED_PROVIDER_ATTEMPTS if corrected_retry else 0
            ),
            "combined_known_provider_reported_tokens": aggregate_tokens + (
                STOPPED_KNOWN_PROVIDER_TOKENS if corrected_retry else 0
            ),
            "combined_known_provider_cost_usd": round(
                aggregate_cost
                + (STOPPED_KNOWN_PROVIDER_COST_USD if corrected_retry else 0.0),
                6,
            ),
            "elapsed_seconds": round(total_elapsed, 3),
            "families_meeting_capacity": sum(
                item["capacity_satisfied"] for item in repositories
            ),
            "families_required": 2,
            "changed_store_tables": changed_tables,
        },
        "outcome_boundary": {
            "candidate_identities_disclosed": 0,
            "source_rendered_for_review": False,
            "human_reviews": 0,
            "assessments_added": 0,
            "labels_added": 0,
            "models_trained": 0,
            "novelty_scores_or_ranks": 0,
            "observational_lens_calls": 0,
            "falsification_calls": 0,
            "normalization_calls": 0,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--corrected-retry", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"refusing to overwrite {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result = run_wave(
        corrected_retry=args.corrected_retry,
        artifact_directory=args.output.parent,
    )
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "status": result["status"],
        "repositories_materialized": result["aggregate"]["repositories_materialized"],
        "families_meeting_capacity": result["aggregate"]["families_meeting_capacity"],
        "provider_calls": result["aggregate"]["provider_calls"],
        "provider_reported_tokens": result["aggregate"]["provider_reported_tokens"],
        "provider_cost_usd": result["aggregate"]["provider_cost_usd"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
