"""Thin CLI. Parses arguments and calls library functions — zero business logic.

This boundary is architectural (see CLAUDE.md): commands here only marshal arguments
and print results. All real work lives in the stage packages. Stages that are still
stubbed raise `NotImplementedError`, which is surfaced here as a clean message rather
than a traceback.
"""

from __future__ import annotations

import getpass
import io
import json
import sys
import threading
import time
from contextlib import contextmanager, redirect_stdout
from contextvars import ContextVar
from datetime import datetime
from enum import StrEnum
from functools import wraps
from types import SimpleNamespace

import typer

from pathlib import Path

from . import __version__
from .analyze import (
    audit_quantitative_inputs,
    quantitative_disclosure,
    quantify_appendix,
    render_quant_audit,
)
from .config import get_config
from .detect import (
    DetectionRun,
    project_detection_work,
    run_ensemble,
    validate_detection_projection,
)
from .detect.ensemble import CITATION_INTEGRITY_VERSION, LENS_PROMPT_VERSIONS
from .eval import (
    build_usage_calibration,
    evaluate_archive_detection_sentinels,
    evaluate_finding_convergence,
    evaluate_manufactured_sentinels,
    evaluate_xml_detection_sentinels,
    render_convergence,
    render_detection_qualification,
    render_sentinel_qualification,
    render_usage_calibration,
    render_xml_detection_qualification,
)
from .falsify import challenge
from .falsify.challenger import (
    CONTEXT_VERSION as FALSIFY_CONTEXT_VERSION,
    CRITIQUE_PROMPT_VERSION,
    PROMPT_VERSION as FALSIFY_PROMPT_VERSION,
)
from .ingest import ingest_repo, snapshot_manifests
from .ingest import latest_snapshot
from .interactive import load_menu_state, render_main_menu
from .llm import model_usage_scope
from .map import recover_architecture
from .map.domain_map import PROMPT_VERSION as MAP_PROMPT_VERSION
from .normalize import adjudicate_repo
from .normalize.adjudicate import PROMPT_VERSION as NORMALIZE_PROMPT_VERSION
from .observability import (
    detection_metrics,
    falsification_metrics,
    normalization_metrics,
)
from .preflight import PreflightResult, check_model, check_runtime
from .presentation import (
    architecture_artifact_path,
    architecture_ascii,
    ndjson_event,
    repos_json,
    repos_table,
    review_requests_json,
)
from .report import write_backlog, write_memo
from .review import (
    decide,
    open_review_requests,
    raise_review_requests,
    render_open_requests,
)
from .store import db
from .store.models import (
    ReviewDisposition,
    RunStatus,
    TriageDisposition,
)
from .triage import (
    assess_finding,
    collection_status,
    render_collection_status,
    render_threshold_stats,
    threshold_stats,
    triage_repo,
)
from .uat import score_demo

app = typer.Typer(
    help=(
        "Audit a codebase with a two-phase workflow: `run` through the review "
        "checkpoint, resolve any `review` requests, then `finalize` both reports. "
        "Run with no command in an interactive terminal to open the numbered menu. "
        "Individual pipeline stages remain available for advanced/manual use."
    ),
    no_args_is_help=False,
    add_completion=False,
)
db_app = typer.Typer(help="Database commands.", no_args_is_help=True)
app.add_typer(db_app, name="db")
review_app = typer.Typer(help="Human-review checkpoint commands.", no_args_is_help=True)
app.add_typer(review_app, name="review")
repos_app = typer.Typer(help="Ingested repository commands.", no_args_is_help=True)
app.add_typer(repos_app, name="repos")
runs_app = typer.Typer(help="Pipeline run history and failure diagnostics.", no_args_is_help=True)
app.add_typer(runs_app, name="runs")


class ReportMode(StrEnum):
    ENGINEERING = "engineering"
    MEMO = "memo"


class LabelDisposition(StrEnum):
    """Detailed analyst ground truth plus legacy binary aliases."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"
    CONFIRMED_ACTIONABLE = "confirmed_actionable"
    TOOL_INCORRECT = "tool_incorrect"
    UNREACHABLE = "unreachable"
    NOT_ATTACKER_CONTROLLED = "not_attacker_controlled"
    MITIGATED = "mitigated"
    DUPLICATE = "duplicate"
    VALID_NOT_ACTIONABLE = "valid_not_actionable"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ListFormat(StrEnum):
    HUMAN = "human"
    JSON = "json"


class RunFormat(StrEnum):
    HUMAN = "human"
    NDJSON = "ndjson"


_DEMO_REPO_ID = "uat_lightweight_app"


_debug_enabled: ContextVar[bool] = ContextVar("repoauditor_debug", default=False)
_quiet_enabled: ContextVar[bool] = ContextVar("repoauditor_quiet", default=False)
_verbose_enabled: ContextVar[bool] = ContextVar("repoauditor_verbose", default=False)


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(seconds, 60)
    return f"{int(minutes)}m {remainder:.1f}s"


def _stored_elapsed(started_at: str | None, completed_at: str | None) -> str:
    if not started_at or not completed_at:
        return "-"
    try:
        return _elapsed(
            (datetime.fromisoformat(completed_at) - datetime.fromisoformat(started_at))
            .total_seconds()
        )
    except ValueError:
        return "unavailable"


@contextmanager
def _stage_timing(label: str):
    timing = {"started_at": _timestamp(), "started": time.monotonic()}
    if not _quiet_enabled.get():
        typer.echo(f"[{timing['started_at']}] {label} started")
    yield timing
    timing["completed_at"] = _timestamp()
    timing["elapsed"] = time.monotonic() - timing["started"]


def _stage_summary(message: str, timing: dict) -> None:
    if not _quiet_enabled.get():
        typer.echo(f"[{timing['completed_at']}] {message} (elapsed {_elapsed(timing['elapsed'])})")


def _verbose(message: str) -> None:
    if _verbose_enabled.get() and not _quiet_enabled.get():
        typer.echo(f"  {message}")


def _clean_errors(stage: str):
    """Give individual commands the same concise failure boundary as orchestrators."""
    def decorate(fn):
        @wraps(fn)
        def invoke(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except typer.Exit:
                raise
            except Exception as exc:
                if _debug_enabled.get():
                    raise
                typer.secho(
                    f"{stage} failed: {type(exc).__name__}: {exc}",
                    fg=typer.colors.RED,
                    err=True,
                )
                raise typer.Exit(code=1) from None
        return invoke
    return decorate


def _stub_guard(fn, *args, **kwargs):
    """Call a stage function, turning a stubbed NotImplementedError into a clean exit."""
    try:
        return fn(*args, **kwargs)
    except NotImplementedError as exc:
        typer.secho(f"not yet implemented: {exc}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=2)


@contextmanager
def _progress(label: str):
    """Render an indeterminate ASCII bar for a blocking stage call on interactive terminals."""
    stream = sys.stderr
    if _quiet_enabled.get() or not stream.isatty():
        yield
        return

    width = 24
    stopped = threading.Event()

    def animate() -> None:
        position = 0
        direction = 1
        pulse = "====>"
        while not stopped.is_set():
            cells = [" "] * width
            cells[position:position + len(pulse)] = pulse
            stream.write(f"\r{label:<10} [{''.join(cells)}]")
            stream.flush()
            position += direction
            if position <= 0 or position >= width - len(pulse):
                direction *= -1
            stopped.wait(0.12)

    worker = threading.Thread(target=animate, daemon=True)
    worker.start()
    try:
        yield
    except BaseException:
        stopped.set()
        worker.join()
        stream.write(f"\r{label:<10} [{'!' * width}] failed\n")
        stream.flush()
        raise
    else:
        stopped.set()
        worker.join()
        stream.write(f"\r{label:<10} [{'=' * width}] done\n")
        stream.flush()


def _run_step(
    stage: str,
    fn,
    *,
    pipeline_id: int | None = None,
    config=None,
    metadata=lambda value: ({}, []),
):
    """Run one orchestrated stage and turn its exception into an attributable CLI error."""
    if pipeline_id is not None:
        db.start_stage_run(pipeline_id, stage, config)
    try:
        value = fn()
        if pipeline_id is not None:
            summary, artifacts = metadata(value)
            usage = db.summarize_model_usage(pipeline_id, config, stage=stage)
            summary["model_usage"] = usage if usage["calls"] else "not recorded"
            db.finish_stage_run(
                pipeline_id,
                stage,
                RunStatus.COMPLETED,
                summary=summary,
                artifacts=artifacts,
                config=config,
            )
        return value
    except typer.Exit as exc:
        if pipeline_id is not None:
            db.finish_stage_run(
                pipeline_id,
                stage,
                RunStatus.FAILED,
                failure_detail=f"stage exited with code {exc.exit_code}",
                config=config,
            )
        typer.secho(
            f"pipeline failed at {stage}: stage exited with code {exc.exit_code}",
            fg=typer.colors.RED,
            err=True,
        )
        raise
    except Exception as exc:
        if pipeline_id is not None:
            db.finish_stage_run(
                pipeline_id,
                stage,
                RunStatus.FAILED,
                failure_detail=f"{type(exc).__name__}: {exc}"[:4000],
                config=config,
            )
        if _debug_enabled.get():
            raise
        typer.secho(
            f"pipeline failed at {stage}: {type(exc).__name__}: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1) from exc


def _ingest_run_metadata(value):
    return (
        {"repo_id": value.repo_id, "commit_hash": value.commit},
        [str(value.snapshot_path)],
    )


def _map_run_metadata(value, config):
    repo_id = getattr(value, "repo_id", None)
    commit = getattr(value, "commit", None)
    artifact = (
        architecture_artifact_path(config.paths.data_dir, repo_id, commit)
        if repo_id and commit
        else None
    )
    return (
        {
            "entry_points": len(getattr(value, "entry_points", []) or []),
            "trust_boundaries": len(getattr(value, "trust_boundaries", []) or []),
            "data_stores": len(getattr(value, "data_stores", []) or []),
            "integrations": len(getattr(value, "integrations", []) or []),
            "llm": {
                "provider": config.llm.provider,
                "model": config.model.name,
                "prompt_versions": {"map": MAP_PROMPT_VERSION},
            },
            "artifact": str(artifact) if artifact else None,
        },
        [str(artifact)] if artifact else [],
    )


def _detect_run_metadata(value, config, scanner_coverage=None):
    projection = getattr(value, "projection", None)
    source_counts = getattr(value, "source_counts", {}) or {}
    summary = {
        **detection_metrics(value, source_counts),
        "region_plan": ({
            "source_files": projection.source_files,
            "unbounded_base_calls": projection.unbounded_base_calls,
            "planned_regions": projection.planned_regions,
            "planned_base_calls": projection.planned_base_calls,
            "omitted_regions": projection.omitted_regions,
            "selected": value.selected_regions,
            "completed_calls": value.completed_region_calls,
            "reused_completed_calls": value.skipped_completed_region_calls,
        } if projection is not None else None),
        "semgrep_status": getattr(value, "semgrep_status", None),
        "scanner_statuses": getattr(value, "scanner_statuses", {}),
        "scanner_failures": getattr(value, "scanner_failures", {}),
        "llm": {
            "provider": config.llm.provider,
            "model": config.model.name,
            "prompt_versions": {
                **LENS_PROMPT_VERSIONS,
                "citation_integrity": CITATION_INTEGRITY_VERSION,
            },
        },
    }
    if scanner_coverage is not None:
        summary["scanner_coverage"] = scanner_coverage
    sarif_path = getattr(value, "sarif_path", None)
    return summary, [str(sarif_path)] if sarif_path else []


def _triage_run_metadata(value):
    return ({
        "real_labels": getattr(value, "n_real_labels", None),
        "ranked": len(getattr(value, "ranked", []) or []),
        "action_threshold": getattr(value, "action_threshold", None),
        "synthetic_share": getattr(value, "synthetic_share", None),
        "synthetic_dropped": getattr(value, "synthetic_dropped", None),
        "suppressed": getattr(value, "n_suppressed", None),
        "model": getattr(value, "model_name", None),
        "evaluations": [
            {
                "model": evaluation.model_name,
                "eval_on": evaluation.eval_on,
                "brier": evaluation.brier,
                "average_precision": evaluation.average_precision,
                "n_eval": evaluation.n_eval,
                "split_strategy": evaluation.split_strategy,
                "split_detail": evaluation.split_detail,
            }
            for evaluation in (getattr(value, "evaluations", None) or [])
        ],
    }, [])


def _falsify_run_metadata(value, config, *, backlog_before: int | None = None):
    summary = {
        **falsification_metrics(value, getattr(value, "deferred_count", 0)),
        "llm": {
            "provider": config.llm.provider,
            "model": config.model.name,
            "prompt_versions": {
                "falsify": FALSIFY_PROMPT_VERSION,
                "falsify_critique": CRITIQUE_PROMPT_VERSION,
                "falsify_context": FALSIFY_CONTEXT_VERSION,
            },
        },
    }
    if backlog_before is not None:
        summary["backlog_before"] = backlog_before
    return summary, []


def _normalize_run_metadata(value, config):
    return ({
        **normalization_metrics(value),
        "llm": {
            "provider": config.llm.provider,
            "model": config.model.name,
            "prompt_versions": {"normalize": NORMALIZE_PROMPT_VERSION},
        },
    }, [])


def _quantify_run_metadata(value, *, trials: int, seed: int, record_audit: bool):
    path, scenario_count = value
    return ({
        "scenario_count": scenario_count,
        "trials": trials,
        "seed": seed,
        "record_audit": record_audit,
    }, [str(path)])


def _report_run_metadata(value, *, mode: ReportMode):
    return ({
        "mode": mode.value,
        "output_paths": [str(path) for path in value],
    }, [str(path) for path in value])


def _metered_operation(
    source: str,
    stage: str,
    fn,
    config,
    *,
    repo_id: str | None = None,
    commit_hash: str | None = None,
    success=lambda value: True,
    failure_detail=lambda value: None,
    metadata=lambda value: ({}, []),
):
    """Run one standalone paid operation inside a durable, fresh usage budget."""
    db.init_db(config)
    pipeline = db.start_pipeline_run(source, config)
    if repo_id is not None and commit_hash is not None:
        db.update_pipeline_run_identity(
            pipeline.id, repo_id, commit_hash, config
        )
    db.start_stage_run(pipeline.id, stage, config)
    try:
        with model_usage_scope(pipeline.id):
            value = fn()
        usage = db.summarize_model_usage(pipeline.id, config, stage=stage)
        summary, artifacts = metadata(value)
        summary["model_usage"] = usage if usage["calls"] else "not recorded"
    except BaseException as exc:
        detail = f"{type(exc).__name__}: {exc}"[:4000]
        db.finish_stage_run(
            pipeline.id, stage, RunStatus.FAILED,
            failure_detail=detail, config=config,
        )
        db.finish_pipeline_run(
            pipeline.id, RunStatus.FAILED, failed_stage=stage,
            failure_detail=detail, config=config,
        )
        raise

    if success(value):
        db.finish_stage_run(
            pipeline.id, stage, RunStatus.COMPLETED, summary=summary,
            artifacts=artifacts, config=config,
        )
        db.finish_pipeline_run(
            pipeline.id, RunStatus.COMPLETED, artifacts=artifacts, config=config
        )
    else:
        detail = str(failure_detail(value) or "operation reported failure")[:4000]
        db.finish_stage_run(
            pipeline.id, stage, RunStatus.FAILED, summary=summary,
            artifacts=artifacts, failure_detail=detail, config=config,
        )
        db.finish_pipeline_run(
            pipeline.id, RunStatus.FAILED, failed_stage=stage,
            failure_detail=detail, config=config,
        )
    return value, pipeline


def _metered_repo_stage(
    repo_id: str, stage: str, fn, config,
    *, metadata=lambda value: ({}, []),
):
    """Resolve immutable repo provenance, then meter one standalone stage."""
    db.init_db(config)
    repo = db.get_latest_ingested_repo(repo_id, config)
    if repo is None:
        raise FileNotFoundError(f"no ingested repository named {repo_id}")
    snapshot = config.raw_dir / repo.repo_id / repo.commit_hash
    if not snapshot.is_dir():
        raise FileNotFoundError(f"stored snapshot is missing: {snapshot}")
    return _metered_operation(
        repo.source, stage, fn, config,
        repo_id=repo.repo_id, commit_hash=repo.commit_hash,
        metadata=metadata,
    )


def _render_preflight(result: PreflightResult) -> None:
    if not _quiet_enabled.get():
        if result.migrations:
            typer.echo(f"preflight: initialized SQLite ({', '.join(result.migrations)})")
        else:
            typer.echo("preflight: SQLite schema is ready")
    if result.missing_packages:
        typer.secho(
            f"preflight error: missing Python packages: {', '.join(result.missing_packages)}; "
            "run `uv sync`",
            fg=typer.colors.RED,
            err=True,
        )
    elif not _quiet_enabled.get():
        typer.echo("preflight: Python package dependencies are ready")
    if result.credential_error:
        typer.secho(
            f"preflight error: {result.credential_error}", fg=typer.colors.RED, err=True
        )
    if not result.git_available:
        typer.secho(
            "preflight warning: git executable not found; Git URL/repository ingest will fail",
            fg=typer.colors.YELLOW,
            err=True,
        )
    if not result.scanners_checked and not _quiet_enabled.get():
        typer.echo("preflight: optional deterministic scanners are disabled by config")
    elif result.missing_scanners:
        typer.secho(
            "preflight warning: optional scanners unavailable (their lenses will be skipped): "
            + ", ".join(result.missing_scanners),
            fg=typer.colors.YELLOW,
            err=True,
        )
    elif not result.missing_packages and not _quiet_enabled.get():
        typer.echo(
            "preflight: optional scanner executables are installed "
            "(execution health is verified during detect)"
        )


def _preflight(config) -> PreflightResult:
    result = check_runtime(config)
    _render_preflight(result)
    return result


def _ingest_stage(source: str, config):
    with _stage_timing("ingest") as timing, _progress("ingest"):
        result = ingest_repo(source, config)
        manifests = snapshot_manifests(result.snapshot_path, result.repo_id, result.commit)
    status = "reused (no-op)" if result.reused else "ingested"
    _stage_summary(
        f"{status}. repo-id: {result.repo_id}; commit: {result.commit}; "
        f"manifests={len(manifests.manifests)} -> {result.snapshot_path}", timing
    )
    return result


def _map_stage(repo_id: str, config):
    snapshot_path, commit = latest_snapshot(config, repo_id)
    with _stage_timing("map") as timing, _progress("map"):
        result = _stub_guard(recover_architecture, snapshot_path, repo_id, commit, config)
        artifact = architecture_artifact_path(
            config.paths.data_dir, result.repo_id, result.commit
        )
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(architecture_ascii(result), encoding="utf-8")
    _stage_summary(
        f"mapped {repo_id}: entry-points={len(result.entry_points)}, "
        f"trust-boundaries={len(result.trust_boundaries)}, "
        f"data-stores={len(result.data_stores)}, integrations={len(result.integrations)}; "
        f"artifact={artifact}", timing
    )
    _verbose(f"snapshot={snapshot_path}; commit={commit}")
    return result


def _detect_stage(repo_id: str, config):
    with _stage_timing("detect") as timing, _progress("detect"):
        result = _stub_guard(run_ensemble, repo_id, config)
    counts = result.source_counts
    _stage_summary(
        f"detected {len(result)} findings: semgrep={counts['semgrep']}, "
        f"gitleaks={counts['gitleaks']}, pip-audit={counts['pip-audit']}, "
        f"osv-scanner={counts['osv-scanner']}, llm-ensemble={counts['llm-ensemble']}", timing
    )
    if result.projection is not None and not _quiet_enabled.get():
        typer.echo(
            "  live-region-coverage="
            f"{result.projection.planned_regions}/{result.projection.source_files}; "
            f"completed-calls={result.completed_region_calls}; "
            f"reused-completed-calls={result.skipped_completed_region_calls}"
        )
    if result.sarif_path is not None:
        if not _quiet_enabled.get():
            typer.echo(f"  semgrep-status={result.semgrep_status}; SARIF={result.sarif_path}")
    scanner_statuses = getattr(result, "scanner_statuses", {})
    scanner_failures = getattr(result, "scanner_failures", {})
    if scanner_statuses and not _quiet_enabled.get():
        typer.echo(
            "  scanner-execution: "
            + ", ".join(
                f"{name}={status}"
                for name, status in sorted(scanner_statuses.items())
            )
        )
    for name, detail in sorted(scanner_failures.items()):
        typer.secho(
            f"  scanner detail: {name}: {detail}",
            fg=typer.colors.YELLOW,
            err=True,
        )
    return result


def _triage_stage(repo_id: str, config, sarif: Path | None = None, threshold: float = 0.5):
    with _stage_timing("triage") as timing, _progress("triage"):
        outcome = _stub_guard(
            triage_repo, repo_id, config, sarif_path=sarif, action_threshold=threshold
        )
    eval_on = outcome.evaluations[0].eval_on if outcome.evaluations else "synthetic"
    _stage_summary(
        f"triaged {len(outcome.ranked)} findings for {repo_id}: "
        f"ranked={len(outcome.ranked)}, suppressed={outcome.n_suppressed}, eval_on={eval_on}", timing
    )
    synth = "dropped" if outcome.synthetic_dropped else f"{outcome.synthetic_share:.0%}"
    if not _quiet_enabled.get():
        typer.echo(
            f"  labels: real={outcome.n_real_labels} synthetic_share={synth} "
            f"(shrinks as real labels accumulate)"
        )
        if outcome.evaluations:
            typer.echo(
                f"  validation: {outcome.evaluations[0].split_strategy}; "
                f"{outcome.evaluations[0].split_detail}"
            )
    _verbose(f"SARIF={sarif or 'auto-discovered'}; action-threshold={threshold}")
    return outcome


def _falsify_stage(repo_id: str, config):
    with _stage_timing("falsify") as timing, _progress("falsify"):
        result = _stub_guard(challenge, repo_id, config)
    counts = {status: 0 for status in ("confirmed", "killed", "unresolved")}
    for outcome in result:
        counts[str(outcome.status)] += 1
    _stage_summary(
        f"falsified {repo_id}: confirmed={counts['confirmed']}, killed={counts['killed']}, "
        f"unresolved={counts['unresolved']}, deferred={result.deferred_count}", timing
    )
    if result.remaining_call_capacity is not None and not _quiet_enabled.get():
        typer.echo(
            f"  cost preflight: pending={result.pending_count}; "
            f"minimum={result.minimum_calls_per_finding} calls/finding; "
            f"reserved={result.reserved_calls_per_finding} including iteration/retry envelope; "
            f"capacity-at-start={result.remaining_call_capacity}"
        )
    return result


def _normalize_stage(repo_id: str, config):
    with _stage_timing("normalize") as timing, _progress("normalize"):
        result = _stub_guard(adjudicate_repo, repo_id, config)
    unresolved = sum(f.falsification_status.value == "unresolved" for f in result)
    _stage_summary(
        f"normalized {repo_id}: resolved={len(result) - unresolved}, "
        f"unresolved (routed to review)={unresolved}", timing
    )
    return result


def _quantify_stage(
    repo_id: str, config, *, trials: int = 50_000, seed: int = 0,
    record_audit: bool = False,
):
    with _stage_timing("quantify") as timing, _progress("quantify"):
        artifacts = _stub_guard(
            quantify_appendix, repo_id, config, trials=trials, seed=seed,
            persist=record_audit,
        )
    path, scenario_count = artifacts
    disclosure = quantitative_disclosure(audit_quantitative_inputs(repo_id, config))
    if disclosure:
        typer.secho(disclosure, fg=typer.colors.YELLOW, err=True)
    _stage_summary(
        f"quantified {repo_id}: scenarios={scenario_count}, "
        f"record-audit={'yes' if record_audit else 'no'}; wrote {path}", timing
    )
    return artifacts


def _report_stage(
    repo_id: str, config, mode: ReportMode, *, record_audit: bool = False,
    quantification=None, print_report: bool = True,
):
    with _stage_timing(f"report ({mode.value})") as timing, _progress("report"):
        if mode is ReportMode.ENGINEERING:
            paths = [_stub_guard(write_backlog, repo_id, config)]
            rendered_path = paths[0]
        else:
            paths = _stub_guard(
                write_memo, repo_id, config, record_audit=record_audit,
                quantification=quantification,
            )
            rendered_path = next(path for path in paths if path.name == "memo.md")
    if print_report and not _quiet_enabled.get():
        typer.echo(rendered_path.read_text())
    _stage_summary(f"reported {repo_id}: wrote {', '.join(str(path) for path in paths)}", timing)
    return paths


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
    debug: bool = typer.Option(
        False, "--debug", help="Diagnostic mode: preserve Python tracebacks on failures."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress stage progress/summaries; show final recap or errors."
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show extra artifact and stage metadata (not tracebacks)."
    ),
):
    if quiet and verbose:
        raise typer.BadParameter("--quiet and --verbose cannot be used together")
    _debug_enabled.set(debug)
    _quiet_enabled.set(quiet)
    _verbose_enabled.set(verbose)
    if version:
        typer.echo(f"repoauditor {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        if sys.stdin.isatty() and sys.stdout.isatty():
            menu()
        else:
            typer.echo(ctx.get_help())
        raise typer.Exit()


def _menu_repo(
    config, *, require_reviews: bool = False, require_deferred: bool = False
):
    """Prompt for one known repository; return its state or None."""
    state = load_menu_state(config)
    choices = [
        repo for repo in state.repositories
        if (not require_reviews or repo.open_reviews)
        and (not require_deferred or repo.deferred_findings)
    ]
    if not choices:
        typer.echo(
            (
                "No repositories have pending review requests."
                if require_reviews
                else "No repositories have deferred findings."
                if require_deferred
                else "No repositories have been ingested yet."
            )
        )
        return None
    typer.echo("")
    for index, repo in enumerate(choices, 1):
        review = f"; {repo.open_reviews} review(s) pending" if repo.open_reviews else ""
        deferred = (
            f"; {repo.deferred_findings} deferred" if repo.deferred_findings else ""
        )
        typer.echo(f"  {index}. {repo.repo_id} — {repo.source}{review}{deferred}")
    while True:
        value = typer.prompt("Select repository", default="1").strip()
        if value.isdigit() and 1 <= int(value) <= len(choices):
            return choices[int(value) - 1]
        typer.echo(f"Enter a number from 1 to {len(choices)}.")


@app.command()
@_clean_errors("menu")
def menu() -> None:
    """Open the state-aware numbered interface (existing commands remain available)."""
    config = get_config()
    state = load_menu_state(config)
    typer.echo(render_main_menu(state))
    while True:
        selection = typer.prompt("Select an option", default="1").strip()
        if selection in {str(number) for number in range(1, 8)}:
            break
        typer.echo("Enter a number from 1 to 7.")

    if selection == "1":
        typer.echo("Equivalent command: repoauditor demo")
        demo(trials=10_000, seed=0, non_interactive=False)
    elif selection == "2":
        deferred_repos = [
            repo for repo in state.repositories if repo.deferred_findings
        ]
        if deferred_repos and typer.confirm(
            "Resume a deferred scan instead of starting a new one?", default=True
        ):
            repo = _menu_repo(config, require_deferred=True)
            if repo is None:
                return
            typer.echo(f"Equivalent command: repoauditor resume {repo.repo_id}")
            resume(repo.repo_id, RunFormat.HUMAN)
            return
        source = typer.prompt("Repository path or Git URL").strip()
        if not source:
            typer.echo("No target entered; returning without starting a scan.")
            return
        typer.echo(f"Equivalent command: repoauditor run {source}")
        run(source=source, output_format=RunFormat.HUMAN, fresh=False)
    elif selection == "3":
        repo = _menu_repo(config, require_reviews=True)
        if repo is None:
            return
        typer.echo(f"Equivalent command: repoauditor review list {repo.repo_id}")
        typer.echo(render_open_requests(repo.repo_id, config))
        requests = open_review_requests(repo.repo_id, config)
        request = requests[0] if len(requests) == 1 else None
        if request is None:
            request_id = typer.prompt("Request id to decide").strip()
            request = next((item for item in requests if str(item.id) == request_id), None)
            if request is None:
                typer.echo("That request is not open for the selected repository.")
                return
        if not typer.confirm(f"Decide request #{request.id} now?", default=True):
            return
        disposition = typer.prompt("Decision (confirm/dismiss)", default="dismiss").strip().lower()
        while disposition not in {"confirm", "dismiss"}:
            disposition = typer.prompt("Enter confirm or dismiss").strip().lower()
        rationale = typer.prompt("Short rationale").strip()
        while not rationale:
            rationale = typer.prompt("A rationale is required").strip()
        reviewer = typer.prompt("Reviewer name", default=getpass.getuser())
        decision = decide(
            repo.repo_id, request.id, disposition, rationale, reviewer, config
        )
        typer.echo(f"Recorded decision #{decision.id}: {decision.disposition}.")
    elif selection == "4":
        repo = _menu_repo(config)
        if repo is None:
            return
        if repo.open_reviews:
            typer.echo(
                f"Finalize is blocked: {repo.open_reviews} review request(s) remain. "
                "Choose option 3 first."
            )
            return
        typer.echo(f"Equivalent command: repoauditor finalize {repo.repo_id}")
        finalize(
            repo_id=repo.repo_id, trials=50_000, seed=0,
            record_audit=False, print_reports=False,
        )
    elif selection == "5":
        typer.echo("Equivalent commands: repoauditor repos list; repoauditor runs list")
        typer.echo(repos_table(db.list_ingested_repos(config, all_snapshots=False)))
        runs_list(repo_id=None)
    elif selection == "6":
        live = typer.confirm(
            "Also make one live model request? This may incur provider charges.", default=False
        )
        typer.echo("Equivalent command: repoauditor doctor" + (" --check-model" if live else ""))
        doctor(model=live)
    else:
        typer.echo("Goodbye.")


@db_app.command("init")
@_clean_errors("db init")
def db_init() -> None:
    """Create/upgrade the SQLite schema by applying pending migrations."""
    applied = db.init_db(get_config())
    if applied:
        typer.echo(f"applied migrations: {', '.join(applied)}")
    else:
        typer.echo("schema already up to date")


@app.command()
@_clean_errors("demo")
def demo(
    trials: int = typer.Option(10_000, "--trials", help="Monte Carlo trial count."),
    seed: int = typer.Option(0, "--seed", help="RNG seed for reproducibility."),
    non_interactive: bool = typer.Option(
        False, "--non-interactive",
        help="Stop at review instead of prompting for a human decision.",
    ),
    continue_existing: bool = typer.Option(
        False, "--continue",
        help="Finish review, reports, and scorecards after a bounded demo resume.",
    ),
) -> None:
    """Run the safe, intentionally vulnerable UAT storefront as a guided demo."""
    config = get_config()
    fixture_root = config.root / "tests" / "fixtures" / _DEMO_REPO_ID
    snapshot = fixture_root / "snapshot"
    expectations = fixture_root / "expected_findings.json"
    if not snapshot.is_dir() or not expectations.is_file():
        typer.secho(
            "demo fixture is missing; run this command from a complete repoauditor checkout",
            fg=typer.colors.RED, err=True,
        )
        raise typer.Exit(code=1)

    preflight = _preflight(config)
    if preflight.credential_error:
        env_name = (
            "ANTHROPIC_API_KEY" if config.llm.provider == "anthropic"
            else config.llm.api_key_env
        )
        typer.secho(
            f"Demo cannot start: no API key present. Set it in this terminal with:\n"
            f"  export {env_name}=\"your-key-here\"\n"
            "The key is read from the environment and is never written to the repository.",
            fg=typer.colors.RED, err=True,
        )
        raise typer.Exit(code=1)
    if not preflight.ready:
        typer.secho("demo stopped: preflight requirements are not satisfied", err=True)
        raise typer.Exit(code=1)

    db.init_db(config)
    pipeline = db.start_pipeline_run(str(snapshot), config)
    try:
        with model_usage_scope(pipeline.id):
            if continue_existing:
                artifacts, identity = _continue_demo(
                    config, expectations, trials, seed, non_interactive, pipeline.id
                )
            else:
                artifacts, identity = _execute_demo(
                    config, snapshot, expectations, trials, seed, non_interactive,
                    pipeline.id,
                )
        if identity is not None:
            db.update_pipeline_run_identity(
                pipeline.id, identity.repo_id, identity.commit, config
            )
        db.finish_pipeline_run(
            pipeline.id, RunStatus.COMPLETED, artifacts=artifacts, config=config
        )
    except BaseException as exc:
        # A normal zero-code Click exit is an expected review pause; every other exit or
        # exception is durable failure evidence for the same protected run.
        if isinstance(exc, typer.Exit) and exc.exit_code == 0:
            db.finish_pipeline_run(
                pipeline.id, RunStatus.COMPLETED, artifacts=[str(snapshot)], config=config
            )
        else:
            db.finish_pipeline_run(
                pipeline.id, RunStatus.FAILED, failed_stage="demo",
                failure_detail=f"{type(exc).__name__}: {exc}"[:4000], config=config,
            )
        raise


def _execute_demo(
    config, snapshot: Path, expectations: Path, trials: int, seed: int,
    non_interactive: bool, pipeline_id: int,
) -> tuple[list[str], object | None]:
    """Execute the guided workflow inside demo's durable model-usage scope."""
    typer.echo(
        "Demo safety: this fixture is intentionally vulnerable. repoauditor reads it "
        "statically and will not start the web application."
    )
    typer.echo("Checking the configured live model (one small API request; charges may apply)...")
    probe = check_model(config)
    if not probe.ready:
        typer.secho(f"Demo cannot start: model check failed: {probe.error}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Model ready: {probe.provider}/{probe.model}")

    def ingest_demo():
        with _stage_timing("ingest") as timing, _progress("ingest"):
            result = ingest_repo(str(snapshot), config, repo_id=_DEMO_REPO_ID)
            manifests = snapshot_manifests(
                result.snapshot_path, result.repo_id, result.commit
            )
        _stage_summary(
            f"ingested demo. repo-id: {result.repo_id}; commit: {result.commit}; "
            f"manifests={len(manifests.manifests)}", timing,
        )
        return result

    ingested = _run_step(
        "ingest",
        ingest_demo,
        pipeline_id=pipeline_id,
        config=config,
        metadata=_ingest_run_metadata,
    )
    db.update_pipeline_run_identity(
        pipeline_id, ingested.repo_id, ingested.commit, config
    )
    _run_step(
        "map",
        lambda: _map_stage(_DEMO_REPO_ID, config),
        pipeline_id=pipeline_id,
        config=config,
        metadata=lambda value: _map_run_metadata(value, config),
    )
    detection = _run_step(
        "detect",
        lambda: _detect_stage(_DEMO_REPO_ID, config),
        pipeline_id=pipeline_id,
        config=config,
        metadata=lambda value: _detect_run_metadata(value, config),
    )
    _run_step(
        "triage",
        lambda: _triage_stage(_DEMO_REPO_ID, config, sarif=detection.sarif_path),
        pipeline_id=pipeline_id,
        config=config,
        metadata=_triage_run_metadata,
    )
    falsification = _run_step(
        "falsify",
        lambda: _falsify_stage(_DEMO_REPO_ID, config),
        pipeline_id=pipeline_id,
        config=config,
        metadata=lambda value: _falsify_run_metadata(value, config),
    )
    if falsification.deferred_count:
        typer.echo(
            f"Demo paused safely with {falsification.deferred_count} deferred finding(s); "
            f"run `repoauditor resume {_DEMO_REPO_ID}` to continue the bounded queue "
            "without repeating map/detect. When the backlog is clear, run "
            "`repoauditor demo --continue` to complete review, reports, and scorecards."
        )
        return [str(ingested.snapshot_path)], ingested
    _run_step(
        "normalize",
        lambda: _normalize_stage(_DEMO_REPO_ID, config),
        pipeline_id=pipeline_id,
        config=config,
        metadata=lambda value: _normalize_run_metadata(value, config),
    )
    return _finish_demo(
        config, expectations, trials, seed, non_interactive, ingested, pipeline_id
    )


def _continue_demo(
    config, expectations: Path, trials: int, seed: int, non_interactive: bool,
    pipeline_id: int,
) -> tuple[list[str], object | None]:
    """Continue only the demo checkpoint/artifact path; never repeat map or detect."""
    repo = db.get_latest_ingested_repo(_DEMO_REPO_ID, config)
    if repo is None:
        typer.secho("No prior demo scan exists; run `repoauditor demo` first.", err=True)
        raise typer.Exit(code=1)
    deferred = db.list_deferred_findings(_DEMO_REPO_ID, config)
    if deferred:
        typer.secho(
            f"Demo still has {len(deferred)} deferred finding(s). Continue with "
            f"`repoauditor resume {_DEMO_REPO_ID}` first.",
            err=True,
        )
        raise typer.Exit(code=1)
    snapshot_path, commit = latest_snapshot(config, _DEMO_REPO_ID)
    identity = SimpleNamespace(
        repo_id=_DEMO_REPO_ID, commit=commit, snapshot_path=snapshot_path
    )
    typer.echo("Continuing the existing demo without repeating ingest, map, or detect.")
    return _finish_demo(
        config, expectations, trials, seed, non_interactive, identity, pipeline_id
    )


def _finish_demo(
    config, expectations: Path, trials: int, seed: int, non_interactive: bool,
    identity, pipeline_id: int,
) -> tuple[list[str], object | None]:
    """Handle the review checkpoint and generate every final demo artifact."""
    _run_step(
        "review checkpoint",
        lambda: raise_review_requests(
            _DEMO_REPO_ID, config, sampling_run_id=pipeline_id
        ),
        pipeline_id=pipeline_id,
        config=config,
        metadata=lambda value: ({
            "requests_raised_or_refreshed": len(value),
            "open_requests": len(open_review_requests(_DEMO_REPO_ID, config)),
        }, []),
    )
    requests = open_review_requests(_DEMO_REPO_ID, config)
    if requests:
        typer.echo(render_open_requests(_DEMO_REPO_ID, config))
        if non_interactive:
            typer.echo(
                f"Demo paused successfully. Decide requests with `repoauditor review decide "
                f"{_DEMO_REPO_ID} ...`, then run `repoauditor demo --continue`."
            )
            return [str(identity.snapshot_path)], identity
        reviewer = typer.prompt("Reviewer name", default=getpass.getuser())
        for request in requests:
            disposition = typer.prompt(
                f"Request #{request.id}: decision (confirm/dismiss)", default="dismiss"
            ).strip().lower()
            while disposition not in {"confirm", "dismiss"}:
                disposition = typer.prompt("Enter confirm or dismiss").strip().lower()
            rationale = typer.prompt("Short rationale").strip()
            while not rationale:
                rationale = typer.prompt("A rationale is required").strip()
            decide(
                _DEMO_REPO_ID, request.id, disposition, rationale, reviewer, config
            )
            typer.echo(f"Recorded {disposition} for request #{request.id}.")

    quantification = _run_step(
        "quantify",
        lambda: _quantify_stage(
            _DEMO_REPO_ID, config, trials=trials, seed=seed, record_audit=True
        ),
        pipeline_id=pipeline_id,
        config=config,
        metadata=lambda value: _quantify_run_metadata(
            value, trials=trials, seed=seed, record_audit=True
        ),
    )
    engineering = _run_step(
        "engineering report",
        lambda: _report_stage(
            _DEMO_REPO_ID, config, ReportMode.ENGINEERING, print_report=False
        ),
        pipeline_id=pipeline_id,
        config=config,
        metadata=lambda value: _report_run_metadata(
            value, mode=ReportMode.ENGINEERING
        ),
    )
    memo = _run_step(
        "memo report",
        lambda: _report_stage(
            _DEMO_REPO_ID, config, ReportMode.MEMO,
            quantification=quantification, print_report=False,
        ),
        pipeline_id=pipeline_id,
        config=config,
        metadata=lambda value: _report_run_metadata(
            value, mode=ReportMode.MEMO
        ),
    )
    scorecard = score_demo(_DEMO_REPO_ID, expectations, config)
    typer.echo(
        f"Demo complete: {scorecard.passed}/{scorecard.total} final security outcomes passed; "
        f"{sum(case.mechanism_exercised for case in scorecard.cases)}/"
        f"{scorecard.total} expected mechanisms exercised."
    )
    typer.echo("Artifacts:")
    artifacts = [*engineering, *memo, scorecard.markdown_path, scorecard.json_path]
    for path in artifacts:
        typer.echo(f"  {path}")
    return [str(path) for path in artifacts], identity


@app.command()
@_clean_errors("doctor")
def doctor(
    model: bool = typer.Option(
        False, "--check-model",
        help="Make one live, potentially billable request to verify endpoint, auth, model, and structured output.",
    ),
) -> None:
    """Check dependencies/schema; optionally probe the configured model."""
    config = get_config()
    result = _preflight(config)
    if not result.ready:
        raise typer.Exit(code=1)
    if model:
        typer.echo("Model check: making one live API request; provider charges may apply.")
        probe, _ = _metered_operation(
            "diagnostic:model-check", "doctor", lambda: check_model(config), config,
            success=lambda value: value.ready,
            failure_detail=lambda value: value.error,
        )
        if not probe.ready:
            typer.secho(
                f"model check failed ({probe.provider}/{probe.model}, "
                f"structured-output={probe.response_format}): {probe.error}",
                fg=typer.colors.RED, err=True,
            )
            raise typer.Exit(code=1)
        typer.echo(
            f"model check passed: provider={probe.provider}; model={probe.model}; "
            f"structured-output={probe.response_format}"
        )


@app.command()
@_clean_errors("ingest")
def ingest(source: str = typer.Argument(..., help="Git URL or local repo/dir to ingest.")) -> None:
    """Clone/snapshot a target repo (idempotent, keyed by commit hash)."""
    _ingest_stage(source, get_config())


@repos_app.command("list")
@_clean_errors("repos list")
def repos_list(
    output_format: ListFormat = typer.Option(
        ListFormat.HUMAN, "--format", help="Output format: human or json."
    ),
    all_snapshots: bool = typer.Option(
        False, "--all", help="Show full ingest history, not only each source's latest snapshot."
    ),
) -> None:
    """List ingested repositories (latest snapshot per source by default)."""
    repos = db.list_ingested_repos(get_config(), all_snapshots=all_snapshots)
    typer.echo(repos_json(repos) if output_format is ListFormat.JSON else repos_table(repos))


@app.command()
@_clean_errors("map")
def map(repo_id: str = typer.Argument(..., help="Ingested repo id.")) -> None:
    """Recover the architecture/trust-boundary map (runs before detection)."""
    config = get_config()
    _metered_repo_stage(
        repo_id, "map", lambda: _map_stage(repo_id, config), config,
        metadata=lambda value: _map_run_metadata(value, config),
    )


@app.command()
@_clean_errors("detect")
def detect(repo_id: str = typer.Argument(..., help="Ingested + mapped repo id.")) -> None:
    """Run the multi-lens detection ensemble + deterministic tools."""
    config = get_config()
    _metered_repo_stage(
        repo_id, "detect", lambda: _detect_stage(repo_id, config), config,
        metadata=lambda value: _detect_run_metadata(value, config),
    )


@app.command()
@_clean_errors("triage")
def triage(
    repo_id: str = typer.Argument(..., help="Repo id with deterministic SAST findings."),
    sarif: Path = typer.Option(
        None, "--sarif", help="SARIF file to triage (default: discovered by convention)."
    ),
    threshold: float = typer.Option(
        0.5, "--threshold", help="P(actionable) below which a finding is suppressed."
    ),
) -> None:
    """Rank SAST findings by calibrated P(actionable) (runs after detect, before falsify)."""
    _triage_stage(repo_id, get_config(), sarif, threshold)


@app.command(name="triage-label")
@_clean_errors("triage-label")
def triage_label(
    finding_id: int = typer.Argument(..., help="Finding id to label (from `triage` output)."),
    disposition: LabelDisposition = typer.Option(
        ...,
        "--disposition",
        help=(
            "confirmed_actionable | tool_incorrect | unreachable | "
            "not_attacker_controlled | mitigated | duplicate | "
            "valid_not_actionable | insufficient_evidence. Legacy "
            "true_positive/false_positive/uncertain remain accepted."
        ),
    ),
    rationale: str = typer.Option(
        ..., "--rationale", "--note", help="Required analyst rationale (audited)."
    ),
    analyst: str = typer.Option(
        None, "--analyst", help="Analyst identity (defaults to the current OS user)."
    ),
    dimension: list[str] = typer.Option(
        None, "--dimension", help="Repeatable analyst-declared coverage dimension."
    ),
    material: bool = typer.Option(
        False, "--material",
        help="Mark as material; requires matching review by a second analyst before training."
    ),
) -> None:
    """Record a reasoned analyst assessment; uncertain assessments do not train."""
    try:
        legacy = {
            LabelDisposition.TRUE_POSITIVE: TriageDisposition.CONFIRMED_ACTIONABLE,
            LabelDisposition.FALSE_POSITIVE: TriageDisposition.TOOL_INCORRECT,
            LabelDisposition.UNCERTAIN: TriageDisposition.INSUFFICIENT_EVIDENCE,
        }
        detailed = (
            legacy[disposition]
            if disposition in legacy
            else TriageDisposition(disposition.value)
        )
        assessment, label = assess_finding(
            finding_id,
            detailed,
            rationale,
            analyst or getpass.getuser(),
            dimension,
            get_config(),
            material=material,
        )
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if label is None:
        if not assessment.classifier_eligible:
            material_note = (
                " Material-review evidence remains subject to independent agreement."
                if assessment.material else ""
            )
            typer.echo(
                f"recorded assessment #{assessment.id}: finding #{finding_id} has no "
                "compatible triage feature row, so this is assessment-only evidence and "
                f"was excluded from classifier training.{material_note}"
            )
            return
        if assessment.material and (
            assessment.outcome is not TriageAssessmentOutcome.UNCERTAIN
        ):
            typer.echo(
                f"recorded material assessment #{assessment.id}: finding #{finding_id} "
                "is withheld from classifier training pending a matching review by a "
                "second analyst."
            )
            return
        typer.echo(
            f"recorded assessment #{assessment.id}: finding #{finding_id} remains "
            f"{assessment.disposition.value} and was excluded from classifier training."
        )
        return
    verdict = "true positive" if label.actionable else "false positive"
    typer.echo(
        f"recorded assessment #{assessment.id}; labelled finding #{finding_id} as "
        f"{verdict} ({assessment.disposition.value}; rule {label.rule_id}, "
        f"engagement {label.engagement}) — manual label takes precedence over derived."
    )


@app.command(name="triage-collection")
@_clean_errors("triage-collection")
def triage_collection_command(
    repo_id: str = typer.Argument(
        None, help="Optional repo/engagement id; omit for portfolio collection status."
    ),
) -> None:
    """Show progress and coverage against the controlled real-label activation gate."""
    config = get_config()
    db.init_db(config)
    typer.echo(render_collection_status(collection_status(repo_id, config)))


@app.command(name="triage-stats")
@_clean_errors("triage-stats")
def triage_stats_command(
    repo_id: str = typer.Argument(
        None, help="Optional repo/engagement id; omit for the cross-engagement view."
    ),
    label_source: str = typer.Option(
        "human", "--label-source", help="Label cohort: human, derived, or all."
    ),
    run_id: int = typer.Option(
        None, "--run-id", help="Restrict to scores from one compatible triage model run."
    ),
) -> None:
    """Show real-label precision/recall tradeoffs without recommending a threshold."""
    typer.echo(render_threshold_stats(threshold_stats(
        repo_id, get_config(), label_cohort=label_source, triage_run_id=run_id
    )))


@app.command()
@_clean_errors("quantify")
def quantify(
    repo_id: str = typer.Argument(..., help="Repo id with triaged/falsified findings."),
    trials: int = typer.Option(50_000, "--trials", help="Monte Carlo trial count."),
    seed: int = typer.Option(0, "--seed", help="RNG seed for reproducibility."),
    record_audit: bool = typer.Option(
        False, "--record-audit",
        help="Persist a versioned SimulationRun and its scenario inputs."
    ),
) -> None:
    """Run a FAIR-style Monte Carlo risk simulation and write the findings appendix."""
    _quantify_stage(
        repo_id, get_config(), trials=trials, seed=seed, record_audit=record_audit
    )


@app.command(name="quant-audit")
@_clean_errors("quant-audit")
def quant_audit_command(
    repo_id: str = typer.Argument(
        ..., help="Repo id whose current read-only quantitative inputs should be audited."
    ),
) -> None:
    """Check quantitative applicability/double counting without changing the model."""
    typer.echo(render_quant_audit(audit_quantitative_inputs(repo_id, get_config())))


@app.command()
@_clean_errors("falsify")
def falsify(repo_id: str = typer.Argument(..., help="Repo id with candidate findings.")) -> None:
    """Run the falsification pass over candidate findings."""
    config = get_config()
    result, _ = _metered_repo_stage(
        repo_id, "falsify", lambda: _falsify_stage(repo_id, config), config,
        metadata=lambda value: _falsify_run_metadata(value, config),
    )
    if result.deferred_count:
        typer.echo(
            f"Next: repoauditor resume {repo_id} "
            f"({result.deferred_count} deferred finding(s) remain)"
        )


@app.command(name="falsify-convergence")
@_clean_errors("falsify-convergence")
def falsify_convergence(
    finding_id: int = typer.Argument(
        ..., help="Persisted finding id to evaluate without changing its verdict."
    ),
    output_format: ListFormat = typer.Option(
        ListFormat.HUMAN, "--format", help="Output format: human or json."
    ),
) -> None:
    """Test verdict stability across coarse-to-refined analysis resolution.

    This evaluation makes multiple model calls and can incur provider cost. It never
    writes a falsification verdict or changes the production pipeline.
    """
    config = get_config()
    finding = db.get_finding(finding_id, config)
    if finding is None:
        typer.secho(f"finding #{finding_id} not found", err=True)
        raise typer.Exit(code=1)
    result, _ = _metered_repo_stage(
        finding.repo_id, "falsify-convergence",
        lambda: evaluate_finding_convergence(finding_id, config), config,
    )
    typer.echo(
        result.model_dump_json(indent=2)
        if output_format is ListFormat.JSON
        else render_convergence(result)
    )


@app.command(name="qualify-instrument")
@_clean_errors("qualify-instrument")
def qualify_instrument(
    output_format: ListFormat = typer.Option(
        ListFormat.HUMAN, "--format", help="Output format: human or json."
    ),
) -> None:
    """Run paid manufactured controls against the falsification instrument.

    This makes multiple model calls and may incur provider cost. It does not scan or
    modify an ingested repository and does not measure real-world accuracy.
    """
    config = get_config()
    fixture = config.root / "tests" / "fixtures" / "manufactured_sentinels"
    result, pipeline = _metered_operation(
        "evaluation:manufactured-sentinels", "qualify-instrument",
        lambda: evaluate_manufactured_sentinels(fixture, config=config), config,
    )
    result.model_usage = db.summarize_model_usage(
        pipeline.id, config
    )
    typer.echo(
        result.model_dump_json(indent=2)
        if output_format is ListFormat.JSON
        else render_sentinel_qualification(result)
    )
    if not result.qualified:
        raise typer.Exit(code=1)


@app.command(name="qualify-detection")
@_clean_errors("qualify-detection")
def qualify_detection(
    output_format: ListFormat = typer.Option(
        ListFormat.HUMAN, "--format", help="Output format: human or json."
    ),
) -> None:
    """Run the paid manufactured archive pair against the OWASP detection lens."""
    config = get_config()
    fixture = config.root / "tests" / "fixtures" / "manufactured_archive_controls"
    result, pipeline = _metered_operation(
        "evaluation:manufactured-archive-detection",
        "qualify-detection",
        lambda: evaluate_archive_detection_sentinels(fixture, config=config),
        config,
    )
    result.model_usage = db.summarize_model_usage(
        pipeline.id, config, stage="qualify-detection"
    )
    typer.echo(
        result.model_dump_json(indent=2)
        if output_format is ListFormat.JSON
        else render_detection_qualification(result)
    )
    if not result.qualified:
        raise typer.Exit(code=1)


@app.command(name="qualify-xml-detection")
@_clean_errors("qualify-xml-detection")
def qualify_xml_detection(
    output_format: ListFormat = typer.Option(
        ListFormat.HUMAN, "--format", help="Output format: human or json."
    ),
) -> None:
    """Run the paid manufactured XML parser-differential pair against OWASP."""
    config = get_config()
    fixture = config.root / "tests" / "fixtures" / "manufactured_xml_controls"
    result, pipeline = _metered_operation(
        "evaluation:manufactured-xml-detection",
        "qualify-xml-detection",
        lambda: evaluate_xml_detection_sentinels(fixture, config=config),
        config,
    )
    result.model_usage = db.summarize_model_usage(
        pipeline.id, config
    )
    typer.echo(
        result.model_dump_json(indent=2)
        if output_format is ListFormat.JSON
        else render_xml_detection_qualification(result)
    )
    if not result.qualified:
        raise typer.Exit(code=1)


@app.command(name="usage-calibration")
@_clean_errors("usage-calibration")
def usage_calibration(
    lightweight_run_id: int = typer.Option(
        ..., "--lightweight-run-id", help="Completed lightweight fixture pipeline run id."
    ),
    independent_pre_run_id: int = typer.Option(
        ..., "--independent-pre-run-id", help="Completed vulnerable pre-fix pipeline run id."
    ),
    independent_post_run_id: int = typer.Option(
        ..., "--independent-post-run-id", help="Completed patched post-fix pipeline run id."
    ),
    output_format: ListFormat = typer.Option(
        ListFormat.HUMAN, "--format", help="Output format: human or json."
    ),
) -> None:
    """Compare recorded provider usage offline; never calls a model or changes a limit."""
    config = get_config()
    db.init_db(config)
    report = build_usage_calibration(
        {
            "lightweight": lightweight_run_id,
            "independent_pre": independent_pre_run_id,
            "independent_post": independent_post_run_id,
        },
        config,
    )
    typer.echo(
        report.model_dump_json(indent=2)
        if output_format is ListFormat.JSON
        else render_usage_calibration(report)
    )
    if not report.ready:
        raise typer.Exit(code=1)


@app.command()
@_clean_errors("normalize")
def normalize(repo_id: str = typer.Argument(..., help="Repo id with falsified findings.")) -> None:
    """Adjudicate conflicting severities and route unresolved findings to review."""
    config = get_config()
    _metered_repo_stage(
        repo_id, "normalize", lambda: _normalize_stage(repo_id, config), config,
        metadata=lambda value: _normalize_run_metadata(value, config),
    )


@app.command()
@_clean_errors("report")
def report(
    repo_id: str = typer.Argument(..., help="Repo id to report on."),
    mode: ReportMode = typer.Option(
        ReportMode.ENGINEERING, "--mode", help="Projection to produce."
    ),
    record_audit: bool = typer.Option(
        False, "--record-audit",
        help="memo only: persist a versioned SimulationRun and scenario inputs "
             "(additive logging; never mutates findings/severity).",
    ),
) -> None:
    """Project the findings store into an engineering backlog or a leadership memo."""
    _report_stage(repo_id, get_config(), mode, record_audit=record_audit)


@app.command()
@_clean_errors("run")
def run(
    source: str = typer.Argument(..., help="Git URL or local repo/dir to audit."),
    output_format: RunFormat = typer.Option(
        RunFormat.HUMAN, "--format", help="Output format: human or streaming ndjson."
    ),
    fresh: bool = typer.Option(
        False, "--fresh", help="Start a new run instead of resuming the latest incomplete run for this source."
    ),
) -> None:
    """Run ingest through normalize, then stop at the human-review checkpoint.

    Incomplete runs resume from their first unfinished stage. Use --fresh to force a new
    run record; stage writes remain idempotent if a failed stage had partially persisted.
    """
    run_started = time.monotonic()
    run_started_at = _timestamp()
    machine = output_format is RunFormat.NDJSON
    if machine:
        _quiet_enabled.set(True)

    def event(stage: str, status: str, **details) -> None:
        if machine:
            typer.echo(ndjson_event(stage, status, **details))

    pipeline = None

    def step(stage: str, fn, metadata=lambda value: ({}, [])):
        event(stage, "started")
        db.start_stage_run(pipeline.id, stage, config)
        try:
            with model_usage_scope(pipeline.id):
                value = _run_step(stage, fn)
        except BaseException as exc:
            detail = f"{type(exc).__name__}: {exc}"[:4000]
            db.finish_stage_run(
                pipeline.id, stage, RunStatus.FAILED, failure_detail=detail, config=config
            )
            db.finish_pipeline_run(
                pipeline.id, RunStatus.FAILED, failed_stage=stage,
                failure_detail=detail, config=config,
            )
            event(stage, "failed", error=detail)
            raise
        summary, artifacts = metadata(value)
        usage = db.summarize_model_usage(pipeline.id, config, stage=stage)
        summary["model_usage"] = usage if usage["calls"] else "not recorded"
        db.finish_stage_run(
            pipeline.id, stage, RunStatus.COMPLETED, summary=summary,
            artifacts=artifacts, config=config,
        )
        event(stage, "completed", **summary, artifacts=artifacts)
        return value

    config = get_config()
    event("preflight", "started")
    if machine:
        with redirect_stdout(io.StringIO()):
            preflight = _preflight(config)
    else:
        preflight = _preflight(config)
    if not preflight.ready:
        event("preflight", "failed", error="requirements are not satisfied")
        typer.secho("run stopped: preflight requirements are not satisfied", err=True)
        raise typer.Exit(code=1)
    event("preflight", "completed")
    # Preflight normally applies this migration; the idempotent call also keeps
    # orchestrator tests/custom preflight wrappers from bypassing run-record setup.
    db.init_db(config)
    pipeline = None if fresh else db.find_resumable_pipeline_run(source, config)
    if pipeline is None:
        pipeline = db.start_pipeline_run(source, config)
        completed: dict[str, object] = {}
    else:
        db.resume_pipeline_run(pipeline.id, config)
        completed = {
            stage.stage: stage for stage in db.list_stage_runs(pipeline.id, config)
            if stage.status is RunStatus.COMPLETED
        }
        event("run", "resumed", run_id=pipeline.id, completed_stages=list(completed))
        if not machine and not _quiet_enabled.get():
            typer.echo(
                f"resuming run #{pipeline.id} after completed stage(s): "
                + (", ".join(completed) if completed else "none")
            )

    result = None
    if "ingest" not in completed or not pipeline.repo_id:
        result = step(
            "ingest", lambda: _ingest_stage(source, config),
            _ingest_run_metadata,
        )
        repo_id, commit = result.repo_id, result.commit
        db.update_pipeline_run_identity(pipeline.id, repo_id, commit, config)
    else:
        repo_id, commit = pipeline.repo_id, pipeline.commit_hash
    snapshot_path, _ = latest_snapshot(config, repo_id)
    projection = project_detection_work(
        snapshot_path, config, lens_count=len(LENS_PROMPT_VERSIONS)
    )
    validate_detection_projection(projection, config, preceding_map_calls=2)
    if not machine and not _quiet_enabled.get():
        typer.echo(
            "detection preflight: "
            f"source-files={projection.source_files}; "
            f"unbounded-base-calls={projection.unbounded_base_calls}; "
            f"planned-regions={projection.planned_regions}; "
            f"planned-base-calls={projection.planned_base_calls}; "
            f"omitted-regions={projection.omitted_regions}"
        )

    map_artifact = architecture_artifact_path(config.paths.data_dir, repo_id, commit)
    if "map" not in completed:
        step(
            "map",
            lambda: _map_stage(repo_id, config),
            lambda value: _map_run_metadata(value, config),
        )

    if "detect" not in completed:
        detection = step(
            "detect", lambda: _detect_stage(repo_id, config),
            lambda value: _detect_run_metadata(
                value,
                config,
                scanner_coverage={
                    "checked": preflight.scanners_checked,
                    "missing": preflight.missing_scanners,
                },
            ),
        )
    else:
        prior_detect = completed["detect"]
        paths = prior_detect.artifacts
        detection = DetectionRun(
            [], prior_detect.summary.get("source_counts", {}),
            Path(paths[0]) if paths else None,
            prior_detect.summary.get("semgrep_status"),
            scanner_statuses=prior_detect.summary.get("scanner_statuses", {}),
            scanner_failures=prior_detect.summary.get("scanner_failures", {}),
        )
    if "triage" not in completed:
        step(
            "triage", lambda: _triage_stage(repo_id, config, sarif=detection.sarif_path),
            _triage_run_metadata,
        )
    if "falsify" not in completed:
        falsification = step(
            "falsify", lambda: _falsify_stage(repo_id, config),
            lambda value: _falsify_run_metadata(value, config),
        )
        deferred_after_falsify = getattr(falsification, "deferred_count", 0)
    else:
        deferred_after_falsify = int(
            completed["falsify"].summary.get("deferred", 0) or 0
        )
    # A bounded falsify batch is a successful stage result, but deferred findings have
    # not been adjudicated and must not enter normalize/review/report as if examined.
    if not deferred_after_falsify and "normalize" not in completed:
        step(
            "normalize", lambda: _normalize_stage(repo_id, config),
            lambda value: _normalize_run_metadata(value, config),
        )
    if not deferred_after_falsify and "review checkpoint" not in completed:
        step(
            "review checkpoint",
            lambda: raise_review_requests(
                repo_id, config, sampling_run_id=pipeline.id
            ),
            lambda value: ({
                "requests_raised_or_refreshed": len(value),
                "open_requests": len(open_review_requests(repo_id, config)),
            }, []),
        )

    requests = open_review_requests(repo_id, config)
    deferred = db.list_deferred_findings(repo_id, config)
    if detection.semgrep_status not in {"complete", "empty"}:
        typer.secho(
            f"coverage notice: Semgrep status is {detection.semgrep_status}; "
            "the run completed without full SAST coverage.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    degraded_scanners = {
        name: status
        for name, status in getattr(detection, "scanner_statuses", {}).items()
        if status in {"failed", "partial"}
    }
    if degraded_scanners:
        typer.secho(
            "coverage notice: deterministic scanner coverage is incomplete: "
            + ", ".join(
                f"{name}={status}" for name, status in sorted(degraded_scanners.items())
            )
            + "; inspect `repoauditor runs show "
            + f"{pipeline.id}` for attributable detail.",
            fg=typer.colors.YELLOW,
            err=True,
        )
    artifact_items = [f"snapshot={snapshot_path}"]
    artifact_paths = [str(snapshot_path)]
    if map_artifact.is_file():
        artifact_items.append(f"architecture-map={map_artifact}")
        artifact_paths.append(str(map_artifact))
    if detection.sarif_path is not None:
        artifact_items.append(f"semgrep-sarif={detection.sarif_path}")
        artifact_paths.append(str(detection.sarif_path))
    artifact_items.append(f"review-requests={len(requests)}")
    artifact_items.append(f"deferred-findings={len(deferred)}")
    usage_totals = db.summarize_model_usage(pipeline.id, config)
    if usage_totals["calls"]:
        processed_tokens = (
            usage_totals["input_tokens"] + usage_totals["output_tokens"]
            + usage_totals["cache_read_tokens"] + usage_totals["cache_write_tokens"]
        )
        artifact_items.append(
            f"model-usage={usage_totals['calls']} calls/{processed_tokens} known tokens"
            + (
                f"/{usage_totals['unknown_usage_calls']} call(s) without token metadata"
                if usage_totals["unknown_usage_calls"] else ""
            )
        )
    db.finish_pipeline_run(
        pipeline.id, RunStatus.COMPLETED, artifacts=artifact_paths, config=config
    )
    if machine:
        next_command = (
            f"repoauditor resume {repo_id}"
            if deferred else (
                f"repoauditor review list {repo_id}" if requests
                else f"repoauditor finalize {repo_id}"
            )
        )
        typer.echo(ndjson_event(
            "run", "completed", repo_id=repo_id,
            run_id=pipeline.id,
            open_review_requests=len(requests), deferred_findings=len(deferred),
            artifacts=artifact_paths,
            model_usage=usage_totals if usage_totals["calls"] else "not recorded",
            elapsed_seconds=round(time.monotonic() - run_started, 3),
            next_command=next_command,
        ))
        return
    if deferred:
        typer.echo(
            f"run complete for {repo_id}; {len(deferred)} finding(s) remain deferred "
            "by the safe falsification budget and are not ready for analysis."
        )
        if requests:
            typer.echo(
                f"Review checkpoint also has {len(requests)} open request(s): "
                f"repoauditor review list {repo_id}"
            )
        typer.echo(f"Next: repoauditor resume {repo_id}")
    elif requests:
        typer.echo(
            f"run complete for {repo_id}; stopped at review checkpoint with "
            f"{len(requests)} open request(s)."
        )
        typer.echo(f"Next: repoauditor review list {repo_id}")
    else:
        typer.echo(f"run complete for {repo_id}; no findings require review.")
        typer.echo(f"Next: repoauditor finalize {repo_id}")
    typer.echo(
        f"run recap: started={run_started_at}; completed={_timestamp()}; "
        f"total={_elapsed(time.monotonic() - run_started)}; " + "; ".join(artifact_items)
    )


@app.command()
@_clean_errors("resume")
def resume(
    repo_id: str = typer.Argument(
        ..., help="Ingested repo id with a deferred falsification backlog."
    ),
    output_format: RunFormat = typer.Option(
        RunFormat.HUMAN, "--format", help="Output format: human or streaming ndjson."
    ),
) -> None:
    """Continue a deferred queue with a fresh budget; never rerun upstream stages."""
    started = time.monotonic()
    machine = output_format is RunFormat.NDJSON
    if machine:
        _quiet_enabled.set(True)

    def event(stage: str, status: str, **details) -> None:
        if machine:
            typer.echo(ndjson_event(stage, status, **details))

    config = get_config()
    event("preflight", "started")
    if machine:
        with redirect_stdout(io.StringIO()):
            preflight = _preflight(config)
    else:
        preflight = _preflight(config)
    if not preflight.ready:
        event("preflight", "failed", error="requirements are not satisfied")
        typer.secho("resume stopped: preflight requirements are not satisfied", err=True)
        raise typer.Exit(code=1)
    event("preflight", "completed")
    db.init_db(config)

    repo = db.get_latest_ingested_repo(repo_id, config)
    if repo is None:
        typer.secho(
            f"resume failed: no ingested repository named {repo_id}", err=True
        )
        raise typer.Exit(code=1)
    snapshot_path = config.raw_dir / repo.repo_id / repo.commit_hash
    if not snapshot_path.is_dir():
        typer.secho(
            f"resume failed: stored snapshot is missing: {snapshot_path}", err=True
        )
        raise typer.Exit(code=1)

    parent = db.get_latest_pipeline_run(
        repo_id, config, commit_hash=repo.commit_hash
    )
    pipeline = db.start_pipeline_run(
        repo.source, config, parent_run_id=parent.id if parent is not None else None
    )
    db.update_pipeline_run_identity(
        pipeline.id, repo.repo_id, repo.commit_hash, config
    )

    def step(stage: str, fn, metadata=lambda value: ({}, [])):
        event(stage, "started")
        db.start_stage_run(pipeline.id, stage, config)
        try:
            with model_usage_scope(pipeline.id):
                value = _run_step(stage, fn)
        except BaseException as exc:
            detail = f"{type(exc).__name__}: {exc}"[:4000]
            db.finish_stage_run(
                pipeline.id, stage, RunStatus.FAILED,
                failure_detail=detail, config=config,
            )
            db.finish_pipeline_run(
                pipeline.id, RunStatus.FAILED, failed_stage=stage,
                failure_detail=detail, artifacts=[str(snapshot_path)], config=config,
            )
            event(stage, "failed", error=detail)
            raise
        summary, artifacts = metadata(value)
        usage = db.summarize_model_usage(pipeline.id, config, stage=stage)
        summary["model_usage"] = usage if usage["calls"] else "not recorded"
        db.finish_stage_run(
            pipeline.id, stage, RunStatus.COMPLETED, summary=summary,
            artifacts=artifacts, config=config,
        )
        event(stage, "completed", **summary, artifacts=artifacts)
        return value

    deferred_before = db.list_deferred_findings(repo_id, config)
    if deferred_before:
        step(
            "falsify", lambda: _falsify_stage(repo_id, config),
            lambda value: _falsify_run_metadata(
                value, config, backlog_before=len(deferred_before)
            ),
        )

    deferred = db.list_deferred_findings(repo_id, config)
    requests = open_review_requests(repo_id, config)
    if not deferred:
        step(
            "normalize", lambda: _normalize_stage(repo_id, config),
            lambda value: _normalize_run_metadata(value, config),
        )
        step(
            "review checkpoint",
            lambda: raise_review_requests(
                repo_id, config, sampling_run_id=pipeline.id
            ),
            lambda value: ({
                "requests_raised_or_refreshed": len(value),
                "open_requests": len(open_review_requests(repo_id, config)),
            }, []),
        )
        requests = open_review_requests(repo_id, config)

    usage = db.summarize_model_usage(pipeline.id, config)
    db.finish_pipeline_run(
        pipeline.id, RunStatus.COMPLETED, artifacts=[str(snapshot_path)], config=config
    )
    next_command = (
        f"repoauditor resume {repo_id}" if deferred
        else (
            "repoauditor demo --continue" if repo_id == _DEMO_REPO_ID
            else f"repoauditor review list {repo_id}" if requests
            else f"repoauditor finalize {repo_id}"
        )
    )
    if machine:
        typer.echo(ndjson_event(
            "resume", "completed", run_id=pipeline.id, repo_id=repo_id,
            backlog_before=len(deferred_before), deferred_findings=len(deferred),
            open_review_requests=len(requests), artifacts=[str(snapshot_path)],
            model_usage=usage if usage["calls"] else "not recorded",
            elapsed_seconds=round(time.monotonic() - started, 3),
            next_command=next_command,
        ))
        return

    if deferred:
        typer.echo(
            f"resume batch complete for {repo_id}: backlog "
            f"{len(deferred_before)} -> {len(deferred)} deferred finding(s)."
        )
    elif requests:
        typer.echo(
            f"resume complete for {repo_id}; falsification backlog is clear and "
            f"{len(requests)} review request(s) are open."
        )
    else:
        typer.echo(
            f"resume complete for {repo_id}; falsification backlog is clear and "
            "no findings require review."
        )
    typer.echo(f"Next: {next_command}")


@runs_app.command("list")
@_clean_errors("runs list")
def runs_list(
    repo_id: str = typer.Option(None, "--repo-id", help="Limit history to one repository id."),
) -> None:
    """List pipeline run history, newest first."""
    rows = db.list_pipeline_runs(get_config(), repo_id=repo_id)
    if not rows:
        typer.echo("No pipeline runs recorded.")
        return
    typer.echo("RUN  STATUS     REPO-ID                 STARTED              FAILURE")
    for item in rows:
        typer.echo(
            f"{item.id:<4} {item.status.value:<10} {(item.repo_id or '-'):<23} "
            f"{(item.started_at or '-'):<20} {item.failed_stage or '-'}"
        )


@runs_app.command("show")
@_clean_errors("runs show")
def runs_show(run_id: int = typer.Argument(..., help="Pipeline run id.")) -> None:
    """Show stage timing, artifacts, and failure detail for one pipeline run."""
    config = get_config()
    item = db.get_pipeline_run(run_id, config)
    if item is None:
        typer.secho(f"run #{run_id} not found", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(
        f"run #{item.id}: status={item.status.value}; source={item.source}; "
        f"repo-id={item.repo_id or '-'}; commit={item.commit_hash or '-'}; "
        f"parent-run={item.parent_run_id or '-'}"
    )
    typer.echo(f"started={item.started_at}; completed={item.completed_at or '-'}")
    if item.failure_detail:
        typer.echo(f"failure at {item.failed_stage}: {item.failure_detail}")
    for stage in db.list_stage_runs(run_id, config):
        detail = f"; failure={stage.failure_detail}" if stage.failure_detail else ""
        elapsed = _stored_elapsed(stage.started_at, stage.completed_at)
        typer.echo(
            f"  {stage.stage}: {stage.status.value}; started={stage.started_at}; "
            f"completed={stage.completed_at or '-'}; elapsed={elapsed}; "
            f"artifacts={stage.artifacts}{detail}"
        )
        if stage.summary:
            typer.echo("    summary: " + json.dumps(stage.summary, sort_keys=True))
    usage = db.summarize_model_usage(run_id, config)
    if usage["calls"]:
        processed = (
            usage["input_tokens"] + usage["output_tokens"]
            + usage["cache_read_tokens"] + usage["cache_write_tokens"]
        )
        typer.echo(
            f"model usage: calls={usage['calls']}; processed-tokens={processed}; "
            f"input={usage['input_tokens']}; output={usage['output_tokens']}; "
            f"cache-read={usage['cache_read_tokens']}; "
            f"cache-write={usage['cache_write_tokens']}; "
            f"unknown-usage-calls={usage['unknown_usage_calls']}; "
            f"provider-latency-ms={usage['latency_ms']}"
        )
    else:
        typer.echo("model usage: not recorded")
    chain, chain_usage, _ = db.summarize_model_usage_chain(run_id, config)
    if len(chain) > 1:
        chain_processed = (
            chain_usage["input_tokens"] + chain_usage["output_tokens"]
            + chain_usage["cache_read_tokens"] + chain_usage["cache_write_tokens"]
        )
        typer.echo(
            f"logical scan chain: runs={[run.id for run in chain]}; "
            f"calls={chain_usage['calls']}; processed-tokens={chain_processed}; "
            f"unknown-usage-calls={chain_usage['unknown_usage_calls']}"
        )
    if item.artifacts:
        typer.echo("artifacts: " + ", ".join(item.artifacts))


@app.command()
@_clean_errors("finalize")
def finalize(
    repo_id: str = typer.Argument(..., help="Reviewed repo id to analyze and report."),
    trials: int = typer.Option(50_000, "--trials", help="Monte Carlo trial count."),
    seed: int = typer.Option(0, "--seed", help="RNG seed for reproducibility."),
    record_audit: bool = typer.Option(
        False, "--record-audit",
        help="Persist a versioned SimulationRun and its scenario inputs."
    ),
    print_reports: bool = typer.Option(
        False, "--print-reports", help="Also print both generated Markdown reports to stdout."
    ),
) -> None:
    """After review, quantify risk and write both reports; optionally retain an audit run."""
    config = get_config()
    db.init_db(config)
    deferred = db.list_deferred_findings(repo_id, config)
    if deferred:
        ids = ", ".join(f"#{finding.id}" for finding in deferred[:10])
        suffix = " ..." if len(deferred) > 10 else ""
        typer.secho(
            f"finalize blocked for {repo_id}: {len(deferred)} finding(s) have not been "
            f"falsified yet ({ids}{suffix})",
            fg=typer.colors.RED,
            err=True,
        )
        typer.echo(
            f"Continue the bounded queue with: repoauditor resume {repo_id}",
            err=True,
        )
        raise typer.Exit(code=1)
    _run_step("review checkpoint", lambda: raise_review_requests(repo_id, config))
    requests = open_review_requests(repo_id, config)
    if requests:
        ids = ", ".join(
            f"#{request.id} (finding #{request.finding_id})" for request in requests
        )
        typer.secho(
            f"finalize blocked for {repo_id}: {len(requests)} open review request(s): {ids}",
            fg=typer.colors.RED,
            err=True,
        )
        typer.echo(f"Review them with: repoauditor review list {repo_id}", err=True)
        raise typer.Exit(code=1)

    quantification = _run_step(
        "quantify",
        lambda: _quantify_stage(
            repo_id, config, trials=trials, seed=seed, record_audit=record_audit
        ),
    )
    engineering_paths = _run_step(
        "engineering report",
        lambda: _report_stage(
            repo_id, config, ReportMode.ENGINEERING, print_report=print_reports
        ),
    )
    memo_paths = _run_step(
        "memo report",
        lambda: _report_stage(
            repo_id, config, ReportMode.MEMO, quantification=quantification,
            print_report=print_reports,
        ),
    )
    paths = [*(engineering_paths or []), *(memo_paths or [])]
    typer.echo(
        f"finalize complete for {repo_id}: wrote "
        + (", ".join(str(path) for path in paths) if paths else "quantitative appendix and both reports")
    )


@review_app.command("list")
@_clean_errors("review list")
def review_list(
    repo_id: str = typer.Argument(..., help="Repo id to list open review requests for."),
    output_format: ListFormat = typer.Option(
        ListFormat.HUMAN, "--format", help="Output format: human or json."
    ),
) -> None:
    """Show open review requests (held findings) with their evidence summary."""
    config = get_config()
    if output_format is ListFormat.JSON:
        typer.echo(review_requests_json(open_review_requests(repo_id, config)))
    else:
        typer.echo(render_open_requests(repo_id, config))


@review_app.command("decide")
@_clean_errors("review decide")
def review_decide(
    repo_id: str = typer.Argument(..., help="Repo id the review request belongs to."),
    request_id: int = typer.Argument(..., help="ReviewRequest id (from `review list`)."),
    decision: ReviewDisposition = typer.Option(
        ..., "--decision", help="confirm (release to analysis) | dismiss (withhold)."
    ),
    rationale: str = typer.Option(..., "--rationale", help="Why — mandatory, audited."),
    reviewer: str = typer.Option(
        None, "--reviewer", help="Who is ruling (defaults to the current OS user)."
    ),
) -> None:
    """Record an append-only review decision on a held finding."""
    try:
        result = decide(
            repo_id, request_id, decision, rationale,
            reviewer or getpass.getuser(), get_config(),
        )
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(
        f"recorded decision #{result.id}: {result.disposition} on request "
        f"#{request_id} by {result.reviewer}"
    )


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()
