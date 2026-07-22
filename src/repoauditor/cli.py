"""Thin CLI. Parses arguments and calls library functions — zero business logic.

This boundary is architectural (see CLAUDE.md): commands here only marshal arguments
and print results. All real work lives in the stage packages. Stages that are still
stubbed raise `NotImplementedError`, which is surfaced here as a clean message rather
than a traceback.
"""

from __future__ import annotations

import getpass
from enum import StrEnum

import typer

from pathlib import Path

from . import __version__
from .analyze import generate_appendix
from .config import get_config
from .detect import run_ensemble
from .falsify import challenge
from .ingest import ingest_repo, snapshot_manifests
from .map import recover_architecture
from .report import build_backlog, build_memo
from .review import decide, render_open_requests
from .store import db
from .store.models import ReviewDisposition
from .triage import label_finding, triage_repo

app = typer.Typer(
    help="repoauditor — audit an acquired codebase: ingest, map, detect, falsify, report.",
    no_args_is_help=True,
    add_completion=False,
)
db_app = typer.Typer(help="Database commands.", no_args_is_help=True)
app.add_typer(db_app, name="db")
review_app = typer.Typer(help="Human-review checkpoint commands.", no_args_is_help=True)
app.add_typer(review_app, name="review")


class ReportMode(StrEnum):
    ENGINEERING = "engineering"
    MEMO = "memo"


class LabelDisposition(StrEnum):
    """Analyst disposition for `triage-label` — the ground-truth call on a finding."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"


def _stub_guard(fn, *args, **kwargs):
    """Call a stage function, turning a stubbed NotImplementedError into a clean exit."""
    try:
        return fn(*args, **kwargs)
    except NotImplementedError as exc:
        typer.secho(f"not yet implemented: {exc}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(code=2)


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
):
    if version:
        typer.echo(f"repoauditor {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@db_app.command("init")
def db_init() -> None:
    """Create/upgrade the SQLite schema by applying pending migrations."""
    applied = db.init_db(get_config())
    if applied:
        typer.echo(f"applied migrations: {', '.join(applied)}")
    else:
        typer.echo("schema already up to date")


@app.command()
def ingest(source: str = typer.Argument(..., help="Git URL or local repo/dir to ingest.")) -> None:
    """Clone/snapshot a target repo (idempotent, keyed by commit hash)."""
    config = get_config()
    result = ingest_repo(source, config)
    manifests = snapshot_manifests(result.snapshot_path, result.repo_id, result.commit)
    status = "reused (no-op)" if result.reused else "ingested"
    typer.echo(
        f"{status}: repo_id={result.repo_id} commit={result.commit} "
        f"manifests={len(manifests.manifests)} -> {result.snapshot_path}"
    )


@app.command()
def map(repo_id: str = typer.Argument(..., help="Ingested repo id.")) -> None:
    """Recover the architecture/trust-boundary map (runs before detection)."""
    config = get_config()
    _stub_guard(recover_architecture, config.raw_dir / repo_id, repo_id, "HEAD", config)


@app.command()
def detect(repo_id: str = typer.Argument(..., help="Ingested + mapped repo id.")) -> None:
    """Run the multi-lens detection ensemble + deterministic tools."""
    _stub_guard(run_ensemble, repo_id, get_config())


@app.command()
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
    outcome = _stub_guard(
        triage_repo, repo_id, get_config(), sarif_path=sarif, action_threshold=threshold
    )
    eval_on = outcome.evaluations[0].eval_on if outcome.evaluations else "synthetic"
    evals = "  ".join(
        f"{e.model_name}(AP={e.average_precision:.2f},Brier={e.brier:.2f})"
        for e in outcome.evaluations
    )
    typer.echo(
        f"triaged {len(outcome.ranked)} findings for {repo_id}: model={outcome.model_name} "
        f"[{evals}] eval_on={eval_on} suppressed={outcome.n_suppressed}"
    )
    synth = "dropped" if outcome.synthetic_dropped else f"{outcome.synthetic_share:.0%}"
    typer.echo(
        f"  labels: real={outcome.n_real_labels}  synthetic_share={synth} "
        f"(shrinks as real labels accumulate)"
    )
    for r in outcome.ranked[:10]:
        flag = " (suppressed)" if r.suppressed else ""
        top = ", ".join(a["feature"] for a in r.attributions)
        typer.echo(f"  #{r.rank} p={r.p_actionable:.2f}{flag} — top: {top}")


@app.command(name="triage-label")
def triage_label(
    finding_id: int = typer.Argument(..., help="Finding id to label (from `triage` output)."),
    disposition: LabelDisposition = typer.Option(
        ..., "--disposition", help="true_positive | false_positive (analyst ground truth)."
    ),
    note: str = typer.Option(None, "--note", help="Optional analyst note."),
) -> None:
    """Assert a manual analyst label on a finding (overrides any derived label)."""
    try:
        label = label_finding(
            finding_id,
            disposition is LabelDisposition.TRUE_POSITIVE,
            note,
            get_config(),
        )
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    verdict = "true positive" if label.actionable else "false positive"
    typer.echo(
        f"labelled finding #{finding_id} as {verdict} (rule {label.rule_id}, "
        f"engagement {label.engagement}) — manual label takes precedence over derived."
    )


@app.command()
def quantify(
    repo_id: str = typer.Argument(..., help="Repo id with triaged/falsified findings."),
    trials: int = typer.Option(50_000, "--trials", help="Monte Carlo trial count."),
    seed: int = typer.Option(0, "--seed", help="RNG seed for reproducibility."),
) -> None:
    """Run a FAIR-style Monte Carlo risk simulation and write the findings appendix."""
    path = _stub_guard(generate_appendix, repo_id, get_config(), trials=trials, seed=seed)
    typer.echo(f"wrote risk appendix -> {path}")


@app.command()
def falsify(repo_id: str = typer.Argument(..., help="Repo id with candidate findings.")) -> None:
    """Run the falsification pass over candidate findings."""
    _stub_guard(challenge, repo_id, get_config())


@app.command()
def report(
    repo_id: str = typer.Argument(..., help="Repo id to report on."),
    mode: ReportMode = typer.Option(
        ReportMode.ENGINEERING, "--mode", help="Projection to produce."
    ),
    record_audit: bool = typer.Option(
        False, "--record-audit",
        help="memo only: persist the backing SimulationRun as an audit trail "
             "(additive logging; never mutates findings/severity).",
    ),
) -> None:
    """Project the findings store into an engineering backlog or a leadership memo."""
    config = get_config()
    if mode is ReportMode.ENGINEERING:
        typer.echo(_stub_guard(build_backlog, repo_id, config))
    else:
        typer.echo(_stub_guard(build_memo, repo_id, config, record_audit=record_audit))


@review_app.command("list")
def review_list(
    repo_id: str = typer.Argument(..., help="Repo id to list open review requests for."),
) -> None:
    """Show open review requests (held findings) with their evidence summary."""
    typer.echo(render_open_requests(repo_id, get_config()))


@review_app.command("decide")
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
