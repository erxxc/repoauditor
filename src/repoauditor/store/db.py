"""SQLite persistence layer.

This is the ONLY module in repoauditor allowed to open or touch the database.
Every read/write goes through a function here; no other module knows the DB path,
opens a connection, or writes SQL. It owns the migration mechanism too.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from ..config import Config, get_config
from .models import (
    AdjudicationDebate,
    Corroboration,
    ClaimVerification,
    ClaimVerificationStatus,
    ClaimEvidence,
    DealRisk,
    DebatePosition,
    DetectionRegionRun,
    Entity,
    EntityKind,
    EvalRun,
    FalsificationIteration,
    FalsificationStatus,
    Finding,
    IngestedRepo,
    ModelUsage,
    PipelineRun,
    PriorSource,
    ReviewDecision,
    ReviewDisposition,
    ReviewRequest,
    RiskScenario,
    RunStatus,
    ScenarioInput,
    RulePrior,
    SecurityClaim,
    SimulationRun,
    StageRun,
    TriageFeatureRecord,
    TriageAssessment,
    TriageAssessmentOutcome,
    TriageDisposition,
    TriageLabel,
    TriageLabelSource,
    TriageModelRun,
    TriageResult,
    ScoredTriageLabel,
    TrustBoundary,
    ValidationFailure,
)
from ..matching import find_matches  # pure logic (imports only store.models — no cycle)

DDL_DIR = Path(__file__).parent / "ddl"
_MIGRATION_RE = re.compile(r"^(\d+)_.*\.sql$")


# --------------------------------------------------------------------------- #
# Connection
# --------------------------------------------------------------------------- #
def get_connection(config: Config | None = None) -> sqlite3.Connection:
    """Open a connection to the configured database, creating its parent dir.

    Foreign-key enforcement is on and rows come back as `sqlite3.Row`.
    """
    config = config or get_config()
    db_path = config.db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# --------------------------------------------------------------------------- #
# Migrations
# --------------------------------------------------------------------------- #
def _discover_migrations() -> list[tuple[int, Path]]:
    """Return (version, path) for each migration file, sorted by version."""
    migrations: list[tuple[int, Path]] = []
    for path in DDL_DIR.glob("*.sql"):
        match = _MIGRATION_RE.match(path.name)
        if match:
            migrations.append((int(match.group(1)), path))
    migrations.sort(key=lambda item: item[0])
    return migrations


def _applied_versions(conn: sqlite3.Connection) -> set[int]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "  version    INTEGER PRIMARY KEY,"
        "  filename   TEXT NOT NULL,"
        "  applied_at TEXT NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    return {row["version"] for row in rows}


def init_db(config: Config | None = None) -> list[str]:
    """Apply any unapplied migrations. Idempotent; safe to run repeatedly.

    Returns the filenames of migrations applied by this call (empty if none).
    """
    config = config or get_config()
    conn = get_connection(config)
    applied_now: list[str] = []
    try:
        already = _applied_versions(conn)
        for version, path in _discover_migrations():
            if version in already:
                continue
            with conn:  # one transaction per migration
                conn.executescript(path.read_text())
                conn.execute(
                    "INSERT INTO schema_migrations (version, filename) VALUES (?, ?)",
                    (version, path.name),
                )
            applied_now.append(path.name)
    finally:
        conn.close()
    return applied_now


# --------------------------------------------------------------------------- #
# Writes
# --------------------------------------------------------------------------- #
def record_ingested_repo(repo: IngestedRepo, config: Config | None = None) -> None:
    """Record an ingested snapshot, preserving the timestamp of an existing row."""
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "INSERT INTO ingested_repo (repo_id, source, commit_hash) VALUES (?, ?, ?) "
                "ON CONFLICT (repo_id, commit_hash) DO UPDATE SET source = excluded.source",
                (repo.repo_id, repo.source, repo.commit_hash),
            )
    finally:
        conn.close()


def start_pipeline_run(
    source: str, config: Config | None = None, *, parent_run_id: int | None = None
) -> PipelineRun:
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO pipeline_run (source, status, parent_run_id) "
                "VALUES (?, 'running', ?)",
                (source, parent_run_id),
            )
            row = conn.execute("SELECT * FROM pipeline_run WHERE id = ?", (cur.lastrowid,)).fetchone()
        return _pipeline_run_from_row(row)
    finally:
        conn.close()


def update_pipeline_run_identity(
    run_id: int, repo_id: str, commit_hash: str, config: Config | None = None
) -> None:
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "UPDATE pipeline_run SET repo_id = ?, commit_hash = ? WHERE id = ?",
                (repo_id, commit_hash, run_id),
            )
    finally:
        conn.close()


def finish_pipeline_run(
    run_id: int, status: RunStatus, *, failed_stage: str | None = None,
    failure_detail: str | None = None, artifacts: list[str] | None = None,
    config: Config | None = None,
) -> None:
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "UPDATE pipeline_run SET status = ?, completed_at = datetime('now'), "
                "failed_stage = ?, failure_detail = ?, artifacts = ? WHERE id = ?",
                (str(status), failed_stage, failure_detail, json.dumps(artifacts or []), run_id),
            )
    finally:
        conn.close()


def start_stage_run(run_id: int, stage: str, config: Config | None = None) -> StageRun:
    """Start or restart a stage attempt within an existing pipeline run."""
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "INSERT INTO stage_run (pipeline_run_id, stage, status) VALUES (?, ?, 'running') "
                "ON CONFLICT (pipeline_run_id, stage) DO UPDATE SET "
                "status='running', started_at=datetime('now'), completed_at=NULL, "
                "summary='{}', artifacts='[]', failure_detail=NULL",
                (run_id, stage),
            )
            row = conn.execute(
                "SELECT * FROM stage_run WHERE pipeline_run_id = ? AND stage = ?",
                (run_id, stage),
            ).fetchone()
        return _stage_run_from_row(row)
    finally:
        conn.close()


def finish_stage_run(
    run_id: int, stage: str, status: RunStatus, *, summary: dict | None = None,
    artifacts: list[str] | None = None, failure_detail: str | None = None,
    config: Config | None = None,
) -> None:
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "UPDATE stage_run SET status = ?, completed_at = datetime('now'), summary = ?, "
                "artifacts = ?, failure_detail = ? WHERE pipeline_run_id = ? AND stage = ?",
                (str(status), json.dumps(summary or {}), json.dumps(artifacts or []),
                 failure_detail, run_id, stage),
            )
    finally:
        conn.close()


def insert_model_usage(usage: ModelUsage, config: Config | None = None) -> int:
    """Persist provider-reported model usage; callers never estimate missing values."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO model_usage (pipeline_run_id, stage, module, prompt_version, "
                "provider, model, usage_available, input_tokens, output_tokens, "
                "cache_read_tokens, cache_write_tokens, latency_ms) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    usage.pipeline_run_id, usage.stage, usage.module, usage.prompt_version,
                    usage.provider, usage.model, int(usage.usage_available),
                    usage.input_tokens, usage.output_tokens, usage.cache_read_tokens,
                    usage.cache_write_tokens, usage.latency_ms,
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_model_usage(
    config: Config | None = None, *, pipeline_run_id: int | None = None
) -> list[ModelUsage]:
    conn = get_connection(config)
    try:
        if pipeline_run_id is None:
            rows = conn.execute("SELECT * FROM model_usage ORDER BY id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM model_usage WHERE pipeline_run_id = ? ORDER BY id",
                (pipeline_run_id,),
            ).fetchall()
        return [ModelUsage(**dict(row)) for row in rows]
    finally:
        conn.close()


def start_detection_region(
    region: DetectionRegionRun, config: Config | None = None
) -> DetectionRegionRun:
    """Start/restart one region; a completed row is returned unchanged."""
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "INSERT INTO detection_region_run "
                "(repo_id, commit_hash, file, lens, prompt_version, selection_basis, status) "
                "VALUES (?, ?, ?, ?, ?, ?, 'running') "
                "ON CONFLICT(repo_id, commit_hash, file, lens, prompt_version) DO UPDATE SET "
                "selection_basis=excluded.selection_basis, status=CASE "
                "WHEN detection_region_run.status='completed' THEN 'completed' ELSE 'running' END, "
                "started_at=CASE WHEN detection_region_run.status='completed' "
                "THEN detection_region_run.started_at ELSE datetime('now') END, "
                "completed_at=CASE WHEN detection_region_run.status='completed' "
                "THEN detection_region_run.completed_at ELSE NULL END, "
                "failure_detail=CASE WHEN detection_region_run.status='completed' "
                "THEN detection_region_run.failure_detail ELSE NULL END",
                (
                    region.repo_id, region.commit_hash, region.file, region.lens,
                    region.prompt_version, region.selection_basis,
                ),
            )
            row = conn.execute(
                "SELECT * FROM detection_region_run WHERE repo_id=? AND commit_hash=? "
                "AND file=? AND lens=? AND prompt_version=?",
                (
                    region.repo_id, region.commit_hash, region.file, region.lens,
                    region.prompt_version,
                ),
            ).fetchone()
        return DetectionRegionRun(**dict(row))
    finally:
        conn.close()


def finish_detection_region(
    region_id: int,
    status: RunStatus,
    *,
    finding_count: int = 0,
    failure_detail: str | None = None,
    config: Config | None = None,
) -> None:
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "UPDATE detection_region_run SET status=?, finding_count=?, "
                "completed_at=datetime('now'), failure_detail=? WHERE id=?",
                (str(status), finding_count, failure_detail, region_id),
            )
    finally:
        conn.close()


def list_detection_regions(
    repo_id: str,
    commit_hash: str,
    config: Config | None = None,
) -> list[DetectionRegionRun]:
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM detection_region_run WHERE repo_id=? AND commit_hash=? "
            "ORDER BY id",
            (repo_id, commit_hash),
        ).fetchall()
        return [DetectionRegionRun(**dict(row)) for row in rows]
    finally:
        conn.close()


def summarize_model_usage(
    pipeline_run_id: int, config: Config | None = None, *, stage: str | None = None
) -> dict[str, int]:
    """Return authoritative token/call totals for one pipeline run."""
    conn = get_connection(config)
    try:
        query = (
            "SELECT COUNT(*) AS calls, COALESCE(SUM(input_tokens), 0) AS input_tokens, "
            "COALESCE(SUM(output_tokens), 0) AS output_tokens, "
            "COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens, "
            "COALESCE(SUM(cache_write_tokens), 0) AS cache_write_tokens, "
            "COALESCE(SUM(CASE WHEN usage_available = 0 THEN 1 ELSE 0 END), 0) "
            "AS unknown_usage_calls, "
            "COALESCE(SUM(latency_ms), 0) AS latency_ms "
            "FROM model_usage WHERE pipeline_run_id = ?"
        )
        params: tuple = (pipeline_run_id,)
        if stage is not None:
            query += " AND stage = ?"
            params += (stage,)
        row = conn.execute(query, params).fetchone()
        return {key: int(row[key]) for key in row.keys()}
    finally:
        conn.close()


def list_pipeline_runs(
    config: Config | None = None, *, repo_id: str | None = None
) -> list[PipelineRun]:
    conn = get_connection(config)
    try:
        if repo_id is None:
            rows = conn.execute("SELECT * FROM pipeline_run ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM pipeline_run WHERE repo_id = ? ORDER BY id DESC", (repo_id,)
            ).fetchall()
        return [_pipeline_run_from_row(row) for row in rows]
    finally:
        conn.close()


def get_pipeline_run(run_id: int, config: Config | None = None) -> PipelineRun | None:
    conn = get_connection(config)
    try:
        row = conn.execute("SELECT * FROM pipeline_run WHERE id = ?", (run_id,)).fetchone()
        return _pipeline_run_from_row(row) if row else None
    finally:
        conn.close()


def get_latest_pipeline_run(
    repo_id: str, config: Config | None = None, *, commit_hash: str | None = None
) -> PipelineRun | None:
    """Return the newest run record for a repository, regardless of status."""
    conn = get_connection(config)
    try:
        if commit_hash is None:
            row = conn.execute(
                "SELECT * FROM pipeline_run WHERE repo_id = ? ORDER BY id DESC LIMIT 1",
                (repo_id,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM pipeline_run WHERE repo_id = ? AND commit_hash = ? "
                "ORDER BY id DESC LIMIT 1",
                (repo_id, commit_hash),
            ).fetchone()
        return _pipeline_run_from_row(row) if row else None
    finally:
        conn.close()


def list_pipeline_run_chain(
    run_id: int, config: Config | None = None
) -> list[PipelineRun]:
    """Return one logical scan's linked batches, root first; fail on a broken cycle."""
    chain: list[PipelineRun] = []
    seen: set[int] = set()
    current = get_pipeline_run(run_id, config)
    while current is not None:
        if current.id is None or current.id in seen:
            raise ValueError(f"invalid pipeline continuation chain at run #{run_id}")
        seen.add(current.id)
        chain.append(current)
        if current.parent_run_id is None:
            break
        current = get_pipeline_run(current.parent_run_id, config)
    return list(reversed(chain))


def summarize_model_usage_chain(
    run_id: int, config: Config | None = None
) -> tuple[list[PipelineRun], dict[str, int], list[dict[str, int]]]:
    """Aggregate authoritative usage over a linked continuation chain."""
    chain = list_pipeline_run_chain(run_id, config)
    per_run = [summarize_model_usage(item.id, config) for item in chain]
    keys = (
        "calls", "input_tokens", "output_tokens", "cache_read_tokens",
        "cache_write_tokens", "unknown_usage_calls", "latency_ms",
    )
    totals = {key: sum(item[key] for item in per_run) for key in keys}
    return chain, totals, per_run


def find_resumable_pipeline_run(
    source: str, config: Config | None = None
) -> PipelineRun | None:
    conn = get_connection(config)
    try:
        row = conn.execute(
            "SELECT * FROM pipeline_run WHERE source = ? AND status != 'completed' "
            "ORDER BY id DESC LIMIT 1", (source,),
        ).fetchone()
        return _pipeline_run_from_row(row) if row else None
    finally:
        conn.close()


def resume_pipeline_run(run_id: int, config: Config | None = None) -> None:
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "UPDATE pipeline_run SET status='running', completed_at=NULL, failed_stage=NULL, "
                "failure_detail=NULL WHERE id = ?", (run_id,),
            )
    finally:
        conn.close()


def list_stage_runs(run_id: int, config: Config | None = None) -> list[StageRun]:
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM stage_run WHERE pipeline_run_id = ? ORDER BY id", (run_id,)
        ).fetchall()
        return [_stage_run_from_row(row) for row in rows]
    finally:
        conn.close()


def _pipeline_run_from_row(row: sqlite3.Row) -> PipelineRun:
    values = dict(row)
    values["artifacts"] = json.loads(values["artifacts"])
    return PipelineRun(**values)


def _stage_run_from_row(row: sqlite3.Row) -> StageRun:
    values = dict(row)
    values["summary"] = json.loads(values["summary"])
    values["artifacts"] = json.loads(values["artifacts"])
    return StageRun(**values)


def list_ingested_repos(
    config: Config | None = None, *, all_snapshots: bool = True
) -> list[IngestedRepo]:
    """List ingested snapshots, newest first.

    When ``all_snapshots`` is false, return only the most recently ingested
    snapshot for each source repository. ``rowid`` breaks ties between SQLite's
    one-second timestamps deterministically.
    """
    conn = get_connection(config)
    try:
        if all_snapshots:
            query = (
                "SELECT repo_id, source, commit_hash, ingested_at FROM ingested_repo "
                "ORDER BY ingested_at DESC, rowid DESC, repo_id, commit_hash"
            )
        else:
            query = (
                "SELECT repo_id, source, commit_hash, ingested_at FROM ("
                " SELECT repo_id, source, commit_hash, ingested_at, rowid,"
                " ROW_NUMBER() OVER (PARTITION BY source ORDER BY ingested_at DESC, rowid DESC) AS n"
                " FROM ingested_repo"
                ") WHERE n = 1 ORDER BY ingested_at DESC, rowid DESC, repo_id, commit_hash"
            )
        rows = conn.execute(query).fetchall()
        return [IngestedRepo(**dict(row)) for row in rows]
    finally:
        conn.close()


def get_latest_ingested_repo(
    repo_id: str, config: Config | None = None
) -> IngestedRepo | None:
    """Return the newest immutable snapshot record for one repository id."""
    conn = get_connection(config)
    try:
        row = conn.execute(
            "SELECT repo_id, source, commit_hash, ingested_at FROM ingested_repo "
            "WHERE repo_id = ? ORDER BY ingested_at DESC, rowid DESC LIMIT 1",
            (repo_id,),
        ).fetchone()
        return IngestedRepo(**dict(row)) if row else None
    finally:
        conn.close()


def insert_trust_boundary(tb: TrustBoundary, config: Config | None = None) -> int:
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO trust_boundary (repo_id, name, description) "
                "VALUES (?, ?, ?)",
                (tb.repo_id, tb.name, tb.description),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def upsert_trust_boundary(tb: TrustBoundary, config: Config | None = None) -> int:
    """Insert or refresh a map boundary, idempotent on (repo_id, name)."""
    conn = get_connection(config)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT id FROM trust_boundary WHERE repo_id = ? AND name = ? ORDER BY id LIMIT 1",
            (tb.repo_id, tb.name),
        ).fetchone()
        if row is not None:
            conn.execute(
                "UPDATE trust_boundary SET description = ? WHERE id = ?",
                (tb.description, row["id"]),
            )
            conn.commit()
            return int(row["id"])
        cur = conn.execute(
            "INSERT INTO trust_boundary (repo_id, name, description) VALUES (?, ?, ?)",
            (tb.repo_id, tb.name, tb.description),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def insert_entity(entity: Entity, config: Config | None = None) -> int:
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO entity "
                "(repo_id, kind, name, location, trust_boundary_id, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    entity.repo_id,
                    str(entity.kind),
                    entity.name,
                    entity.location,
                    entity.trust_boundary_id,
                    json.dumps(entity.metadata) if entity.metadata else None,
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def upsert_entity(entity: Entity, config: Config | None = None) -> int:
    """Insert or refresh a map entity on its stable repo/kind/name/location identity."""
    conn = get_connection(config)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT id FROM entity WHERE repo_id = ? AND kind = ? AND name = ? "
            "AND location IS ? ORDER BY id LIMIT 1",
            (entity.repo_id, str(entity.kind), entity.name, entity.location),
        ).fetchone()
        metadata = json.dumps(entity.metadata) if entity.metadata else None
        if row is not None:
            conn.execute(
                "UPDATE entity SET trust_boundary_id = ?, metadata = ? WHERE id = ?",
                (entity.trust_boundary_id, metadata, row["id"]),
            )
            conn.commit()
            return int(row["id"])
        cur = conn.execute(
            "INSERT INTO entity "
            "(repo_id, kind, name, location, trust_boundary_id, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (entity.repo_id, str(entity.kind), entity.name, entity.location,
             entity.trust_boundary_id, metadata),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def insert_finding(finding: Finding, config: Config | None = None) -> int:
    """Persist a finding and its corroborations in one transaction."""
    conn = get_connection(config)
    try:
        with conn:
            values = (
                finding.repo_id, finding.title, finding.file, finding.line_start,
                finding.line_end, finding.citation_snippet,
            )
            tail = (
                finding.source_lens, finding.source_tool, finding.confidence,
                str(finding.severity), str(finding.falsification_status),
                finding.falsification_reason, finding.trust_boundary_id,
                finding.entity_id, finding.description,
            )
            if "identity_key" in {
                row["name"] for row in conn.execute("PRAGMA table_info(finding)")
            }:
                cur = conn.execute(
                    "INSERT INTO finding "
                    "(repo_id, title, file, line_start, line_end, citation_snippet, identity_key, "
                    " source_lens, source_tool, confidence, severity, falsification_status, "
                    " falsification_reason, trust_boundary_id, entity_id, description) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (*values, finding.identity_key, *tail),
                )
            else:
                # Migration tests intentionally exercise historical schemas through the
                # current store API. A keyed finding cannot be represented before 0021.
                if finding.identity_key is not None:
                    raise RuntimeError("finding identity requires migration 0021")
                cur = conn.execute(
                    "INSERT INTO finding "
                    "(repo_id, title, file, line_start, line_end, citation_snippet, "
                    " source_lens, source_tool, confidence, severity, falsification_status, "
                    " falsification_reason, trust_boundary_id, entity_id, description) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (*values, *tail),
                )
            finding_id = int(cur.lastrowid)
            for corr in finding.corroborated_by:
                conn.execute(
                    "INSERT INTO corroboration "
                    "(finding_id, source_type, source_name, note, score, match_basis) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (finding_id, str(corr.source_type), corr.source_name, corr.note,
                     corr.score, corr.match_basis),
                )
        return finding_id
    finally:
        conn.close()


def upsert_detected_finding(finding: Finding, config: Config | None = None) -> int:
    """Persist a detector result once, preserving downstream verdicts on rerun.

    The natural identity excludes mutable confidence/severity/status fields. A repeated
    detector pass returns the existing row instead of resetting falsification or normalized
    severity state. `BEGIN IMMEDIATE` makes the read-then-insert safe across concurrent CLI
    processes despite the legacy schema having no corresponding UNIQUE constraint.
    """
    conn = get_connection(config)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT id FROM finding WHERE repo_id = ? AND source_lens IS ? "
            "AND source_tool IS ? AND file = ? AND line_start = ? AND line_end = ? "
            "AND title = ? AND citation_snippet = ? AND identity_key IS ? "
            "ORDER BY id LIMIT 1",
            (
                finding.repo_id, finding.source_lens, finding.source_tool, finding.file,
                finding.line_start, finding.line_end, finding.title,
                finding.citation_snippet, finding.identity_key,
            ),
        ).fetchone()
        if row is not None:
            conn.commit()
            return int(row["id"])
        cur = conn.execute(
            "INSERT INTO finding "
            "(repo_id, title, file, line_start, line_end, citation_snippet, identity_key, "
            " source_lens, source_tool, confidence, severity, falsification_status, "
            " falsification_reason, trust_boundary_id, entity_id, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.repo_id, finding.title, finding.file, finding.line_start,
                finding.line_end, finding.citation_snippet, finding.identity_key,
                finding.source_lens,
                finding.source_tool, finding.confidence, str(finding.severity),
                str(finding.falsification_status), finding.falsification_reason,
                finding.trust_boundary_id, finding.entity_id, finding.description,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #
def _hydrate_findings(conn: sqlite3.Connection, rows: list[sqlite3.Row]) -> list[Finding]:
    """Turn `finding` rows into models, attaching each one's corroborations."""
    findings: list[Finding] = []
    for row in rows:
        corr_rows = conn.execute(
            "SELECT * FROM corroboration WHERE finding_id = ? ORDER BY id",
            (row["id"],),
        ).fetchall()
        corroborations = [
            Corroboration(
                id=c["id"],
                finding_id=c["finding_id"],
                source_type=c["source_type"],
                source_name=c["source_name"],
                note=c["note"],
                score=c["score"],
                match_basis=c["match_basis"],
            )
            for c in corr_rows
        ]
        findings.append(
            Finding(
                id=row["id"],
                repo_id=row["repo_id"],
                title=row["title"],
                file=row["file"],
                line_start=row["line_start"],
                line_end=row["line_end"],
                citation_snippet=row["citation_snippet"],
                identity_key=row["identity_key"] if "identity_key" in row.keys() else None,
                source_lens=row["source_lens"],
                source_tool=row["source_tool"],
                confidence=row["confidence"],
                severity=row["severity"],
                falsification_status=row["falsification_status"],
                falsification_reason=row["falsification_reason"],
                trust_boundary_id=row["trust_boundary_id"],
                entity_id=row["entity_id"],
                description=row["description"],
                corroborated_by=corroborations,
            )
        )
    return findings


def list_findings(repo_id: str | None = None, config: Config | None = None) -> list[Finding]:
    """Read findings (optionally scoped to a repo), with corroborations attached.

    This is the read API the report stage projects from — reports never touch the
    DB directly, they call here.
    """
    conn = get_connection(config)
    try:
        if repo_id is None:
            rows = conn.execute("SELECT * FROM finding ORDER BY id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM finding WHERE repo_id = ? ORDER BY id", (repo_id,)
            ).fetchall()
        return _hydrate_findings(conn, rows)
    finally:
        conn.close()


def list_deferred_findings(
    repo_id: str, config: Config | None = None
) -> list[Finding]:
    """Return findings not yet examined because they fell outside a falsify budget."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM finding WHERE repo_id = ? AND falsification_status = ? "
            "ORDER BY id",
            (repo_id, str(FalsificationStatus.DEFERRED)),
        ).fetchall()
        return _hydrate_findings(conn, rows)
    finally:
        conn.close()


def get_finding(finding_id: int, config: Config | None = None) -> Finding | None:
    """Read a single finding by id (with corroborations), or None if it doesn't exist.

    Used by the manual triage-label path to validate the target and resolve its engagement.
    """
    conn = get_connection(config)
    try:
        rows = conn.execute("SELECT * FROM finding WHERE id = ?", (finding_id,)).fetchall()
        hydrated = _hydrate_findings(conn, rows)
        return hydrated[0] if hydrated else None
    finally:
        conn.close()


def list_analyzable_findings(repo_id: str, config: Config | None = None) -> list[Finding]:
    """Findings the analyze stage is allowed to consume — the review gate applied.

    This is the query an analyze-style stage uses instead of `list_findings`: it drops
    findings blocked at the human-review checkpoint. A finding is blocked when it has a
    `review_request` whose *effective* (most recent) decision is not `confirm` — i.e.
    no decision yet, or a `dismiss`. `killed` findings are excluded (analyze's own
    null-result handling), and so are `deferred` ones — a deferred finding fell outside a
    falsify run's budget and has not been examined yet, so it must never be mistaken for
    an analysis-ready verdict. Everything with no review request passes through
    unchanged, so review-clean pipelines behave exactly as before.
    """
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT f.* FROM finding f "
            "WHERE f.repo_id = ? "
            "  AND f.falsification_status NOT IN (?, ?) "
            "  AND NOT EXISTS ("
            "    SELECT 1 FROM review_request rr "
            "    WHERE rr.finding_id = f.id "
            "      AND COALESCE("
            "        (SELECT rd.disposition FROM review_decision rd "
            "         WHERE rd.review_request_id = rr.id ORDER BY rd.id DESC LIMIT 1), "
            "        '__open__') != ? "
            "  ) "
            "ORDER BY f.id",
            (repo_id, str(FalsificationStatus.KILLED), str(FalsificationStatus.DEFERRED),
             str(ReviewDisposition.CONFIRM)),
        ).fetchall()
        return _hydrate_findings(conn, rows)
    finally:
        conn.close()


def list_countable_findings(repo_id: str, config: Config | None = None) -> list[Finding]:
    """Analyzable findings collapsed to one row per matched issue — the *countable* set.

    When several sources flag the same underlying issue, normalize/adjudicate.py resolves
    them into one representative but leaves the non-representative rows in place (they are
    still evidence of what each source found, per store/'s never-delete discipline). A
    consumer that counts *issues* — `analyze/risk_quant.build_scenarios`, and later
    `report/` — must therefore not treat those rows as N separate findings.

    Design decision — Option B (read-side view), not Option A (a persisted `superseded_by`
    status). Rationale, recorded here so future sessions don't re-derive it:
      * No schema change and no write to existing rows — de-duplication is computed on read
        from the shared `matching.find_matches`, which is deterministic on the finding set
        (see tests/test_matching.py::test_matching_is_deterministic_on_the_finding_set), so
        it always reflects the same grouping normalize used. store/ writes stay append-only.
      * It composes the review gate: it de-duplicates the *analyzable* set
        (`list_analyzable_findings` already drops killed/deferred/review-blocked), returning
        one representative (highest-confidence member) per match group.
      * Nothing is hidden: every row is still returned by `list_findings` — this is a
        counting view, not a soft-delete. `list_findings` remains the raw, complete read.
    A merged group's non-representative rows are simply not among the representatives, so
    they can no longer be double-counted downstream.
    """
    analyzable = list_analyzable_findings(repo_id, config)
    return [group.representative for group in find_matches(analyzable).groups]


def update_falsification(
    finding_id: int,
    status: FalsificationStatus,
    reason: str,
    config: Config | None = None,
) -> None:
    """Record a falsification verdict for a finding.

    Killed findings are updated in place (not deleted) with their status and the
    reason they were killed — explicit null-result logging, so nothing disappears.
    """
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "UPDATE finding SET falsification_status = ?, falsification_reason = ? "
                "WHERE id = ?",
                (str(status), reason, finding_id),
            )
    finally:
        conn.close()


def apply_adjudication(finding: Finding, config: Config | None = None) -> None:
    """Persist a normalize/ adjudication: the representative's resolved severity + status,
    plus its cross-source corroborations, in one transaction.

    This is how a corroboration-licensed severity upgrade becomes *final before review/* —
    review/ reads the store, so the resolved severity must be written here (at normalize
    time), not left in memory. The finding row is updated in place (keyed by id); the
    corroborations are upserted (idempotent). store/ owns this write — normalize calls it.
    """
    if finding.id is None:
        raise ValueError("apply_adjudication requires a persisted finding (id is None)")
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "UPDATE finding SET severity = ?, falsification_status = ? WHERE id = ?",
                (str(finding.severity), str(finding.falsification_status), finding.id),
            )
            for corr in finding.corroborated_by:
                conn.execute(
                    "INSERT INTO corroboration "
                    "(finding_id, source_type, source_name, note, score, match_basis) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT (finding_id, source_type, source_name) DO UPDATE SET "
                    "  note = COALESCE(excluded.note, corroboration.note), "
                    "  score = COALESCE(excluded.score, corroboration.score), "
                    "  match_basis = COALESCE(excluded.match_basis, corroboration.match_basis)",
                    (finding.id, str(corr.source_type), corr.source_name, corr.note,
                     corr.score, corr.match_basis),
                )
    finally:
        conn.close()


def add_corroboration(corr: Corroboration, config: Config | None = None) -> int:
    """Record that another lens/tool independently flagged an existing finding.

    Idempotent per (finding_id, source_type, source_name) via the UNIQUE constraint. When
    the same corroborator is re-recorded with a freshly computed score/match_basis (e.g. the
    analyze pass augmenting a normalize-written row), `ON CONFLICT ... DO UPDATE` refreshes
    the score/basis rather than silently dropping it — so the analyze corroboration score is
    never lost to an INSERT OR IGNORE no-op.
    """
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO corroboration "
                "(finding_id, source_type, source_name, note, score, match_basis) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (finding_id, source_type, source_name) DO UPDATE SET "
                "  note = COALESCE(excluded.note, corroboration.note), "
                "  score = COALESCE(excluded.score, corroboration.score), "
                "  match_basis = COALESCE(excluded.match_basis, corroboration.match_basis)",
                (corr.finding_id, str(corr.source_type), corr.source_name, corr.note,
                 corr.score, corr.match_basis),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_trust_boundaries(
    repo_id: str, config: Config | None = None
) -> list[TrustBoundary]:
    """Read the trust boundaries recovered by the map stage for a repo."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM trust_boundary WHERE repo_id = ? ORDER BY id", (repo_id,)
        ).fetchall()
        return [
            TrustBoundary(
                id=r["id"],
                repo_id=r["repo_id"],
                name=r["name"],
                description=r["description"],
            )
            for r in rows
        ]
    finally:
        conn.close()


def list_entities(repo_id: str, config: Config | None = None) -> list[Entity]:
    """Read the architectural entities (entry points, data stores, …) for a repo."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM entity WHERE repo_id = ? ORDER BY id", (repo_id,)
        ).fetchall()
        return [
            Entity(
                id=r["id"],
                repo_id=r["repo_id"],
                kind=EntityKind(r["kind"]),
                name=r["name"],
                location=r["location"],
                trust_boundary_id=r["trust_boundary_id"],
                metadata=json.loads(r["metadata"]) if r["metadata"] else None,
            )
            for r in rows
        ]
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Reliability layer: validation failures + eval runs
# --------------------------------------------------------------------------- #
def insert_validation_failure(vf: ValidationFailure, config: Config | None = None) -> int:
    """Log an exhausted parse/schema retry or semantic citation failure."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO validation_failure "
                "(module, prompt_version, raw_response, validation_error) "
                "VALUES (?, ?, ?, ?)",
                (vf.module, vf.prompt_version, vf.raw_response, vf.validation_error),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_validation_failures(config: Config | None = None) -> list[ValidationFailure]:
    """Read the logged validation failures (reliability trail)."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM validation_failure ORDER BY id"
        ).fetchall()
        return [
            ValidationFailure(
                id=r["id"],
                module=r["module"],
                prompt_version=r["prompt_version"],
                raw_response=r["raw_response"],
                validation_error=r["validation_error"],
            )
            for r in rows
        ]
    finally:
        conn.close()


def insert_eval_run(run: EvalRun, config: Config | None = None) -> int:
    """Persist one golden-harness execution's metrics for regression gating."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO eval_run "
                "(lineage, prompt_versions, precision, recall, regressed_from_prior) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    run.lineage,
                    json.dumps(run.prompt_versions, sort_keys=True),
                    run.precision,
                    run.recall,
                    int(run.regressed_from_prior),
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def last_eval_run(lineage: str, config: Config | None = None) -> EvalRun | None:
    """Return the most recent prior `EvalRun` for a lineage, or None if first ever."""
    conn = get_connection(config)
    try:
        row = conn.execute(
            "SELECT * FROM eval_run WHERE lineage = ? ORDER BY id DESC LIMIT 1",
            (lineage,),
        ).fetchone()
        if row is None:
            return None
        return EvalRun(
            id=row["id"],
            lineage=row["lineage"],
            prompt_versions=json.loads(row["prompt_versions"]),
            precision=row["precision"],
            recall=row["recall"],
            regressed_from_prior=bool(row["regressed_from_prior"]),
        )
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Triage layer: analyst labels + per-rule priors
# --------------------------------------------------------------------------- #
def upsert_triage_label(
    label: TriageLabel, config: Config | None = None, *, protect_manual: bool = False
) -> int:
    """Record a disposition on a finding (idempotent per engagement+fingerprint).

    The cross-engagement label store the triage classifier trains on. Re-labelling the
    same finding within an engagement overwrites the prior disposition rather than
    duplicating it.

    `protect_manual=True` (used by the derivation pass) adds a `WHERE source != 'manual'`
    guard to the upsert so a *derived* label can never clobber an analyst's manual one —
    the manual-precedence rule enforced at the persistence layer. The manual path leaves
    it False so an analyst can always overwrite (including correcting a prior manual call).
    """
    conn = get_connection(config)
    guard = " WHERE triage_label.source != 'manual'" if protect_manual else ""
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO triage_label "
                "(engagement, rule_id, finding_fingerprint, actionable, note, source, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, datetime('now')) "
                "ON CONFLICT (engagement, finding_fingerprint) DO UPDATE SET "
                "  rule_id = excluded.rule_id, actionable = excluded.actionable, "
                "  note = excluded.note, source = excluded.source, "
                "  updated_at = datetime('now')" + guard,
                (
                    label.engagement,
                    label.rule_id,
                    label.finding_fingerprint,
                    int(label.actionable),
                    label.note,
                    str(label.source),
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_triage_labels(
    rule_id: str | None = None, config: Config | None = None
) -> list[TriageLabel]:
    """Read labels, optionally scoped to one rule (for per-rule FP history)."""
    conn = get_connection(config)
    try:
        if rule_id is None:
            rows = conn.execute("SELECT * FROM triage_label ORDER BY id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM triage_label WHERE rule_id = ? ORDER BY id", (rule_id,)
            ).fetchall()
        return [
            TriageLabel(
                id=r["id"],
                engagement=r["engagement"],
                rule_id=r["rule_id"],
                finding_fingerprint=r["finding_fingerprint"],
                actionable=bool(r["actionable"]),
                source=TriageLabelSource(r["source"]),
                note=r["note"],
                created_at=r["created_at"],
                updated_at=r["updated_at"],
            )
            for r in rows
        ]
    finally:
        conn.close()


def delete_triage_label_projection(
    engagement: str,
    finding_fingerprint: str,
    config: Config | None = None,
) -> None:
    """Remove an effective training projection while retaining assessment evidence."""
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "DELETE FROM triage_label "
                "WHERE engagement = ? AND finding_fingerprint = ?",
                (engagement, finding_fingerprint),
            )
    finally:
        conn.close()


def insert_triage_assessment(
    assessment: TriageAssessment, config: Config | None = None
) -> int:
    """Append an analyst assessment; corrections remain visible as later rows."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO triage_assessment "
                "(finding_id, engagement, outcome, disposition, rationale, analyst, "
                " material, classifier_eligible, dimensions) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    assessment.finding_id, assessment.engagement, str(assessment.outcome),
                    str(assessment.disposition) if assessment.disposition else None,
                    assessment.rationale, assessment.analyst,
                    int(assessment.material), int(assessment.classifier_eligible),
                    json.dumps(assessment.dimensions),
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_triage_assessments(
    repo_id: str | None = None, config: Config | None = None
) -> list[TriageAssessment]:
    """Read append-only analyst assessments, optionally for one engagement."""
    conn = get_connection(config)
    try:
        if repo_id is None:
            rows = conn.execute("SELECT * FROM triage_assessment ORDER BY id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM triage_assessment WHERE engagement = ? ORDER BY id",
                (repo_id,),
            ).fetchall()
        return [TriageAssessment(
            id=row["id"], finding_id=row["finding_id"], engagement=row["engagement"],
            outcome=TriageAssessmentOutcome(row["outcome"]), rationale=row["rationale"],
            disposition=(
                TriageDisposition(row["disposition"]) if row["disposition"] else None
            ),
            analyst=row["analyst"], material=bool(row["material"]),
            classifier_eligible=bool(row["classifier_eligible"]),
            dimensions=json.loads(row["dimensions"]),
            created_at=row["created_at"],
        ) for row in rows]
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Triage feature bridge: the join between accumulated labels and training rows
# --------------------------------------------------------------------------- #
def upsert_triage_features(
    record: TriageFeatureRecord, config: Config | None = None
) -> int:
    """Persist the triaged feature vector for a finding (idempotent per finding_id).

    Written once per finding at triage time; re-running triage refreshes the vector. This
    is the only place a finding's numeric feature row is durably kept, so a label collected
    later (manual or derived) can be rejoined to real features for cross-engagement training.
    """
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO triage_features "
                "(finding_id, engagement, rule_id, fingerprint, features, feature_names, "
                " detector, detector_source, language, language_source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (finding_id) DO UPDATE SET "
                "  engagement = excluded.engagement, rule_id = excluded.rule_id, "
                "  fingerprint = excluded.fingerprint, features = excluded.features, "
                "  feature_names = excluded.feature_names, detector = excluded.detector, "
                "  detector_source = excluded.detector_source, language = excluded.language, "
                "  language_source = excluded.language_source",
                (
                    record.finding_id,
                    record.engagement,
                    record.rule_id,
                    record.fingerprint,
                    json.dumps(record.features),
                    json.dumps(record.feature_names),
                    record.detector,
                    record.detector_source,
                    record.language,
                    record.language_source,
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def _triage_feature_record_from_row(row: sqlite3.Row) -> TriageFeatureRecord:
    return TriageFeatureRecord(
        finding_id=row["finding_id"],
        engagement=row["engagement"],
        rule_id=row["rule_id"],
        fingerprint=row["fingerprint"],
        features=json.loads(row["features"]),
        feature_names=json.loads(row["feature_names"]),
        detector=row["detector"],
        detector_source=row["detector_source"],
        language=row["language"],
        language_source=row["language_source"],
    )


def get_triage_features(
    finding_id: int, config: Config | None = None
) -> TriageFeatureRecord | None:
    """Read the triaged feature row for a finding (used by the manual-label path)."""
    conn = get_connection(config)
    try:
        row = conn.execute(
            "SELECT * FROM triage_features WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return _triage_feature_record_from_row(row) if row is not None else None
    finally:
        conn.close()


def list_triage_features(config: Config | None = None) -> list[TriageFeatureRecord]:
    """Read every triaged feature row (keyed by finding, spanning engagements)."""
    conn = get_connection(config)
    try:
        rows = conn.execute("SELECT * FROM triage_features ORDER BY finding_id").fetchall()
        return [_triage_feature_record_from_row(r) for r in rows]
    finally:
        conn.close()


def list_real_training_examples(
    config: Config | None = None,
) -> list[tuple[list[float], list[str], bool, str, TriageLabelSource]]:
    """Join accumulated labels to their triaged features → real (features, names, label) rows.

    The cross-engagement real training corpus: every `triage_label` that has a matching
    `triage_features` row (same engagement + fingerprint) becomes one labelled feature
    vector. `feature_names` travels with each row so the caller can drop rows whose schema
    no longer matches the current `FEATURE_NAMES` instead of mis-aligning columns. Manual
    and derived labels are both included — precedence is resolved when the label is written
    (a manual label overwrites the derived row for the same finding), so at read time each
    finding contributes exactly one, already-authoritative, row.
    """
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT tf.features, tf.feature_names, tl.actionable, tl.engagement, tl.source "
            "FROM triage_label tl "
            "JOIN triage_features tf "
            "  ON tf.engagement = tl.engagement "
            " AND tf.fingerprint = tl.finding_fingerprint "
            "ORDER BY tl.id"
        ).fetchall()
        return [
            (json.loads(r["features"]), json.loads(r["feature_names"]),
             bool(r["actionable"]), r["engagement"], TriageLabelSource(r["source"]))
            for r in rows
        ]
    finally:
        conn.close()


def list_scored_triage_labels(
    config: Config | None = None, *, repo_id: str | None = None,
) -> list[ScoredTriageLabel]:
    """Real labels joined to every historical P(actionable) scoring pass."""
    conn = get_connection(config)
    try:
        where = " WHERE tl.engagement = ?" if repo_id else ""
        params = (repo_id,) if repo_id else ()
        rows = conn.execute(
            "SELECT ts.p_actionable, tl.actionable, tl.engagement, tl.source, "
            " ts.triage_run_id, ts.scored_at, tmr.model_name, tmr.model_version, "
            " tmr.feature_schema_version, tmr.calibration "
            "FROM triage_label tl "
            "JOIN triage_features tf ON tf.engagement = tl.engagement "
            " AND tf.fingerprint = tl.finding_fingerprint "
            "JOIN triage_score ts ON ts.finding_id = tf.finding_id "
            "JOIN triage_model_run tmr ON tmr.id = ts.triage_run_id" + where +
            " ORDER BY tl.id, ts.id",
            params,
        ).fetchall()
        return [ScoredTriageLabel(
            p_actionable=float(row["p_actionable"]), actionable=bool(row["actionable"]),
            engagement=row["engagement"], label_source=TriageLabelSource(row["source"]),
            triage_run_id=row["triage_run_id"], scored_at=row["scored_at"],
            model_name=row["model_name"], model_version=row["model_version"],
            feature_schema_version=row["feature_schema_version"],
            calibration=row["calibration"],
        ) for row in rows]
    finally:
        conn.close()


def review_dispositions(
    repo_id: str, config: Config | None = None
) -> dict[int, ReviewDisposition]:
    """Effective (most-recent) review disposition per finding for a repo.

    Only findings with a review request *and* at least one decision appear. Used by the
    triage label-derivation pass so a human confirm/dismiss can override the automated
    falsify verdict when turning outcomes into labels.
    """
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT rr.finding_id AS fid, ("
            "  SELECT rd.disposition FROM review_decision rd "
            "  WHERE rd.review_request_id = rr.id ORDER BY rd.id DESC LIMIT 1"
            ") AS disposition "
            "FROM review_request rr WHERE rr.repo_id = ?",
            (repo_id,),
        ).fetchall()
        return {
            r["fid"]: ReviewDisposition(r["disposition"])
            for r in rows
            if r["disposition"] is not None
        }
    finally:
        conn.close()


def upsert_rule_prior(prior: RulePrior, config: Config | None = None) -> int:
    """Persist (or update) the Beta-Binomial hyperparameters for a rule."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO rule_prior "
                "(rule_id, alpha, beta, observed_actionable, observed_total, "
                " prior_source, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, datetime('now')) "
                "ON CONFLICT (rule_id) DO UPDATE SET "
                "  alpha = excluded.alpha, beta = excluded.beta, "
                "  observed_actionable = excluded.observed_actionable, "
                "  observed_total = excluded.observed_total, "
                "  prior_source = excluded.prior_source, updated_at = datetime('now')",
                (
                    prior.rule_id,
                    prior.alpha,
                    prior.beta,
                    prior.observed_actionable,
                    prior.observed_total,
                    prior.prior_source,
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def get_rule_prior(rule_id: str, config: Config | None = None) -> RulePrior | None:
    """Read the persisted Beta-Binomial prior for a rule, or None if never stored."""
    conn = get_connection(config)
    try:
        row = conn.execute(
            "SELECT * FROM rule_prior WHERE rule_id = ?", (rule_id,)
        ).fetchone()
        if row is None:
            return None
        return RulePrior(
            id=row["id"],
            rule_id=row["rule_id"],
            alpha=row["alpha"],
            beta=row["beta"],
            observed_actionable=row["observed_actionable"],
            observed_total=row["observed_total"],
            prior_source=row["prior_source"],
        )
    finally:
        conn.close()


def insert_triage_model_run(
    run: TriageModelRun, config: Config | None = None
) -> int:
    """Persist one immutable classifier fit/score provenance record."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO triage_model_run "
                "(repo_id, model_name, model_version, feature_schema_version, "
                " training_label_count, evaluation_label_count, label_source_counts, "
                " synthetic_share, synthetic_dropped, calibration, evaluation_basis, "
                " split_strategy, split_detail, evaluations, scanner_versions) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run.repo_id, run.model_name, run.model_version,
                    run.feature_schema_version, run.training_label_count,
                    run.evaluation_label_count, json.dumps(run.label_source_counts),
                    run.synthetic_share, int(run.synthetic_dropped), run.calibration,
                    run.evaluation_basis, run.split_strategy, run.split_detail,
                    json.dumps(run.evaluations), json.dumps(run.scanner_versions),
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_triage_model_runs(
    repo_id: str | None = None, config: Config | None = None
) -> list[TriageModelRun]:
    conn = get_connection(config)
    try:
        if repo_id is None:
            rows = conn.execute("SELECT * FROM triage_model_run ORDER BY id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM triage_model_run WHERE repo_id = ? ORDER BY id", (repo_id,)
            ).fetchall()
        return [TriageModelRun(
            id=row["id"], repo_id=row["repo_id"], model_name=row["model_name"],
            model_version=row["model_version"],
            feature_schema_version=row["feature_schema_version"],
            training_label_count=row["training_label_count"],
            evaluation_label_count=row["evaluation_label_count"],
            label_source_counts=json.loads(row["label_source_counts"]),
            synthetic_share=row["synthetic_share"],
            synthetic_dropped=bool(row["synthetic_dropped"]),
            calibration=row["calibration"], evaluation_basis=row["evaluation_basis"],
            split_strategy=row["split_strategy"], split_detail=row["split_detail"],
            evaluations=json.loads(row["evaluations"]),
            scanner_versions=json.loads(row["scanner_versions"]),
            created_at=row["created_at"],
        ) for row in rows]
    finally:
        conn.close()


def upsert_triage_result(result: TriageResult, config: Config | None = None) -> int:
    """Persist a historical score and update the latest verdict for a finding.

    `triage_score` is append-only provenance; `triage_result` is the idempotent latest-state
    projection used by downstream stages. The underlying finding row remains untouched.
    """
    if result.triage_run_id is None:
        raise ValueError("triage_run_id is required when persisting a triage result")
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "INSERT INTO triage_score "
                "(finding_id, triage_run_id, p_actionable, rank, suppressed) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    result.finding_id,
                    result.triage_run_id,
                    result.p_actionable,
                    result.rank,
                    int(result.suppressed),
                ),
            )
            cur = conn.execute(
                "INSERT INTO triage_result "
                "(finding_id, p_actionable, rank, suppressed, model_name, attributions, "
                " triage_run_id, scored_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now')) "
                "ON CONFLICT (finding_id) DO UPDATE SET "
                "  p_actionable = excluded.p_actionable, rank = excluded.rank, "
                "  suppressed = excluded.suppressed, model_name = excluded.model_name, "
                "  attributions = excluded.attributions, triage_run_id = excluded.triage_run_id, "
                "  scored_at = datetime('now')",
                (
                    result.finding_id,
                    result.p_actionable,
                    result.rank,
                    int(result.suppressed),
                    result.model_name,
                    json.dumps(result.attributions),
                    result.triage_run_id,
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_triage_results(repo_id: str, config: Config | None = None) -> list[TriageResult]:
    """Read triage verdicts for a repo's findings, best-ranked first."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT tr.* FROM triage_result tr "
            "JOIN finding f ON f.id = tr.finding_id "
            "WHERE f.repo_id = ? ORDER BY tr.rank",
            (repo_id,),
        ).fetchall()
        return [
            TriageResult(
                id=r["id"],
                finding_id=r["finding_id"],
                p_actionable=r["p_actionable"],
                rank=r["rank"],
                suppressed=bool(r["suppressed"]),
                model_name=r["model_name"],
                attributions=json.loads(r["attributions"]),
                triage_run_id=r["triage_run_id"],
                scored_at=r["scored_at"],
            )
            for r in rows
        ]
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Analyze stage: deal-risk weighting (sidecar annotation, never overwrites a finding)
# --------------------------------------------------------------------------- #
def upsert_deal_risk(dr: DealRisk, config: Config | None = None) -> int:
    """Persist the deal-risk weighting for a finding (idempotent per finding_id).

    A weighting annotation only — the underlying finding row (and its technical severity)
    is untouched, so deal-risk re-weighting never overwrites the technical assessment.
    """
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO deal_risk "
                "(finding_id, weight, band, production_exposure, remediation_category, "
                " rep_warranty_category, rep_warranty_relevant, severity_component, "
                " exposure_component, remediation_component, rep_warranty_component, rationale) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (finding_id) DO UPDATE SET "
                "  weight = excluded.weight, band = excluded.band, "
                "  production_exposure = excluded.production_exposure, "
                "  remediation_category = excluded.remediation_category, "
                "  rep_warranty_category = excluded.rep_warranty_category, "
                "  rep_warranty_relevant = excluded.rep_warranty_relevant, "
                "  severity_component = excluded.severity_component, "
                "  exposure_component = excluded.exposure_component, "
                "  remediation_component = excluded.remediation_component, "
                "  rep_warranty_component = excluded.rep_warranty_component, "
                "  rationale = excluded.rationale",
                (
                    dr.finding_id, dr.weight, dr.band, dr.production_exposure,
                    dr.remediation_category, dr.rep_warranty_category,
                    int(dr.rep_warranty_relevant), dr.severity_component,
                    dr.exposure_component, dr.remediation_component,
                    dr.rep_warranty_component, dr.rationale,
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_deal_risk(repo_id: str, config: Config | None = None) -> list[DealRisk]:
    """Read deal-risk weightings for a repo's findings, heaviest first."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT dr.* FROM deal_risk dr "
            "JOIN finding f ON f.id = dr.finding_id "
            "WHERE f.repo_id = ? ORDER BY dr.weight DESC, dr.finding_id",
            (repo_id,),
        ).fetchall()
        return [
            DealRisk(
                id=r["id"],
                finding_id=r["finding_id"],
                weight=r["weight"],
                band=r["band"],
                production_exposure=r["production_exposure"],
                remediation_category=r["remediation_category"],
                rep_warranty_category=r["rep_warranty_category"],
                rep_warranty_relevant=bool(r["rep_warranty_relevant"]),
                severity_component=r["severity_component"],
                exposure_component=r["exposure_component"],
                remediation_component=r["remediation_component"],
                rep_warranty_component=r["rep_warranty_component"],
                rationale=r["rationale"],
            )
            for r in rows
        ]
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Risk-quantification layer: prior sources, scenarios, simulation runs
# --------------------------------------------------------------------------- #
def insert_prior_source(ps: PriorSource, config: Config | None = None) -> int:
    """Record provenance for one distribution parameter (enforces no unsourced priors)."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO prior_source (kind, param_path, source, detail, publication, "
                " edition, locator, url, transformation, provenance_status, "
                " target_population, effective_date, data_vintage, "
                " aleatory_representation, epistemic_status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ps.kind, ps.param_path, ps.source, ps.detail, ps.publication,
                 ps.edition, ps.locator, ps.url, ps.transformation, ps.provenance_status,
                 ps.target_population, ps.effective_date, ps.data_vintage,
                 ps.aleatory_representation, ps.epistemic_status),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_prior_sources(config: Config | None = None) -> list[PriorSource]:
    """Read the provenance trail for risk-quant priors."""
    conn = get_connection(config)
    try:
        rows = conn.execute("SELECT * FROM prior_source ORDER BY id").fetchall()
        return [
            PriorSource(
                id=r["id"],
                kind=r["kind"],
                param_path=r["param_path"],
                source=r["source"],
                detail=r["detail"],
                publication=r["publication"],
                edition=r["edition"],
                locator=r["locator"],
                url=r["url"],
                transformation=r["transformation"],
                provenance_status=r["provenance_status"],
                target_population=r["target_population"],
                effective_date=r["effective_date"],
                data_vintage=r["data_vintage"],
                aleatory_representation=r["aleatory_representation"],
                epistemic_status=r["epistemic_status"],
            )
            for r in rows
        ]
    finally:
        conn.close()


def insert_risk_scenario(scenario: RiskScenario, config: Config | None = None) -> int:
    """Persist a FAIR-style loss scenario and its finding membership."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO risk_scenario "
                "(simulation_run_id, repo_id, name, finding_ids, frequency_lambda, magnitude_mu, "
                " magnitude_sigma, frequency_source, magnitude_source, p_actionable, "
                " validity_probabilities, validity_sources, conditional_frequency_lambdas, "
                " conditional_frequency_source, threat_signal_labels, "
                " exposure_factors, control_strengths, loss_scale) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scenario.simulation_run_id,
                    scenario.repo_id,
                    scenario.name,
                    json.dumps(scenario.finding_ids),
                    scenario.frequency_lambda,
                    scenario.magnitude_mu,
                    scenario.magnitude_sigma,
                    scenario.frequency_source,
                    scenario.magnitude_source,
                    scenario.p_actionable,
                    json.dumps(scenario.validity_probabilities),
                    json.dumps(scenario.validity_sources),
                    json.dumps(scenario.conditional_frequency_lambdas),
                    scenario.conditional_frequency_source,
                    json.dumps(scenario.threat_signal_labels),
                    json.dumps(scenario.exposure_factors),
                    json.dumps(scenario.control_strengths),
                    scenario.loss_scale,
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_risk_scenarios(repo_id: str, config: Config | None = None) -> list[RiskScenario]:
    """Read the loss scenarios modelled for a repo."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM risk_scenario WHERE repo_id = ? ORDER BY id", (repo_id,)
        ).fetchall()
        return [
            RiskScenario(
                id=r["id"],
                simulation_run_id=r["simulation_run_id"],
                repo_id=r["repo_id"],
                name=r["name"],
                finding_ids=json.loads(r["finding_ids"]),
                frequency_lambda=r["frequency_lambda"],
                magnitude_mu=r["magnitude_mu"],
                magnitude_sigma=r["magnitude_sigma"],
                frequency_source=r["frequency_source"],
                magnitude_source=r["magnitude_source"],
                p_actionable=r["p_actionable"],
                validity_probabilities=json.loads(r["validity_probabilities"]),
                validity_sources=json.loads(r["validity_sources"]),
                conditional_frequency_lambdas=json.loads(r["conditional_frequency_lambdas"]),
                conditional_frequency_source=r["conditional_frequency_source"],
                threat_signal_labels=json.loads(r["threat_signal_labels"]),
                exposure_factors=json.loads(r["exposure_factors"]),
                control_strengths=json.loads(r["control_strengths"]),
                loss_scale=r["loss_scale"],
            )
            for r in rows
        ]
    finally:
        conn.close()


def insert_scenario_input(value: ScenarioInput, config: Config | None = None) -> int:
    """Persist or refresh one transparent per-engagement scenario input."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO scenario_input (risk_scenario_id, repo_id, scenario_name, "
                " input_name, value, origin, source, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (risk_scenario_id, input_name) DO UPDATE SET value=excluded.value, "
                "origin=excluded.origin, source=excluded.source, detail=excluded.detail",
                (value.risk_scenario_id, value.repo_id, value.scenario_name,
                 value.input_name, value.value, value.origin, value.source, value.detail),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_scenario_inputs(
    repo_id: str, config: Config | None = None
) -> list[ScenarioInput]:
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM scenario_input WHERE repo_id = ? ORDER BY risk_scenario_id, input_name",
            (repo_id,),
        ).fetchall()
        return [ScenarioInput(**dict(row)) for row in rows]
    finally:
        conn.close()


def insert_simulation_run(run: SimulationRun, config: Config | None = None) -> int:
    """Persist one Monte Carlo run's loss-distribution summary + sensitivity output."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO simulation_run "
                "(repo_id, trials, mean_loss, median_loss, p95_loss, "
                " scenario_summary, tornado, seed) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run.repo_id,
                    run.trials,
                    run.mean_loss,
                    run.median_loss,
                    run.p95_loss,
                    json.dumps(run.scenario_summary),
                    json.dumps(run.tornado),
                    run.seed,
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def link_risk_scenarios_to_simulation(
    scenario_ids: list[int], simulation_run_id: int, config: Config | None = None
) -> None:
    """Attach one quantification pass's scenario snapshots to its audit run."""
    if not scenario_ids:
        return
    conn = get_connection(config)
    try:
        with conn:
            placeholders = ", ".join("?" for _ in scenario_ids)
            conn.execute(
                f"UPDATE risk_scenario SET simulation_run_id = ? "
                f"WHERE id IN ({placeholders})",
                (simulation_run_id, *scenario_ids),
            )
    finally:
        conn.close()


def list_simulation_runs(repo_id: str, config: Config | None = None) -> list[SimulationRun]:
    """Read the Monte Carlo runs recorded for a repo (newest last)."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM simulation_run WHERE repo_id = ? ORDER BY id", (repo_id,)
        ).fetchall()
        return [
            SimulationRun(
                id=r["id"],
                repo_id=r["repo_id"],
                trials=r["trials"],
                mean_loss=r["mean_loss"],
                median_loss=r["median_loss"],
                p95_loss=r["p95_loss"],
                scenario_summary=json.loads(r["scenario_summary"]),
                tornado=json.loads(r["tornado"]),
                seed=r["seed"],
                created_at=r["created_at"],
            )
            for r in rows
        ]
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Review layer: blocking checkpoint requests + append-only decisions
# --------------------------------------------------------------------------- #
def upsert_review_request(request: ReviewRequest, config: Config | None = None) -> int:
    """Open (or refresh) the review request for a finding (idempotent per finding_id).

    Re-running the checkpoint over the same finding updates the reason/evidence rather
    than opening a duplicate request. Recording a decision is a separate call.
    """
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO review_request "
                "(repo_id, finding_id, stage, reason, evidence) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (finding_id) DO UPDATE SET "
                "  repo_id = excluded.repo_id, stage = excluded.stage, "
                "  reason = excluded.reason, evidence = excluded.evidence",
                (
                    request.repo_id,
                    request.finding_id,
                    request.stage,
                    request.reason,
                    json.dumps(request.evidence),
                ),
            )
            row = conn.execute(
                "SELECT id FROM review_request WHERE finding_id = ?",
                (request.finding_id,),
            ).fetchone()
        return int(row["id"])
    finally:
        conn.close()


def _review_request_from_row(row: sqlite3.Row) -> ReviewRequest:
    return ReviewRequest(
        id=row["id"],
        repo_id=row["repo_id"],
        finding_id=row["finding_id"],
        stage=row["stage"],
        reason=row["reason"],
        evidence=json.loads(row["evidence"]),
    )


def get_review_request(finding_id: int, config: Config | None = None) -> ReviewRequest | None:
    """Read the review request for a finding, or None if it was never held for review."""
    conn = get_connection(config)
    try:
        row = conn.execute(
            "SELECT * FROM review_request WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return _review_request_from_row(row) if row is not None else None
    finally:
        conn.close()


def get_review_request_by_id(
    request_id: int, config: Config | None = None
) -> ReviewRequest | None:
    """Read a review request by its own id (used to validate a decision target)."""
    conn = get_connection(config)
    try:
        row = conn.execute(
            "SELECT * FROM review_request WHERE id = ?", (request_id,)
        ).fetchone()
        return _review_request_from_row(row) if row is not None else None
    finally:
        conn.close()


def list_review_requests(repo_id: str, config: Config | None = None) -> list[ReviewRequest]:
    """Read every review request opened for a repo (newest schema order by id)."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM review_request WHERE repo_id = ? ORDER BY id", (repo_id,)
        ).fetchall()
        return [_review_request_from_row(r) for r in rows]
    finally:
        conn.close()


def insert_review_decision(decision: ReviewDecision, config: Config | None = None) -> int:
    """Append a reviewer's ruling. Append-only: there is deliberately no update path.

    A correction is a new decision row whose `supersedes_id` points at the ruling it
    overrides — the history is never mutated. Returns the new decision's id.
    """
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO review_decision "
                "(review_request_id, disposition, reviewer, rationale, supersedes_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    decision.review_request_id,
                    str(decision.disposition),
                    decision.reviewer,
                    decision.rationale,
                    decision.supersedes_id,
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def _review_decision_from_row(row: sqlite3.Row) -> ReviewDecision:
    return ReviewDecision(
        id=row["id"],
        review_request_id=row["review_request_id"],
        disposition=ReviewDisposition(row["disposition"]),
        reviewer=row["reviewer"],
        rationale=row["rationale"],
        supersedes_id=row["supersedes_id"],
        created_at=row["created_at"],
    )


def list_review_decisions(
    review_request_id: int, config: Config | None = None
) -> list[ReviewDecision]:
    """Full ruling history for a request, oldest first (the append-only audit trail)."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM review_decision WHERE review_request_id = ? ORDER BY id",
            (review_request_id,),
        ).fetchall()
        return [_review_decision_from_row(r) for r in rows]
    finally:
        conn.close()


def latest_review_decision(
    review_request_id: int, config: Config | None = None
) -> ReviewDecision | None:
    """The effective (most recent) ruling for a request, or None if undecided."""
    conn = get_connection(config)
    try:
        row = conn.execute(
            "SELECT * FROM review_decision WHERE review_request_id = ? "
            "ORDER BY id DESC LIMIT 1",
            (review_request_id,),
        ).fetchone()
        return _review_decision_from_row(row) if row is not None else None
    finally:
        conn.close()


def get_review_decision_by_id(
    decision_id: int, config: Config | None = None
) -> ReviewDecision | None:
    """Read a single review decision by id (used to build a correction that supersedes it)."""
    conn = get_connection(config)
    try:
        row = conn.execute(
            "SELECT * FROM review_decision WHERE id = ?", (decision_id,)
        ).fetchone()
        return _review_decision_from_row(row) if row is not None else None
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Normalize layer: persisted severity-adjudication debate trail
# --------------------------------------------------------------------------- #
def insert_adjudication_debate(debate: AdjudicationDebate, config: Config | None = None) -> int:
    """Persist the current debate for a region, idempotently.

    Normalize and review already identify a debate by repo + exact region. Re-running
    normalize refreshes that record rather than appending an indistinguishable duplicate.
    """
    conn = get_connection(config)
    try:
        positions = [
            {
                "source_type": str(p.source_type),
                "source_name": p.source_name,
                "severity": str(p.severity),
                "reasoning": p.reasoning,
            }
            for p in debate.positions
        ]
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT id FROM adjudication_debate WHERE repo_id = ? AND file = ? "
            "AND line_start = ? AND line_end = ? ORDER BY id LIMIT 1",
            (debate.repo_id, debate.file, debate.line_start, debate.line_end),
        ).fetchone()
        values = (
            json.dumps(positions), debate.outcome,
            str(debate.resolved_severity) if debate.resolved_severity else None,
            debate.synthesis_rationale,
        )
        if row is not None:
            conn.execute(
                "UPDATE adjudication_debate SET positions = ?, outcome = ?, "
                "resolved_severity = ?, synthesis_rationale = ? WHERE id = ?",
                (*values, row["id"]),
            )
            conn.commit()
            return int(row["id"])
        cur = conn.execute(
            "INSERT INTO adjudication_debate "
            "(repo_id, file, line_start, line_end, positions, outcome, "
            " resolved_severity, synthesis_rationale) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                debate.repo_id, debate.file, debate.line_start, debate.line_end,
                *values,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _adjudication_debate_from_row(row: sqlite3.Row) -> AdjudicationDebate:
    return AdjudicationDebate(
        id=row["id"],
        repo_id=row["repo_id"],
        file=row["file"],
        line_start=row["line_start"],
        line_end=row["line_end"],
        positions=[DebatePosition(**p) for p in json.loads(row["positions"])],
        outcome=row["outcome"],
        resolved_severity=row["resolved_severity"],
        synthesis_rationale=row["synthesis_rationale"],
    )


def get_adjudication_debate_for_region(
    repo_id: str, file: str, line_start: int, line_end: int, config: Config | None = None
) -> AdjudicationDebate | None:
    """Most recent debate persisted for an exact finding region, or None."""
    conn = get_connection(config)
    try:
        row = conn.execute(
            "SELECT * FROM adjudication_debate "
            "WHERE repo_id = ? AND file = ? AND line_start = ? AND line_end = ? "
            "ORDER BY id DESC LIMIT 1",
            (repo_id, file, line_start, line_end),
        ).fetchone()
        return _adjudication_debate_from_row(row) if row is not None else None
    finally:
        conn.close()


def list_adjudication_debates(
    repo_id: str, config: Config | None = None
) -> list[AdjudicationDebate]:
    """Read every persisted adjudication debate for a repo."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM adjudication_debate WHERE repo_id = ? ORDER BY id", (repo_id,)
        ).fetchall()
        return [_adjudication_debate_from_row(r) for r in rows]
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Falsify layer: bounded-loop iteration trace
# --------------------------------------------------------------------------- #
def insert_falsification_iteration(
    iteration: FalsificationIteration, config: Config | None = None
) -> int:
    """Log one round of the bounded falsification loop (idempotent per finding+iteration)."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO falsification_iteration "
                "(finding_id, iteration, evidence, verdict_status, verdict_rationale, "
                " verdict_confidence, critique_upholds, critique_note, "
                " counterexample_witness, counterexample_verification, committed) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (finding_id, iteration) DO UPDATE SET "
                "  evidence = excluded.evidence, verdict_status = excluded.verdict_status, "
                "  verdict_rationale = excluded.verdict_rationale, "
                "  verdict_confidence = excluded.verdict_confidence, "
                "  critique_upholds = excluded.critique_upholds, "
                "  critique_note = excluded.critique_note, "
                "  counterexample_witness = excluded.counterexample_witness, "
                "  counterexample_verification = excluded.counterexample_verification, "
                "  committed = excluded.committed",
                (
                    iteration.finding_id,
                    iteration.iteration,
                    iteration.evidence,
                    str(iteration.verdict_status),
                    iteration.verdict_rationale,
                    iteration.verdict_confidence,
                    int(iteration.critique_upholds),
                    iteration.critique_note,
                    (
                        json.dumps(iteration.counterexample_witness)
                        if iteration.counterexample_witness is not None else None
                    ),
                    (
                        json.dumps(iteration.counterexample_verification)
                        if iteration.counterexample_verification is not None else None
                    ),
                    int(iteration.committed),
                ),
            )
        return int(cur.lastrowid)
    finally:
        conn.close()


def finding_ids_with_iterations(repo_id: str, config: Config | None = None) -> set[int]:
    """Ids of a repo's findings the falsify loop has already examined (>=1 logged round).

    The falsify budget uses this to tell a candidate it has *not yet* processed (fresh
    from detect, or deferred by a prior run — no iteration rows) from one it already
    escalated to `unresolved` (has rows), so a resumed run never re-challenges a finding
    that already ran the loop.
    """
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT DISTINCT fi.finding_id FROM falsification_iteration fi "
            "JOIN finding f ON f.id = fi.finding_id WHERE f.repo_id = ?",
            (repo_id,),
        ).fetchall()
        return {row["finding_id"] for row in rows}
    finally:
        conn.close()


def list_falsification_iterations(
    finding_id: int, config: Config | None = None
) -> list[FalsificationIteration]:
    """Read the logged iteration trace for a finding, in round order."""
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM falsification_iteration WHERE finding_id = ? ORDER BY iteration",
            (finding_id,),
        ).fetchall()
        return [
            FalsificationIteration(
                id=r["id"],
                finding_id=r["finding_id"],
                iteration=r["iteration"],
                evidence=r["evidence"],
                verdict_status=r["verdict_status"],
                verdict_rationale=r["verdict_rationale"],
                verdict_confidence=r["verdict_confidence"],
                critique_upholds=bool(r["critique_upholds"]),
                critique_note=r["critique_note"],
                counterexample_witness=(
                    json.loads(r["counterexample_witness"])
                    if r["counterexample_witness"] else None
                ),
                counterexample_verification=(
                    json.loads(r["counterexample_verification"])
                    if r["counterexample_verification"] else None
                ),
                committed=bool(r["committed"]),
            )
            for r in rows
        ]
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Falsify layer: structured claims + deterministic verification
# --------------------------------------------------------------------------- #
def upsert_security_claim(
    claim: SecurityClaim, config: Config | None = None
) -> int:
    """Persist one claim version per finding, refreshing its deterministic evidence."""
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "INSERT INTO security_claim "
                "(finding_id, claim_version, snapshot_commit, mechanism, language, "
                " entry_evidence, caller_evidence, authorization_evidence, "
                " registration_evidence, source_evidence, sink_evidence, "
                " path_nodes, path_predicates, control_candidate, producer_type, "
                " producer_name, prompt_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (finding_id, claim_version) DO UPDATE SET "
                "snapshot_commit=excluded.snapshot_commit, mechanism=excluded.mechanism, "
                "language=excluded.language, "
                "entry_evidence=excluded.entry_evidence, "
                "caller_evidence=excluded.caller_evidence, "
                "authorization_evidence=excluded.authorization_evidence, "
                "registration_evidence=excluded.registration_evidence, "
                "source_evidence=excluded.source_evidence, "
                "sink_evidence=excluded.sink_evidence, path_nodes=excluded.path_nodes, "
                "path_predicates=excluded.path_predicates, "
                "control_candidate=excluded.control_candidate, "
                "producer_type=excluded.producer_type, producer_name=excluded.producer_name, "
                "prompt_version=excluded.prompt_version",
                (
                    claim.finding_id,
                    claim.claim_version,
                    claim.snapshot_commit,
                    claim.mechanism,
                    claim.language,
                    json.dumps([item.model_dump() for item in claim.entry_evidence]),
                    json.dumps([item.model_dump() for item in claim.caller_evidence]),
                    json.dumps([
                        item.model_dump() for item in claim.authorization_evidence
                    ]),
                    json.dumps([
                        item.model_dump() for item in claim.registration_evidence
                    ]),
                    json.dumps([item.model_dump() for item in claim.source_evidence]),
                    json.dumps(claim.sink_evidence.model_dump())
                    if claim.sink_evidence else None,
                    json.dumps([item.model_dump() for item in claim.path_nodes]),
                    json.dumps(claim.path_predicates),
                    json.dumps(claim.control_candidate.model_dump())
                    if claim.control_candidate else None,
                    claim.producer_type,
                    claim.producer_name,
                    claim.prompt_version,
                ),
            )
            row = conn.execute(
                "SELECT id FROM security_claim WHERE finding_id = ? AND claim_version = ?",
                (claim.finding_id, claim.claim_version),
            ).fetchone()
        return int(row["id"])
    finally:
        conn.close()


def list_security_claims(
    finding_id: int, config: Config | None = None
) -> list[SecurityClaim]:
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM security_claim WHERE finding_id = ? ORDER BY id",
            (finding_id,),
        ).fetchall()
        return [
            SecurityClaim(
                id=row["id"],
                finding_id=row["finding_id"],
                claim_version=row["claim_version"],
                snapshot_commit=row["snapshot_commit"],
                mechanism=row["mechanism"],
                language=row["language"],
                entry_evidence=[
                    ClaimEvidence(**item) for item in json.loads(row["entry_evidence"])
                ],
                caller_evidence=[
                    ClaimEvidence(**item) for item in json.loads(row["caller_evidence"])
                ],
                authorization_evidence=[
                    ClaimEvidence(**item)
                    for item in json.loads(row["authorization_evidence"])
                ],
                registration_evidence=[
                    ClaimEvidence(**item)
                    for item in json.loads(row["registration_evidence"])
                ],
                source_evidence=[
                    ClaimEvidence(**item) for item in json.loads(row["source_evidence"])
                ],
                sink_evidence=(
                    ClaimEvidence(**json.loads(row["sink_evidence"]))
                    if row["sink_evidence"] else None
                ),
                path_nodes=[
                    ClaimEvidence(**item) for item in json.loads(row["path_nodes"])
                ],
                path_predicates=json.loads(row["path_predicates"]),
                control_candidate=(
                    ClaimEvidence(**json.loads(row["control_candidate"]))
                    if row["control_candidate"] else None
                ),
                producer_type=row["producer_type"],
                producer_name=row["producer_name"],
                prompt_version=row["prompt_version"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
    finally:
        conn.close()


def upsert_claim_verification(
    verification: ClaimVerification, config: Config | None = None
) -> int:
    """Persist one result per claim/verifier version, idempotently."""
    conn = get_connection(config)
    try:
        with conn:
            conn.execute(
                "INSERT INTO claim_verification "
                "(claim_id, status, verifier_name, verifier_version, checks, reason) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (claim_id, verifier_name, verifier_version) DO UPDATE SET "
                "status=excluded.status, checks=excluded.checks, reason=excluded.reason",
                (
                    verification.claim_id,
                    str(verification.status),
                    verification.verifier_name,
                    verification.verifier_version,
                    json.dumps(verification.checks),
                    verification.reason,
                ),
            )
            row = conn.execute(
                "SELECT id FROM claim_verification WHERE claim_id = ? "
                "AND verifier_name = ? AND verifier_version = ?",
                (
                    verification.claim_id,
                    verification.verifier_name,
                    verification.verifier_version,
                ),
            ).fetchone()
        return int(row["id"])
    finally:
        conn.close()


def list_claim_verifications(
    claim_id: int, config: Config | None = None
) -> list[ClaimVerification]:
    conn = get_connection(config)
    try:
        rows = conn.execute(
            "SELECT * FROM claim_verification WHERE claim_id = ? ORDER BY id",
            (claim_id,),
        ).fetchall()
        return [
            ClaimVerification(
                id=row["id"],
                claim_id=row["claim_id"],
                status=ClaimVerificationStatus(row["status"]),
                verifier_name=row["verifier_name"],
                verifier_version=row["verifier_version"],
                checks=json.loads(row["checks"]),
                reason=row["reason"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
    finally:
        conn.close()
