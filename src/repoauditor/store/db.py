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
    DealRisk,
    DebatePosition,
    Entity,
    EntityKind,
    EvalRun,
    FalsificationIteration,
    FalsificationStatus,
    Finding,
    PriorSource,
    ReviewDecision,
    ReviewDisposition,
    ReviewRequest,
    RiskScenario,
    RulePrior,
    SimulationRun,
    TriageFeatureRecord,
    TriageLabel,
    TriageLabelSource,
    TriageResult,
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


def insert_finding(finding: Finding, config: Config | None = None) -> int:
    """Persist a finding and its corroborations in one transaction."""
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO finding "
                "(repo_id, title, file, line_start, line_end, citation_snippet, "
                " source_lens, source_tool, confidence, severity, "
                " falsification_status, falsification_reason, trust_boundary_id, "
                " entity_id, description) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding.repo_id,
                    finding.title,
                    finding.file,
                    finding.line_start,
                    finding.line_end,
                    finding.citation_snippet,
                    finding.source_lens,
                    finding.source_tool,
                    finding.confidence,
                    str(finding.severity),
                    str(finding.falsification_status),
                    finding.falsification_reason,
                    finding.trust_boundary_id,
                    finding.entity_id,
                    finding.description,
                ),
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
    """Log an exhausted parse/validation retry from `llm/client.py`."""
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
                "(engagement, rule_id, finding_fingerprint, actionable, note, source) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (engagement, finding_fingerprint) DO UPDATE SET "
                "  rule_id = excluded.rule_id, actionable = excluded.actionable, "
                "  note = excluded.note, source = excluded.source" + guard,
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
            )
            for r in rows
        ]
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
                "(finding_id, engagement, rule_id, fingerprint, features, feature_names) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (finding_id) DO UPDATE SET "
                "  engagement = excluded.engagement, rule_id = excluded.rule_id, "
                "  fingerprint = excluded.fingerprint, features = excluded.features, "
                "  feature_names = excluded.feature_names",
                (
                    record.finding_id,
                    record.engagement,
                    record.rule_id,
                    record.fingerprint,
                    json.dumps(record.features),
                    json.dumps(record.feature_names),
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
) -> list[tuple[list[float], list[str], bool]]:
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
            "SELECT tf.features, tf.feature_names, tl.actionable "
            "FROM triage_label tl "
            "JOIN triage_features tf "
            "  ON tf.engagement = tl.engagement "
            " AND tf.fingerprint = tl.finding_fingerprint "
            "ORDER BY tl.id"
        ).fetchall()
        return [
            (json.loads(r["features"]), json.loads(r["feature_names"]), bool(r["actionable"]))
            for r in rows
        ]
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


def upsert_triage_result(result: TriageResult, config: Config | None = None) -> int:
    """Persist the triage verdict for a finding (idempotent per finding_id).

    Ranking/suppression annotation only — the underlying finding row is untouched, so
    nothing is ever deleted by triage.
    """
    conn = get_connection(config)
    try:
        with conn:
            cur = conn.execute(
                "INSERT INTO triage_result "
                "(finding_id, p_actionable, rank, suppressed, model_name, attributions) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (finding_id) DO UPDATE SET "
                "  p_actionable = excluded.p_actionable, rank = excluded.rank, "
                "  suppressed = excluded.suppressed, model_name = excluded.model_name, "
                "  attributions = excluded.attributions",
                (
                    result.finding_id,
                    result.p_actionable,
                    result.rank,
                    int(result.suppressed),
                    result.model_name,
                    json.dumps(result.attributions),
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
                "INSERT INTO prior_source (kind, param_path, source, detail) "
                "VALUES (?, ?, ?, ?)",
                (ps.kind, ps.param_path, ps.source, ps.detail),
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
                "(repo_id, name, finding_ids, frequency_lambda, magnitude_mu, "
                " magnitude_sigma, frequency_source, magnitude_source, p_actionable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scenario.repo_id,
                    scenario.name,
                    json.dumps(scenario.finding_ids),
                    scenario.frequency_lambda,
                    scenario.magnitude_mu,
                    scenario.magnitude_sigma,
                    scenario.frequency_source,
                    scenario.magnitude_source,
                    scenario.p_actionable,
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
                repo_id=r["repo_id"],
                name=r["name"],
                finding_ids=json.loads(r["finding_ids"]),
                frequency_lambda=r["frequency_lambda"],
                magnitude_mu=r["magnitude_mu"],
                magnitude_sigma=r["magnitude_sigma"],
                frequency_source=r["frequency_source"],
                magnitude_source=r["magnitude_source"],
                p_actionable=r["p_actionable"],
            )
            for r in rows
        ]
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
    """Persist one severity-adjudication debate (positions + outcome), not just the value."""
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
        with conn:
            cur = conn.execute(
                "INSERT INTO adjudication_debate "
                "(repo_id, file, line_start, line_end, positions, outcome, "
                " resolved_severity, synthesis_rationale) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    debate.repo_id,
                    debate.file,
                    debate.line_start,
                    debate.line_end,
                    json.dumps(positions),
                    debate.outcome,
                    str(debate.resolved_severity) if debate.resolved_severity else None,
                    debate.synthesis_rationale,
                ),
            )
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
                " verdict_confidence, critique_upholds, critique_note, committed) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (finding_id, iteration) DO UPDATE SET "
                "  evidence = excluded.evidence, verdict_status = excluded.verdict_status, "
                "  verdict_rationale = excluded.verdict_rationale, "
                "  verdict_confidence = excluded.verdict_confidence, "
                "  critique_upholds = excluded.critique_upholds, "
                "  critique_note = excluded.critique_note, committed = excluded.committed",
                (
                    iteration.finding_id,
                    iteration.iteration,
                    iteration.evidence,
                    str(iteration.verdict_status),
                    iteration.verdict_rationale,
                    iteration.verdict_confidence,
                    int(iteration.critique_upholds),
                    iteration.critique_note,
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
                committed=bool(r["committed"]),
            )
            for r in rows
        ]
    finally:
        conn.close()
