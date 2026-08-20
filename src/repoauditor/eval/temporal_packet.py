"""Outcome-blind selector for the frozen OPT-003 wave-one prediction inventories."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

from ..config import get_config
from ..triage.acquisition_funnel import (
    AcquisitionIdentityInput, ReviewPathTier, classify_review_path,
    exact_location_identity, review_path_tier,
)


POLICY_ID = "opt003-wave1-packet-v1"
EXPECTED_INVENTORY_SHA256 = "213119ccebe71ba3cd7f7c78af7e0c9a3f0d6d7386e058235c6b6dbeab40975a"
SOURCES = {
    "opt003-wave1-chatwoot": {"family": "independent-upstream:chatwoot/chatwoot", "run": 36, "commit": "9a9be2f919662b0408b1910be3a07c3f94fbbc6c", "eligible": 315},
    "opt003-wave1-linkwarden": {"family": "independent-upstream:linkwarden/linkwarden", "run": 37, "commit": "4ce789dfb248a032e0f5a8af580fc3cdbc141c21", "eligible": 17},
    "opt003-wave1-paperless": {"family": "independent-upstream:paperless-ngx/paperless-ngx", "run": 38, "commit": "855669ddf93e25fe5c45420781e191a7df63884d", "eligible": 31},
}


def build_plan(db_path: Path) -> dict:
    conn = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT DISTINCT f.id, tf.engagement, tf.rule_id, tf.fingerprint, "
            "f.file, f.line_start, f.line_end, f.title, f.citation_snippet, "
            "COALESCE(f.source_tool, f.source_lens, 'unknown') producer, ts.triage_run_id "
            "FROM triage_score ts JOIN finding f ON f.id=ts.finding_id "
            "JOIN triage_features tf ON tf.finding_id=f.id "
            "WHERE ts.triage_run_id IN (36,37,38) "
            "AND NOT EXISTS (SELECT 1 FROM triage_assessment ta WHERE ta.finding_id=f.id) "
            "ORDER BY tf.engagement, tf.fingerprint, f.id"
        ).fetchall()
    finally:
        conn.close()
    candidates = []
    digest_rows = []
    seen = set()
    for row in rows:
        source = SOURCES.get(row["engagement"])
        if source is None or source["run"] != row["triage_run_id"]:
            continue
        if review_path_tier(classify_review_path(row["file"])) is not ReviewPathTier.PRIMARY:
            continue
        if row["rule_id"].startswith("package_managers.") or row["producer"].casefold() == "gitleaks":
            continue
        identity = exact_location_identity(AcquisitionIdentityInput(
            engagement=row["engagement"], producer=row["producer"],
            rule_id=row["rule_id"], file=row["file"], line_start=row["line_start"],
            line_end=row["line_end"], sink=row["citation_snippet"],
        ))
        unique = (row["engagement"], identity)
        if unique in seen:
            continue
        seen.add(unique)
        digest_rows.append((row["engagement"], row["fingerprint"], identity, row["triage_run_id"]))
        key = hashlib.sha256(f"{POLICY_ID}{source['family']}{row['fingerprint']}{identity}".encode()).hexdigest()
        candidates.append({
            "finding_id": row["id"], "repo_id": row["engagement"],
            "evaluation_family": source["family"], "rule_id": row["rule_id"],
            "finding_fingerprint": row["fingerprint"], "file": row["file"],
            "line_start": row["line_start"], "line_end": row["line_end"],
            "title": row["title"], "producer": row["producer"],
            "triage_model_run_id": row["triage_run_id"],
            "source_commit": source["commit"], "selection_key": key,
        })
    digest = hashlib.sha256(json.dumps(sorted(digest_rows, key=repr), separators=(",", ":")).encode()).hexdigest()
    if digest != EXPECTED_INVENTORY_SHA256:
        raise RuntimeError(f"wave-one eligible inventory drifted: {digest}")
    selected = []
    for repo_id, source in SOURCES.items():
        queue = sorted((row for row in candidates if row["repo_id"] == repo_id), key=lambda row: row["selection_key"])
        if len(queue) != source["eligible"] or len(queue) < 6:
            raise RuntimeError(f"{repo_id} eligible inventory drifted")
        selected.extend(queue[:6])
    selected.sort(key=lambda row: (row["selection_key"], row["repo_id"]))
    return {"schema_version": 1, "policy": POLICY_ID, "inventory_sha256": digest, "packet_size": 18, "entries": selected}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"refusing to overwrite {args.output}")
    plan = build_plan(get_config().db_path)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
