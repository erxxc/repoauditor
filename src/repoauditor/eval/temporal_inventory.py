"""Aggregate-only eligibility measurement for OPT-003 prediction wave two."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from ..config import get_config
from ..triage.acquisition_funnel import (
    AcquisitionIdentityInput,
    ReviewPathTier,
    classify_review_path,
    exact_location_identity,
    review_path_tier,
)


SOURCES = {
    "opt003-wave2-actual": {
        "family": "independent-upstream:actualbudget/actual",
        "run": 39,
        "commit": "4dedf88e58a5c92478ac1d8eb909d216b242a59f",
    },
    "opt003-wave2-memos": {
        "family": "independent-upstream:usememos/memos",
        "run": 40,
        "commit": "34e2a59a4a94176ad95cdb8ce0a93917f471795c",
    },
    "opt003-wave2-authentik": {
        "family": "independent-upstream:goauthentik/authentik",
        "run": 41,
        "commit": "243ab69987ea095c6e61c1917e6ed92825ec427b",
    },
}


def measure(db_path: Path) -> dict:
    """Return counts and an inventory digest without candidate identities."""
    conn = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT DISTINCT f.id, tf.engagement, tf.rule_id, tf.fingerprint, "
            "f.file, f.line_start, f.line_end, f.citation_snippet, "
            "COALESCE(f.source_tool, f.source_lens, 'unknown') producer, "
            "ts.triage_run_id, ts.scored_at "
            "FROM triage_score ts JOIN finding f ON f.id=ts.finding_id "
            "JOIN triage_features tf ON tf.finding_id=f.id "
            "WHERE ts.triage_run_id IN (39,40,41) "
            "AND NOT EXISTS (SELECT 1 FROM triage_assessment ta WHERE ta.finding_id=f.id) "
            "ORDER BY tf.engagement, tf.fingerprint, f.id"
        ).fetchall()
    finally:
        conn.close()

    counts = {repo_id: 0 for repo_id in SOURCES}
    score_bounds = {
        repo_id: {"first_scored_at": None, "last_scored_at": None}
        for repo_id in SOURCES
    }
    digest_rows: list[tuple[str, str, str, int]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        source = SOURCES.get(row["engagement"])
        if source is None or source["run"] != row["triage_run_id"]:
            continue
        bounds = score_bounds[row["engagement"]]
        bounds["first_scored_at"] = min(
            value for value in (bounds["first_scored_at"], row["scored_at"]) if value
        )
        bounds["last_scored_at"] = max(
            value for value in (bounds["last_scored_at"], row["scored_at"]) if value
        )
        if review_path_tier(classify_review_path(row["file"])) is not ReviewPathTier.PRIMARY:
            continue
        if row["rule_id"].startswith("package_managers."):
            continue
        if row["producer"].casefold() == "gitleaks":
            continue
        identity = exact_location_identity(
            AcquisitionIdentityInput(
                engagement=row["engagement"],
                producer=row["producer"],
                rule_id=row["rule_id"],
                file=row["file"],
                line_start=row["line_start"],
                line_end=row["line_end"],
                sink=row["citation_snippet"],
            )
        )
        unique = (row["engagement"], identity)
        if unique in seen:
            continue
        seen.add(unique)
        counts[row["engagement"]] += 1
        digest_rows.append(
            (
                row["engagement"],
                row["fingerprint"],
                identity,
                row["triage_run_id"],
            )
        )

    repositories = []
    for repo_id, source in SOURCES.items():
        eligible = counts[repo_id]
        repositories.append(
            {
                "repo_id": repo_id,
                "evaluation_family": source["family"],
                "source_commit": source["commit"],
                "triage_model_run_id": source["run"],
                "eligible_identities": eligible,
                "minimum_required": 6,
                "minimum_met": eligible >= 6,
                **score_bounds[repo_id],
            }
        )
    inventory_digest = hashlib.sha256(
        json.dumps(sorted(digest_rows, key=repr), separators=(",", ":")).encode()
    ).hexdigest()
    total = sum(counts.values())
    return {
        "schema_version": 1,
        "policy": "opt003-wave2-aggregate-eligibility-v1",
        "inventory_sha256": inventory_digest,
        "eligible_identities": total,
        "minimum_total_required": 18,
        "minimum_total_met": total >= 18,
        "all_family_minimums_met": all(row["minimum_met"] for row in repositories),
        "repositories": repositories,
        "candidate_identities_disclosed": 0,
    }


def main() -> None:
    print(json.dumps(measure(get_config().db_path), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
