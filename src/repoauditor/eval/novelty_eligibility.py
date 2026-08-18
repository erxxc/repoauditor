"""Read-only provenance audit for the existing OPT-009 LLM-finding cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ..config import REPO_ROOT, get_config


POLICY_ID = "opt009-existing-llm-eligibility-v1"
PROTOCOL_PATH = (
    REPO_ROOT / "docs/optimizations/opt-009-eligibility-protocol-2026-08-12.json"
)


@dataclass(frozen=True)
class CohortRule:
    category: str
    expected_findings: int
    exclusion_reason: str


# These are the complete source_lens-bearing engagements in the digest-frozen store.
# None can supply held-out benefit evidence: three names are the same calibration
# fixture, one is a protected post-fix holdout, and one is a known-answer CVE fixture
# whose two Lens findings were already assessed.
COHORT_RULES = {
    "snapshot": CohortRule(
        "calibration_fixture",
        31,
        "purpose-built UAT/calibration fixture",
    ),
    "snapshot-884a968b": CohortRule(
        "calibration_fixture",
        10,
        "repeat materialization of the purpose-built UAT/calibration fixture",
    ),
    "uat_lightweight_app": CohortRule(
        "calibration_fixture",
        19,
        "purpose-built UAT/calibration fixture",
    ),
    "snapshot-2d5abd74": CohortRule(
        "protected_post_fix_holdout",
        1,
        "protected post-fix holdout with an external answer key",
    ),
    "snapshot-a9f8daec": CohortRule(
        "known_answer_pre_fix_fixture",
        2,
        "known-answer CVE pre-fix fixture with prior human assessment",
    ),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_source(source: str, root: Path) -> Path:
    path = Path(source)
    return path if path.is_absolute() else root / path


def build_audit(
    db_path: Path,
    *,
    protocol_path: Path = PROTOCOL_PATH,
    root: Path = REPO_ROOT,
) -> dict:
    """Measure the frozen cohort without reading outcomes or source contents."""
    db_digest_before = _sha256(db_path)
    protocol_digest = _sha256(protocol_path)
    conn = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only = ON")
        findings = conn.execute(
            "SELECT f.id, f.repo_id, f.source_lens, f.file, f.line_start, "
            "f.line_end, f.created_at, "
            "EXISTS(SELECT 1 FROM triage_assessment a WHERE a.finding_id=f.id) "
            "AS has_assessment "
            "FROM finding f WHERE f.source_lens IS NOT NULL "
            "ORDER BY f.repo_id, f.id"
        ).fetchall()
        sources = conn.execute(
            "SELECT repo_id, source, commit_hash FROM ingested_repo "
            "WHERE repo_id IN (SELECT DISTINCT repo_id FROM finding "
            "WHERE source_lens IS NOT NULL) "
            "ORDER BY repo_id, ingested_at, commit_hash"
        ).fetchall()
    finally:
        conn.close()

    observed_repos = {row["repo_id"] for row in findings}
    if observed_repos != set(COHORT_RULES):
        raise RuntimeError(
            "OPT-009 Lens cohort drifted: "
            f"expected {sorted(COHORT_RULES)}, observed {sorted(observed_repos)}"
        )

    source_rows: dict[str, list[sqlite3.Row]] = {key: [] for key in COHORT_RULES}
    for row in sources:
        source_rows[row["repo_id"]].append(row)

    cohorts = []
    inventory_rows = []
    category_counts: Counter[str] = Counter()
    assessed_total = 0
    for repo_id, rule in COHORT_RULES.items():
        members = [row for row in findings if row["repo_id"] == repo_id]
        if len(members) != rule.expected_findings:
            raise RuntimeError(
                f"{repo_id} Lens count drifted: expected {rule.expected_findings}, "
                f"observed {len(members)}"
            )
        assessed = sum(int(row["has_assessment"]) for row in members)
        assessed_total += assessed
        exact_locations = {
            (row["source_lens"], row["file"], row["line_start"], row["line_end"])
            for row in members
        }
        inventory_rows.extend(
            (
                row["id"], row["repo_id"], row["source_lens"], row["file"],
                row["line_start"], row["line_end"], row["created_at"],
                int(row["has_assessment"]),
            )
            for row in members
        )
        category_counts[rule.category] += len(members)
        recorded_sources = [
            {
                "source": row["source"],
                "commit_hash": row["commit_hash"],
                "materialization_present": _resolve_source(row["source"], root).is_dir(),
            }
            for row in source_rows[repo_id]
        ]
        cohorts.append(
            {
                "repo_id": repo_id,
                "category": rule.category,
                "finding_records": len(members),
                "exact_location_lens_groups": len(exact_locations),
                "previously_assessed_records": assessed,
                "evidence_eligible_records": 0,
                "protocol_development_only_records": len(members),
                "exclusion_reason": rule.exclusion_reason,
                "recorded_sources": recorded_sources,
            }
        )

    inventory_digest = hashlib.sha256(
        json.dumps(inventory_rows, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    db_digest_after = _sha256(db_path)
    if db_digest_after != db_digest_before:
        raise RuntimeError("store changed during read-only OPT-009 audit")

    total = len(findings)
    return {
        "schema_version": 1,
        "optimization": "OPT-009",
        "policy": POLICY_ID,
        "audit_date": "2026-08-12",
        "protocol": {
            "path": str(protocol_path.relative_to(root)),
            "sha256": protocol_digest,
        },
        "store": {
            "path": str(db_path.relative_to(root)),
            "sha256_before": db_digest_before,
            "sha256_after": db_digest_after,
            "byte_identical": True,
        },
        "inventory": {
            "source_lens_finding_records": total,
            "previously_assessed_records": assessed_total,
            "unassessed_records": total - assessed_total,
            "evidence_eligible_records": 0,
            "protocol_development_only_records": total,
            "inventory_sha256": inventory_digest,
            "candidate_identities_emitted": 0,
            "source_content_rendered": False,
            "assessment_outcomes_read": False,
            "category_counts": dict(sorted(category_counts.items())),
        },
        "cohorts": cohorts,
        "gate": {
            "existing_cohort_can_supply_retrospective_pilot": False,
            "current_data_gate_cleared": False,
            "reason": (
                "No existing LLM-origin finding is eligible for held-out novelty-benefit "
                "evidence under the frozen provenance and leakage rules."
            ),
            "required_next_evidence": (
                "A separately authorized prospective collection from independent, "
                "production/deployment repositories with novelty assignments frozen "
                "before outcome-blind human review."
            ),
        },
        "accounting": {
            "network_reads": 0,
            "provider_calls": 0,
            "tokens": 0,
            "store_mutations": 0,
            "assessments_added": 0,
            "labels_added": 0,
            "models_trained": 0,
            "scores_read_or_written": 0,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"refusing to overwrite {args.output}")
    result = build_audit(get_config().db_path)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        "OPT-009 eligibility audit: "
        f"{result['inventory']['evidence_eligible_records']} eligible of "
        f"{result['inventory']['source_lens_finding_records']} Lens findings"
    )


if __name__ == "__main__":
    main()
