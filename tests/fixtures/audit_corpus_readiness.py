"""Audit public-corpus metadata and materialization without network or model access."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def build_corpus_readiness(fixtures_root: Path) -> dict:
    records: list[dict] = []
    issues: list[str] = []
    for expected_path in sorted(fixtures_root.glob("*/expected_findings.json")):
        expected = json.loads(expected_path.read_text())
        source = expected.get("source")
        if not isinstance(source, dict):
            issues.append(f"{expected_path.parent.name}: missing source metadata")
            continue
        repo_id = expected_path.parent.name
        kind = source.get("kind")
        role = source.get("evaluation_role")
        materialized = (expected_path.parent / "snapshot").is_dir()
        record = {
            "repo_id": repo_id,
            "kind": kind,
            "evaluation_role": role,
            "project_id": source.get("project_id"),
            "variant": source.get("variant"),
            "language": source.get("language"),
            "pinned_commit": source.get("pinned_commit"),
            "materialized": materialized,
        }
        records.append(record)
        if kind not in {"benchmark", "fixture", "independent"}:
            issues.append(f"{repo_id}: unsupported or missing corpus kind")
        if kind == "independent":
            for field in (
                "project_id", "variant", "pinned_commit", "license",
                "ground_truth", "verified_via",
            ):
                if not source.get(field):
                    issues.append(f"{repo_id}: independent source missing {field}")
            if source.get("variant") not in {"pre_fix", "post_fix"}:
                issues.append(f"{repo_id}: invalid independent variant")
            if "never inferred" not in str(source.get("ground_truth", "")).lower():
                issues.append(f"{repo_id}: ground truth lacks non-circularity statement")

    protected = [
        record for record in records
        if record["evaluation_role"] == "protected_holdout"
    ]
    protected_projects = {record["project_id"] for record in protected}
    if len(protected) != 2 or len(protected_projects) != 1:
        issues.append("protected holdout must be exactly one independent pre/post pair")
    elif (
        {record["variant"] for record in protected} != {"pre_fix", "post_fix"}
        or any(record["kind"] != "independent" for record in protected)
    ):
        issues.append("protected holdout variants must be independent pre_fix/post_fix")

    calibration = [
        record for record in records
        if record["evaluation_role"] == "calibration_fixture"
    ]
    if {record["repo_id"] for record in calibration} != {"uat_lightweight_app"}:
        issues.append("uat_lightweight_app must be the sole calibration fixture")

    protected_materialized = bool(protected) and all(
        record["materialized"] for record in protected
    )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "network_accessed": False,
        "metadata_ready": not issues,
        "online_execution_ready": not issues and protected_materialized,
        "issues": issues,
        "next_actions": (
            []
            if not issues and protected_materialized
            else (
                ["repair corpus metadata before evaluation"]
                if issues
                else ["materialize/restore the exact protected-holdout snapshot cache"]
            )
        ),
        "summary": {
            "entry_count": len(records),
            "kind_counts": dict(sorted(Counter(
                record["kind"] for record in records
            ).items())),
            "independent_project_count": len({
                record["project_id"] for record in records
                if record["kind"] == "independent"
            }),
            "protected_holdout_count": len(protected),
            "protected_holdout_materialized_count": sum(
                record["materialized"] for record in protected
            ),
            "calibration_fixture_count": len(calibration),
        },
        "protected_holdout": protected,
        "records": records,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).parent)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--require-materialized",
        action="store_true",
        help="Also fail unless the protected holdout snapshots are present.",
    )
    args = parser.parse_args()
    report = build_corpus_readiness(args.fixtures)
    payload = json.dumps(report, indent=2) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload)
    print(payload, end="")
    if not report["metadata_ready"]:
        raise SystemExit(1)
    if args.require_materialized and not report["online_execution_ready"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
