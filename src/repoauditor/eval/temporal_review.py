"""Bounded score-blind renderer for the frozen OPT-003 wave-one packet."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

from ..config import get_config


EXPECTED_PLAN_SHA256 = "24bbc7915561dc576a94a8d18b95a92e656fe95bda3b40b2b61ced2ff3ccb56d"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stored_rows(db_path: Path, finding_ids: list[int]) -> dict[int, sqlite3.Row]:
    placeholders = ",".join("?" for _ in finding_ids)
    conn = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT f.id, f.repo_id, f.file, f.line_start, f.line_end, "
            "COALESCE(f.source_tool, f.source_lens, 'unknown') producer, "
            "tf.rule_id, tf.fingerprint, ir.commit_hash "
            "FROM finding f JOIN triage_features tf ON tf.finding_id=f.id "
            "JOIN ingested_repo ir ON ir.repo_id=f.repo_id "
            f"WHERE f.id IN ({placeholders}) ORDER BY f.id",
            finding_ids,
        ).fetchall()
    finally:
        conn.close()
    if len(rows) != len(finding_ids):
        raise RuntimeError("selected findings do not resolve uniquely in the store")
    return {row["id"]: row for row in rows}


def render_review(plan_path: Path, *, context_lines: int = 20) -> str:
    if not 0 <= context_lines <= 20:
        raise ValueError("context_lines must be between 0 and 20")
    if _sha256(plan_path) != EXPECTED_PLAN_SHA256:
        raise RuntimeError("wave-one review plan digest drifted")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    entries = plan.get("entries", [])
    if plan.get("packet_size") != 18 or len(entries) != 18:
        raise RuntimeError("wave-one review packet must contain exactly 18 entries")
    config = get_config()
    rows = _stored_rows(config.db_path, [entry["finding_id"] for entry in entries])
    lines = [
        "# OPT-003 wave-one prospective review packet", "",
        f"Plan SHA-256: `{EXPECTED_PLAN_SHA256}`", "",
        "Scores, ranks, predicted classes, suppression, confidence, priors, and expected",
        "outcomes are intentionally absent. Judge only the bounded source evidence below.",
        "Use `insufficient_evidence` whenever this evidence cannot support a decision.", "",
    ]
    for index, entry in enumerate(entries, 1):
        row = rows[entry["finding_id"]]
        for key, value in {
            "repo_id": row["repo_id"], "file": row["file"],
            "line_start": row["line_start"], "line_end": row["line_end"],
            "producer": row["producer"], "rule_id": row["rule_id"],
            "finding_fingerprint": row["fingerprint"],
        }.items():
            if entry.get(key) != value:
                raise RuntimeError(f"finding {entry['finding_id']} drifted at {key}")
        if not entry["source_commit"].startswith(row["commit_hash"]):
            raise RuntimeError(f"finding {entry['finding_id']} source commit drifted")
        root = (config.paths.data_dir / "raw" / row["repo_id"] / row["commit_hash"]).resolve()
        source = (root / row["file"]).resolve()
        if not source.is_relative_to(root) or not source.is_file():
            raise RuntimeError(f"finding {entry['finding_id']} source unavailable")
        source_lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, row["line_start"] - context_lines)
        end = min(len(source_lines), row["line_end"] + context_lines)
        width = len(str(end))
        excerpt = "\n".join(f"{n:>{width}}  {source_lines[n-1]}" for n in range(start, end + 1))
        lines.extend([
            f"## {index}. Finding #{entry['finding_id']}", "",
            f"- Repository: `{row['repo_id']}`", f"- Snapshot: `{entry['source_commit']}`",
            f"- Rule: `{row['rule_id']}`", f"- Source: `{row['file']}:{row['line_start']}-{row['line_end']}`",
            "", "````text", excerpt, "````", "",
            "Respond with one allowed disposition, an evidence-based rationale, and optional",
            "verified dimensions. Do not infer a label from the rule name alone.", "",
        ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--context-lines", type=int, default=20)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"refusing to overwrite {args.output}")
    rendered = render_review(args.plan, context_lines=args.context_lines)
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
