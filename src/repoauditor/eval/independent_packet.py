"""Outcome-blind selector for the frozen OPT-002 independent-review packet."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path

from ..config import get_config
from ..triage.acquisition_funnel import (
    AcquisitionIdentityInput,
    ReviewPathTier,
    classify_review_path,
    exact_location_identity,
    review_path_tier,
)


POLICY_ID = "opt-002-independent-v1"
EXPECTED_INVENTORY_DIGEST = (
    "73ec5f9f32ff47a65c13fb2b53c59c7fbc210024e641b7636b10cd9843ed0a6c"
)
SOURCES = {
    "opt002-documenso": {
        "family": "independent-upstream:documenso/documenso",
        "commit": "f0ab7c112e3c39656b0153b67fbf25fd9616e96f",
        "model_run": 34,
        "eligible": 53,
    },
    "opt002-lobsters": {
        "family": "independent-upstream:lobsters/lobsters",
        "commit": "57268d762e1c2c95b7a8e64ee8deb259cddd8cc0",
        "model_run": 35,
        "eligible": 165,
    },
}


@dataclass(frozen=True)
class EligibleCandidate:
    finding_id: int
    repo_id: str
    evaluation_family: str
    finding_fingerprint: str
    rule_id: str
    file: str
    line_start: int
    line_end: int
    title: str
    producer: str
    candidate_key: str
    source_commit: str
    triage_model_run_id: int
    normalized_sink: str


def _candidate_key(family: str, fingerprint: str) -> str:
    return hashlib.sha256(f"{POLICY_ID}{family}{fingerprint}".encode()).hexdigest()


def _inventory_digest(candidates: list[EligibleCandidate]) -> str:
    rows = []
    for item in candidates:
        identity = exact_location_identity(AcquisitionIdentityInput(
            engagement=item.repo_id,
            producer=item.producer,
            rule_id=item.rule_id,
            file=item.file,
            line_start=item.line_start,
            line_end=item.line_end,
            sink=item.normalized_sink,
        ))
        rows.append((item.repo_id, item.finding_fingerprint, identity))
    payload = json.dumps(
        sorted(set(rows), key=repr), separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def select_balanced(candidates: list[EligibleCandidate]) -> tuple[EligibleCandidate, ...]:
    """Select six per frozen family using only the protocol's stable hash."""
    queues: dict[str, list[EligibleCandidate]] = {}
    for repo_id in SOURCES:
        queue = sorted(
            (item for item in candidates if item.repo_id == repo_id),
            key=lambda item: item.candidate_key,
        )
        if len(queue) != SOURCES[repo_id]["eligible"]:
            raise RuntimeError(f"{repo_id} eligible inventory drifted: {len(queue)}")
        if len(queue) < 6:
            raise RuntimeError(f"{repo_id} cannot supply the frozen six-entry share")
        queues[repo_id] = queue
    selected = []
    for index in range(6):
        for repo_id in SOURCES:
            selected.append(queues[repo_id][index])
    return tuple(selected)


def _load_candidates(db_path: Path) -> list[EligibleCandidate]:
    # Read-only URI and an explicit column list prevent scores, ranks, suppression,
    # severity, confidence, priors, and outcomes from entering selection.
    conn = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT DISTINCT f.id AS finding_id, tf.engagement AS repo_id, "
            "tf.fingerprint, tf.rule_id, f.file, f.line_start, f.line_end, "
            "f.title, COALESCE(f.source_tool, f.source_lens, 'unknown') AS producer, "
            "f.citation_snippet "
            "FROM triage_features tf JOIN finding f ON f.id = tf.finding_id "
            "JOIN triage_score ts ON ts.finding_id = f.id "
            "WHERE ((tf.engagement = 'opt002-documenso' AND ts.triage_run_id = 34) "
            "OR (tf.engagement = 'opt002-lobsters' AND ts.triage_run_id = 35)) "
            "AND NOT EXISTS (SELECT 1 FROM triage_assessment ta WHERE ta.finding_id=f.id) "
            "AND NOT EXISTS (SELECT 1 FROM triage_label tl WHERE "
            "tl.engagement=tf.engagement AND tl.finding_fingerprint=tf.fingerprint) "
            "ORDER BY tf.engagement, tf.fingerprint, f.id"
        ).fetchall()
    finally:
        conn.close()
    candidates: list[EligibleCandidate] = []
    identities: set[tuple[object, ...]] = set()
    for row in rows:
        if review_path_tier(classify_review_path(row["file"])) is not ReviewPathTier.PRIMARY:
            continue
        if row["rule_id"].startswith("package_managers."):
            continue
        if row["producer"].casefold() == "gitleaks":
            continue
        source = SOURCES[row["repo_id"]]
        identity = exact_location_identity(AcquisitionIdentityInput(
            engagement=row["repo_id"], producer=row["producer"],
            rule_id=row["rule_id"], file=row["file"],
            line_start=row["line_start"], line_end=row["line_end"],
            sink=row["citation_snippet"],
        ))
        if identity in identities:
            continue
        identities.add(identity)
        candidates.append(EligibleCandidate(
            finding_id=row["finding_id"], repo_id=row["repo_id"],
            evaluation_family=source["family"],
            finding_fingerprint=row["fingerprint"], rule_id=row["rule_id"],
            file=row["file"], line_start=row["line_start"], line_end=row["line_end"],
            title=row["title"], producer=row["producer"],
            candidate_key=_candidate_key(source["family"], row["fingerprint"]),
            source_commit=source["commit"], triage_model_run_id=source["model_run"],
            normalized_sink=" ".join(row["citation_snippet"].split()),
        ))
    return candidates


def build_plan(db_path: Path) -> dict:
    candidates = _load_candidates(db_path)
    digest = _inventory_digest(candidates)
    if digest != EXPECTED_INVENTORY_DIGEST:
        raise RuntimeError(f"eligible inventory digest drifted: {digest}")
    selected = select_balanced(candidates)
    entries = []
    for item in selected:
        payload = asdict(item)
        payload.pop("normalized_sink")
        entries.append(payload)
    return {
        "schema_version": 1,
        "protocol_sha256": "202a435a6ddd62e228dbc516a03cf526bce842b2bf9b7fed1bcc76e534fbddab",
        "primary_result_sha256": "be96675aefa96273206424e2d09a16f2135fe07215d6f7404cf14ba5126b7667",
        "eligible_inventory_sha256": digest,
        "selection_policy": POLICY_ID,
        "packet_size": len(entries),
        "entries": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"refusing to overwrite {args.output}")
    config = get_config()
    plan = build_plan(config.db_path)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    print(f"wrote {plan['packet_size']} entries to {args.output}")


if __name__ == "__main__":
    main()
