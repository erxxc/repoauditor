"""Digest-checked atomic importer for the frozen OPT-003 wave-one review."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

from ..config import get_config
from ..store import db
from ..store.models import TriageAssessment, TriageDisposition, TriageLabel, TriageLabelSource
from .temporal_packet import SOURCES


EXPECTED_RESULT_SHA256 = "c7ac0294108d414f0cfa4dbb08d0481b0c920bbf71e10b9ceb1b412889d0416d"
EXPECTED_STORE_SHA256 = "28fa29ad0660dd75f78ee69ee3d82b5d6a97beb4d265528f19e3ef91798bb3aa"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_prediction_bindings(db_path: Path, finding_ids: list[int]) -> None:
    conn = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        placeholders = ",".join("?" for _ in finding_ids)
        rows = conn.execute(
            "SELECT tf.finding_id, tf.engagement, ts.triage_run_id "
            "FROM triage_features tf JOIN triage_score ts ON ts.finding_id=tf.finding_id "
            f"WHERE tf.finding_id IN ({placeholders}) AND ts.triage_run_id IN (36,37,38)",
            finding_ids,
        ).fetchall()
    finally:
        conn.close()
    observed = {(row["finding_id"], row["engagement"], row["triage_run_id"]) for row in rows}
    expected = {
        (finding_id, engagement, source["run"])
        for finding_id in finding_ids
        for engagement, source in SOURCES.items()
        if any(row[0] == finding_id and row[1] == engagement for row in observed)
    }
    if observed != expected or len({row[0] for row in observed}) != len(finding_ids):
        raise RuntimeError("selected finding prediction bindings drifted")


def import_review(result_path: Path) -> dict:
    if _sha256(result_path) != EXPECTED_RESULT_SHA256:
        raise RuntimeError("wave-one review result digest drifted")
    config = get_config()
    if _sha256(config.db_path) != EXPECTED_STORE_SHA256:
        raise RuntimeError("persistent store digest drifted")
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    responses = payload["responses"]
    finding_ids = [row["finding_id"] for row in responses]
    if len(responses) != 18 or len(set(finding_ids)) != 18:
        raise RuntimeError("review result must contain 18 unique responses")
    _assert_prediction_bindings(config.db_path, finding_ids)

    features = {row.finding_id: row for row in db.list_triage_features(config)}
    assessments: list[TriageAssessment] = []
    labels: list[TriageLabel] = []
    for row in responses:
        disposition = TriageDisposition(row["disposition"])
        feature = features.get(row["finding_id"])
        if feature is None:
            raise RuntimeError(f"finding {row['finding_id']} lacks triage features")
        dimensions = [f"{key}: {value}" for key, value in row["verified_dimensions"].items()]
        assessments.append(TriageAssessment(
            finding_id=row["finding_id"], engagement=feature.engagement,
            outcome=disposition.outcome, disposition=disposition,
            rationale=row["rationale"], analyst="project owner", dimensions=dimensions,
            material=False, classifier_eligible=True,
        ))
        if disposition is not TriageDisposition.INSUFFICIENT_EVIDENCE:
            labels.append(TriageLabel(
                engagement=feature.engagement, rule_id=feature.rule_id,
                finding_fingerprint=feature.fingerprint,
                actionable=disposition.outcome.value == "true_positive",
                note=row["rationale"], source=TriageLabelSource.MANUAL,
            ))
    if len(labels) != 16:
        raise RuntimeError("review result must project exactly 16 labels")
    assessment_ids, label_ids = db.import_triage_review_batch(assessments, labels, config)
    return {
        "assessment_ids": assessment_ids,
        "label_ids": label_ids,
        "assessment_count": len(assessment_ids),
        "label_count": len(label_ids),
        "abstention_count": 2,
        "store_sha256_after": _sha256(config.db_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"refusing to overwrite {args.output}")
    outcome = import_review(args.result)
    args.output.write_text(json.dumps(outcome, indent=2) + "\n", encoding="utf-8")
    print(f"atomically imported {outcome['assessment_count']} assessments and {outcome['label_count']} labels")


if __name__ == "__main__":
    main()
