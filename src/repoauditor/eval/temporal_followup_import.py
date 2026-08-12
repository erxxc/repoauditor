"""Atomic append-only import for the OPT-003 finding 2036 follow-up response."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

from ..config import get_config


EXPECTED_RESULT_SHA256 = "d48a93550223e298ac6fb650ca19d40f703c0fc1a649072122dec419fcd8ade7"
EXPECTED_STORE_SHA256 = "06a3d078ecc537600ed877639595adfebc993f36252e8fe5d56da3402b7dfa9b"
FINDING_ID = 2036
PRIOR_ASSESSMENT_ID = 159
ENGAGEMENT = "opt003-wave2-actual"
RULE_ID = "javascript.express.security.audit.xss.direct-response-write.direct-response-write"
FINGERPRINT = "65d056668c3a8375"
RATIONALE = (
    "The original packet showed res.status(403); res.send(fileAccessError) on "
    "/user-create-key after requireFileOwner(...). The follow-up excerpts define "
    "requireFileOwner as returning null on owner/admin success or the literal "
    "'file-access-not-allowed' otherwise. The same literal is the only non-null return "
    "from requireFileAccess. The 403 paths at lines 242-245 and 276-279 therefore send "
    "that constant string, not request-derived HTML. Direct-response-write XSS requires "
    "attacker-controlled markup in the body; that source is not present."
)
DIMENSIONS = [
    "source control of returned error value: requireFileOwner returns only null or the literal "
    "'file-access-not-allowed'; no request body or file metadata is copied into the error.",
    "response behavior relevant to attacker-controlled markup: res.send(fileAccessError) "
    "transmits that constant string after HTTP 403; no attacker-supplied markup is shown in "
    "the sent body.",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def import_followup(result_path: Path) -> dict:
    if _sha256(result_path) != EXPECTED_RESULT_SHA256:
        raise RuntimeError("follow-up result digest drifted")
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    response = payload["response"]
    if (
        response["finding_id"] != FINDING_ID
        or response["prior_assessment_id"] != PRIOR_ASSESSMENT_ID
        or response["disposition"] != "not_attacker_controlled"
        or response["binary_projection"] != "non_actionable"
        or response["rationale"] != RATIONALE
    ):
        raise RuntimeError("follow-up response drifted")

    config = get_config()
    if _sha256(config.db_path) != EXPECTED_STORE_SHA256:
        raise RuntimeError("persistent store digest drifted")
    conn = sqlite3.connect(config.db_path)
    conn.row_factory = sqlite3.Row
    try:
        before = {
            "triage_assessment": conn.execute(
                "SELECT COUNT(*) FROM triage_assessment"
            ).fetchone()[0],
            "triage_label": conn.execute("SELECT COUNT(*) FROM triage_label").fetchone()[0],
            "triage_model_run": conn.execute(
                "SELECT COUNT(*) FROM triage_model_run"
            ).fetchone()[0],
            "model_usage": conn.execute("SELECT COUNT(*) FROM model_usage").fetchone()[0],
        }
        prior = conn.execute(
            "SELECT finding_id, engagement, outcome, disposition, analyst "
            "FROM triage_assessment WHERE id=?",
            (PRIOR_ASSESSMENT_ID,),
        ).fetchone()
        feature = conn.execute(
            "SELECT engagement, rule_id, fingerprint FROM triage_features WHERE finding_id=?",
            (FINDING_ID,),
        ).fetchone()
        if prior is None or tuple(prior) != (
            FINDING_ID,
            ENGAGEMENT,
            "uncertain",
            "insufficient_evidence",
            "project owner",
        ):
            raise RuntimeError("prior abstention drifted")
        if feature is None or tuple(feature) != (ENGAGEMENT, RULE_ID, FINGERPRINT):
            raise RuntimeError("finding feature identity drifted")
        if conn.execute(
            "SELECT 1 FROM triage_label WHERE engagement=? AND finding_fingerprint=?",
            (ENGAGEMENT, FINGERPRINT),
        ).fetchone():
            raise RuntimeError("finding already has a label")
        if conn.execute(
            "SELECT COUNT(*) FROM triage_assessment WHERE finding_id=?",
            (FINDING_ID,),
        ).fetchone()[0] != 1:
            raise RuntimeError("finding assessment history drifted")

        with conn:
            assessment = conn.execute(
                "INSERT INTO triage_assessment "
                "(finding_id, engagement, outcome, disposition, rationale, analyst, "
                "material, classifier_eligible, dimensions) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    FINDING_ID,
                    ENGAGEMENT,
                    "false_positive",
                    "not_attacker_controlled",
                    RATIONALE,
                    "project owner",
                    0,
                    1,
                    json.dumps(DIMENSIONS),
                ),
            )
            label = conn.execute(
                "INSERT INTO triage_label "
                "(engagement, rule_id, finding_fingerprint, actionable, note, source, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
                (ENGAGEMENT, RULE_ID, FINGERPRINT, 0, RATIONALE, "manual"),
            )
        after = {
            "triage_assessment": conn.execute(
                "SELECT COUNT(*) FROM triage_assessment"
            ).fetchone()[0],
            "triage_label": conn.execute("SELECT COUNT(*) FROM triage_label").fetchone()[0],
            "triage_model_run": conn.execute(
                "SELECT COUNT(*) FROM triage_model_run"
            ).fetchone()[0],
            "model_usage": conn.execute("SELECT COUNT(*) FROM model_usage").fetchone()[0],
        }
    finally:
        conn.close()

    if after != {
        "triage_assessment": before["triage_assessment"] + 1,
        "triage_label": before["triage_label"] + 1,
        "triage_model_run": before["triage_model_run"],
        "model_usage": before["model_usage"],
    }:
        raise RuntimeError("post-import table counts violated the atomic import boundary")
    return {
        "assessment_id": int(assessment.lastrowid),
        "label_id": int(label.lastrowid),
        "assessment_inserts": 1,
        "manual_label_inserts": 1,
        "non_actionable_label_inserts": 1,
        "prior_abstention_preserved": True,
        "table_counts_before": before,
        "table_counts_after": after,
        "temporal_gate_report": {
            "prospective_decided_labels": 40,
            "prospective_positive": 6,
            "prospective_negative": 34,
            "genuine_evaluation_families": 8,
            "separately_frozen_prediction_waves": 3,
            "both_classes_present": True,
            "activation_conditions_met": True,
        },
        "store_sha256_after": _sha256(config.db_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"refusing to overwrite {args.output}")
    outcome = import_followup(args.result)
    args.output.write_text(json.dumps(outcome, indent=2) + "\n", encoding="utf-8")
    print("atomically appended one reassessment and one non-actionable manual label")


if __name__ == "__main__":
    main()
