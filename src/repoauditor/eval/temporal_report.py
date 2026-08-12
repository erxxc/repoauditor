"""Read-only fixed-cohort temporal evaluation for OPT-003."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from ..config import get_config


EXPECTED_STORE_SHA256 = "a3d8e55feadf5860c079f1de18b698186afbae81ba6bf678717cdfe1f2cca11f"
BOOTSTRAP_RESAMPLES = 2_000
BOOTSTRAP_CONFIDENCE = 0.95
BOOTSTRAP_SEED = 2_003
THRESHOLDS = tuple(step / 10 for step in range(11))


@dataclass(frozen=True)
class Identity:
    label_id: int
    finding_id: int
    triage_run_id: int
    family: str
    wave: str


COHORT = (
    Identity(155, 859, 34, "independent-upstream:documenso/documenso", "baseline"),
    Identity(156, 1170, 35, "independent-upstream:lobsters/lobsters", "baseline"),
    Identity(157, 861, 34, "independent-upstream:documenso/documenso", "baseline"),
    Identity(158, 1084, 35, "independent-upstream:lobsters/lobsters", "baseline"),
    Identity(159, 905, 34, "independent-upstream:documenso/documenso", "baseline"),
    Identity(160, 1147, 35, "independent-upstream:lobsters/lobsters", "baseline"),
    Identity(161, 869, 34, "independent-upstream:documenso/documenso", "baseline"),
    Identity(162, 884, 34, "independent-upstream:documenso/documenso", "baseline"),
    Identity(163, 1081, 35, "independent-upstream:lobsters/lobsters", "baseline"),
    Identity(164, 870, 34, "independent-upstream:documenso/documenso", "baseline"),
    Identity(165, 1148, 35, "independent-upstream:lobsters/lobsters", "baseline"),
    Identity(208, 1539, 36, "independent-upstream:chatwoot/chatwoot", "wave-one"),
    Identity(209, 1486, 36, "independent-upstream:chatwoot/chatwoot", "wave-one"),
    Identity(210, 1278, 36, "independent-upstream:chatwoot/chatwoot", "wave-one"),
    Identity(211, 1920, 38, "independent-upstream:paperless-ngx/paperless-ngx", "wave-one"),
    Identity(212, 1524, 36, "independent-upstream:chatwoot/chatwoot", "wave-one"),
    Identity(213, 1272, 36, "independent-upstream:chatwoot/chatwoot", "wave-one"),
    Identity(214, 1741, 37, "independent-upstream:linkwarden/linkwarden", "wave-one"),
    Identity(215, 1913, 38, "independent-upstream:paperless-ngx/paperless-ngx", "wave-one"),
    Identity(216, 1742, 37, "independent-upstream:linkwarden/linkwarden", "wave-one"),
    Identity(217, 1924, 38, "independent-upstream:paperless-ngx/paperless-ngx", "wave-one"),
    Identity(218, 1900, 38, "independent-upstream:paperless-ngx/paperless-ngx", "wave-one"),
    Identity(219, 1919, 38, "independent-upstream:paperless-ngx/paperless-ngx", "wave-one"),
    Identity(220, 1925, 38, "independent-upstream:paperless-ngx/paperless-ngx", "wave-one"),
    Identity(221, 1747, 37, "independent-upstream:linkwarden/linkwarden", "wave-one"),
    Identity(222, 1748, 37, "independent-upstream:linkwarden/linkwarden", "wave-one"),
    Identity(223, 1740, 37, "independent-upstream:linkwarden/linkwarden", "wave-one"),
    Identity(266, 2434, 41, "independent-upstream:goauthentik/authentik", "wave-two"),
    Identity(267, 2152, 40, "independent-upstream:usememos/memos", "wave-two"),
    Identity(268, 2161, 40, "independent-upstream:usememos/memos", "wave-two"),
    Identity(269, 2163, 40, "independent-upstream:usememos/memos", "wave-two"),
    Identity(270, 2354, 41, "independent-upstream:goauthentik/authentik", "wave-two"),
    Identity(271, 2172, 40, "independent-upstream:usememos/memos", "wave-two"),
    Identity(272, 2160, 40, "independent-upstream:usememos/memos", "wave-two"),
    Identity(273, 2159, 40, "independent-upstream:usememos/memos", "wave-two"),
    Identity(274, 2034, 39, "independent-upstream:actualbudget/actual", "wave-two"),
    Identity(275, 1982, 39, "independent-upstream:actualbudget/actual", "wave-two"),
    Identity(276, 1997, 39, "independent-upstream:actualbudget/actual", "wave-two"),
    Identity(277, 1978, 39, "independent-upstream:actualbudget/actual", "wave-two"),
    Identity(278, 2036, 39, "independent-upstream:actualbudget/actual", "wave-two"),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _percentile(values: list[float]) -> list[float]:
    alpha = (1.0 - BOOTSTRAP_CONFIDENCE) / 2.0
    low, high = np.quantile(values, [alpha, 1.0 - alpha])
    return [float(low), float(high)]


def _threshold_rows(rows: list[dict]) -> list[dict]:
    positives = sum(row["actionable"] for row in rows)
    output = []
    for threshold in THRESHOLDS:
        selected = [row for row in rows if row["p_actionable"] >= threshold]
        true_positive = sum(row["actionable"] for row in selected)
        output.append(
            {
                "threshold": threshold,
                "selected": len(selected),
                "precision": true_positive / len(selected) if selected else None,
                "recall": true_positive / positives,
            }
        )
    return output


def _bootstrap(rows: list[dict]) -> dict:
    grouped = {
        family: [row for row in rows if row["family"] == family]
        for family in sorted({row["family"] for row in rows})
    }
    families = sorted(grouped)
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    brier_values: list[float] = []
    values = {threshold: {"precision": [], "recall": []} for threshold in THRESHOLDS}
    positive_resamples = 0
    for _ in range(BOOTSTRAP_RESAMPLES):
        sampled = rng.choice(families, size=len(families), replace=True)
        sample = [row for family in sampled for row in grouped[str(family)]]
        brier_values.append(
            sum((row["p_actionable"] - row["actionable"]) ** 2 for row in sample)
            / len(sample)
        )
        positives = sum(row["actionable"] for row in sample)
        if positives == 0:
            continue
        positive_resamples += 1
        for threshold in THRESHOLDS:
            selected = [row for row in sample if row["p_actionable"] >= threshold]
            true_positive = sum(row["actionable"] for row in selected)
            if selected:
                values[threshold]["precision"].append(true_positive / len(selected))
            values[threshold]["recall"].append(true_positive / positives)
    return {
        "sampling_unit": "evaluation_family",
        "resamples": BOOTSTRAP_RESAMPLES,
        "positive_class_resamples": positive_resamples,
        "confidence": BOOTSTRAP_CONFIDENCE,
        "seed": BOOTSTRAP_SEED,
        "interval": "percentile",
        "brier_95": _percentile(brier_values),
        "threshold_intervals": [
            {
                "threshold": threshold,
                "precision_95": _percentile(values[threshold]["precision"])
                if values[threshold]["precision"]
                else None,
                "recall_95": _percentile(values[threshold]["recall"]),
            }
            for threshold in THRESHOLDS
        ],
    }


def build_report() -> dict:
    config = get_config()
    if _sha256(config.db_path) != EXPECTED_STORE_SHA256:
        raise RuntimeError("persistent store digest drifted")
    conn = sqlite3.connect(f"file:{config.db_path.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = []
        for identity in COHORT:
            row = conn.execute(
                "SELECT tl.id AS label_id, tf.finding_id, tl.actionable, tl.source, "
                "ts.triage_run_id, ts.p_actionable, ts.scored_at, "
                "MIN(ta.created_at) AS first_assessed_at "
                "FROM triage_label tl JOIN triage_features tf "
                "ON tf.engagement=tl.engagement AND tf.fingerprint=tl.finding_fingerprint "
                "JOIN triage_score ts ON ts.finding_id=tf.finding_id "
                "JOIN triage_assessment ta ON ta.finding_id=tf.finding_id "
                "WHERE tl.id=? AND tf.finding_id=? AND ts.triage_run_id=? "
                "GROUP BY tl.id, tf.finding_id, tl.actionable, tl.source, "
                "ts.triage_run_id, ts.p_actionable, ts.scored_at",
                (identity.label_id, identity.finding_id, identity.triage_run_id),
            ).fetchone()
            if row is None or row["source"] != "manual":
                raise RuntimeError(f"prospective identity {identity.finding_id} drifted")
            if not row["scored_at"] < row["first_assessed_at"]:
                raise RuntimeError(f"prediction did not precede outcome for {identity.finding_id}")
            rows.append(
                {
                    "label_id": row["label_id"],
                    "finding_id": row["finding_id"],
                    "triage_run_id": row["triage_run_id"],
                    "actionable": int(row["actionable"]),
                    "p_actionable": float(row["p_actionable"]),
                    "family": identity.family,
                    "wave": identity.wave,
                }
            )
    finally:
        conn.close()

    if len(rows) != 40 or sum(row["actionable"] for row in rows) != 6:
        raise RuntimeError("temporal cohort class counts drifted")
    if len({row["family"] for row in rows}) != 8 or len({row["wave"] for row in rows}) != 3:
        raise RuntimeError("temporal cohort family or wave counts drifted")
    brier = sum(
        (row["p_actionable"] - row["actionable"]) ** 2 for row in rows
    ) / len(rows)
    return {
        "schema_version": 1,
        "optimization": "OPT-003",
        "status": "completed-fixed-prospective-evaluation",
        "cohort": {
            "decided_labels": len(rows),
            "positive": sum(row["actionable"] for row in rows),
            "negative": sum(not row["actionable"] for row in rows),
            "evaluation_families": len({row["family"] for row in rows}),
            "prediction_waves": len({row["wave"] for row in rows}),
            "prediction_precedes_first_assessment": True,
            "identity_digest": hashlib.sha256(
                "\n".join(
                    f"{row['label_id']}:{row['finding_id']}:{row['triage_run_id']}"
                    for row in rows
                ).encode()
            ).hexdigest(),
        },
        "brier_score": brier,
        "fixed_thresholds": _threshold_rows(rows),
        "family_block_uncertainty": _bootstrap(rows),
        "per_wave": [
            {
                "wave": wave,
                "labels": len(selected),
                "positive": sum(row["actionable"] for row in selected),
                "negative": sum(not row["actionable"] for row in selected),
                "families": len({row["family"] for row in selected}),
                "brier_score": sum(
                    (row["p_actionable"] - row["actionable"]) ** 2
                    for row in selected
                ) / len(selected),
            }
            for wave in ("baseline", "wave-one", "wave-two")
            for selected in ([row for row in rows if row["wave"] == wave],)
        ],
        "interpretation_boundary": {
            "descriptive_only": True,
            "threshold_selected": False,
            "rescore_performed": False,
            "training_performed": False,
            "production_policy_changed": False,
        },
        "store_sha256": _sha256(config.db_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"refusing to overwrite {args.output}")
    args.output.write_text(json.dumps(build_report(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
