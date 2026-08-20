"""Aggregate-only, read-only OPT-010 agentic-escalation readiness audit."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tomllib
from pathlib import Path
from typing import Any


_FROZEN_SHA256 = {
    "activation_gate": "6ec12b12918c7449866b47b96564d3a815a4efda67739e643aee7cf609e43cfe",
    "optimization_status": "a8d33e0d3f27e686b120213689223fb29b83834245ffc2f0b147f33f7842c6fa",
    "opt_014_handoff": "9af94242b348378a175528e3ceb4d4c8c01f1cccd6da4036ecc7ca895b47045a",
    "sec_edgar_reserve": "5b21cb52b7011165e0609796b3a007c1df2bb209460e343d718b68a7f5cb04d5",
    "receipt": "0f9f324eebba4975b5195acb2d188f56add8e66556a936663a7448329779e478",
    "production_store": "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a",
    "configuration": "30d8837bdb63b56a50aefb0cd9bc18a0a7173ac86cd8581d4af6f2b2b21f3d09",
    "challenger": "ab50f969979c1fe2c2e961b78455bdf91e72fa7e9459c1291ec30f34aca9610c",
    "claims": "d534c9137236a1e37e2ae88072f24d69b1c6f516ab577175af4dbbf461ad41f6",
    "slicing": "f46e8c3eb7bc519efa9c64f11f226dc6fef944ac911373c3238e6615ca07f0df",
    "retrieval_index": "c440666998bc0898453acc309d23a10b13e95a41360ec23f911e0410da357c08",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_only_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)


def _group_counts(
    conn: sqlite3.Connection, table: str, column: str
) -> dict[str, int]:
    # Identifiers are module-owned constants; values are emitted only as aggregate groups.
    rows = conn.execute(
        f'SELECT "{column}", COUNT(*) FROM "{table}" '
        f'GROUP BY "{column}" ORDER BY "{column}"'
    ).fetchall()
    return {str(value): int(count) for value, count in rows}


def _scalar(conn: sqlite3.Connection, query: str) -> int:
    return int(conn.execute(query).fetchone()[0])


def build_audit(root: Path) -> dict[str, Any]:
    """Build the frozen readiness classification without mutation or live execution."""
    root = root.resolve()
    paths = {
        "activation_gate": root / "docs/agentic-escalation-gate.md",
        "optimization_status": root / "docs/optimizations/optimization-status.json",
        "opt_014_handoff": root / "docs/optimizations/opt-014-commercial-license-first-screen-result-2026-08-18.json",
        "sec_edgar_reserve": root / "docs/optimizations/opt-014-sec-edgar-reserve-2026-08-18.json",
        "receipt": root / "docs/optimizations/opt-010-offline-readiness-audit-receipt-2026-08-18.json",
        "production_store": root / "data/repoauditor.db",
        "configuration": root / "config.toml",
        "challenger": root / "src/repoauditor/falsify/challenger.py",
        "claims": root / "src/repoauditor/falsify/claims.py",
        "slicing": root / "src/repoauditor/falsify/slicing.py",
        "retrieval_index": root / "src/repoauditor/detect/retrieval/index.py",
    }
    observed_digests = {name: _sha256(path) for name, path in paths.items()}
    if observed_digests != _FROZEN_SHA256:
        drift = sorted(
            name for name, digest in observed_digests.items()
            if digest != _FROZEN_SHA256[name]
        )
        raise ValueError(f"frozen OPT-010 input digest drift: {', '.join(drift)}")

    lifecycle = json.loads(paths["optimization_status"].read_text(encoding="utf-8"))
    opt010 = next(item for item in lifecycle["items"] if item["id"] == "OPT-010")
    if opt010 != {
        "id": "OPT-010",
        "title": "Agentic falsification",
        "status": "open",
        "gate": "safety-and-evaluation",
        "next_priority": 2,
    }:
        raise ValueError("OPT-010 is not at the frozen open safety-and-evaluation gate")

    reserve = json.loads(paths["sec_edgar_reserve"].read_text(encoding="utf-8"))
    if (
        reserve["reserve_identity"]["source_selected"] is not False
        or reserve["reserve_identity"]["acquisition_authorized"] is not False
    ):
        raise ValueError("OPT-014 SEC/EDGAR reserve is no longer inactive")

    config = tomllib.loads(paths["configuration"].read_text(encoding="utf-8"))
    before_store_sha256 = observed_digests["production_store"]
    with _read_only_connection(paths["production_store"]) as conn:
        conn.execute("PRAGMA query_only = ON")
        aggregate = {
            "findings_by_falsification_status": _group_counts(
                conn, "finding", "falsification_status"
            ),
            "finding_metadata_availability": {
                "total": _scalar(conn, "SELECT COUNT(*) FROM finding"),
                "source_lens_present": _scalar(
                    conn, "SELECT COUNT(*) FROM finding WHERE source_lens IS NOT NULL"
                ),
                "source_tool_present": _scalar(
                    conn, "SELECT COUNT(*) FROM finding WHERE source_tool IS NOT NULL"
                ),
            },
            "usage_accounting": {
                "attempts": _scalar(conn, "SELECT COUNT(*) FROM model_usage"),
                "authoritative_usage": _scalar(
                    conn, "SELECT COUNT(*) FROM model_usage WHERE usage_available = 1"
                ),
                "explicit_unknown_usage": _scalar(
                    conn, "SELECT COUNT(*) FROM model_usage WHERE usage_available = 0"
                ),
                "latency_recorded": _scalar(
                    conn, "SELECT COUNT(*) FROM model_usage WHERE latency_ms >= 0"
                ),
                "linked_continuation_batches": _scalar(
                    conn, "SELECT COUNT(*) FROM pipeline_run WHERE parent_run_id IS NOT NULL"
                ),
            },
            "pipeline_runs_by_status": _group_counts(conn, "pipeline_run", "status"),
            "manual_evidence": {
                "manual_labels": _scalar(
                    conn, "SELECT COUNT(*) FROM triage_label WHERE source = 'manual'"
                ),
                "assessment_abstentions": _scalar(
                    conn, "SELECT COUNT(*) FROM triage_assessment WHERE outcome = 'uncertain'"
                ),
            },
            "structural_claims": {
                "claims": _scalar(conn, "SELECT COUNT(*) FROM security_claim"),
                "snapshot_bound": _scalar(
                    conn,
                    "SELECT COUNT(*) FROM security_claim "
                    "WHERE COALESCE(snapshot_commit, '') <> ''",
                ),
                "by_mechanism": _group_counts(conn, "security_claim", "mechanism"),
                "by_language": _group_counts(conn, "security_claim", "language"),
                "verifications_by_status": _group_counts(
                    conn, "claim_verification", "status"
                ),
            },
        }
    after_store_sha256 = _sha256(paths["production_store"])
    if after_store_sha256 != before_store_sha256:
        raise ValueError("production store changed during read-only OPT-010 audit")

    usage = aggregate["usage_accounting"]
    falsification = aggregate["findings_by_falsification_status"]
    claims = aggregate["structural_claims"]
    config_bounds = {
        "falsify_max_iterations": int(config["falsify"]["max_iterations"]),
        "falsify_max_findings_per_run": int(
            config["falsify"]["max_findings_per_run"]
        ),
        "falsify_min_untriaged_per_run": int(
            config["falsify"]["min_untriaged_per_run"]
        ),
        "provider_call_ceiling": int(config["llm"]["max_calls_per_pipeline_run"]),
        "provider_token_ceiling": int(config["llm"]["max_tokens_per_pipeline_run"]),
    }
    gates = [
        {
            "gate_id": "G01",
            "name": "authoritative-usage-accounting",
            "state": "documented-pass",
            "evidence": {
                "attempts": usage["attempts"],
                "authoritative_usage": usage["authoritative_usage"],
                "explicit_unknown_usage": usage["explicit_unknown_usage"],
                "latency_recorded": usage["latency_recorded"],
                "linked_continuation_batches": usage["linked_continuation_batches"],
                "dated_cost_support": "implemented-for-supported-standard-first-party-model",
            },
            "blocker": None,
        },
        {
            "gate_id": "G02",
            "name": "protected-evaluation-cohort",
            "state": "partial",
            "evidence": {
                "independently_frozen_subjects_documented": 2,
                "subject_set": "single-pre-post-pair",
                "terminal_usage_documented": True,
            },
            "blocker": "One protected pre/post pair is not a sufficiently broad real-world cohort.",
        },
        {
            "gate_id": "G03",
            "name": "baseline-comparison",
            "state": "documented-fail",
            "evidence": {
                "frozen_comparison_protocol": False,
                "proposed_agent_implemented": False,
                "comparison_executed": False,
            },
            "blocker": "No frozen current-falsifier-versus-agent comparison exists.",
        },
        {
            "gate_id": "G04",
            "name": "recall-safety",
            "state": "partial",
            "evidence": {
                "unresolved_findings_retained": int(falsification.get("unresolved", 0)),
                "deferred_findings_retained": int(falsification.get("deferred", 0)),
                "assessment_abstentions_retained": aggregate["manual_evidence"][
                    "assessment_abstentions"
                ],
                "protected_recall_regression_bound": False,
            },
            "blocker": "Abstention is preserved, but the protected cohort cannot yet bound recall regression.",
        },
        {
            "gate_id": "G05",
            "name": "cohort-breakdown",
            "state": "partial",
            "evidence": {
                "mechanism_metadata_present": bool(claims["by_mechanism"]),
                "language_metadata_present": bool(claims["by_language"]),
                "detector_metadata_recorded": aggregate[
                    "finding_metadata_availability"
                ]["source_tool_present"],
                "adequate_protected_subgroup_sizes": False,
            },
            "blocker": "Metadata exists, but protected family, mechanism, language, and detector cohorts are not adequately sized.",
        },
        {
            "gate_id": "G06",
            "name": "read-only-tools",
            "state": "documented-fail",
            "evidence": {
                "deterministic_retrieval_exists": True,
                "bounded_slicing_exists": True,
                "configuration_driven_agent_tool_allowlist": False,
                "agent_tool_provenance_contract": False,
            },
            "blocker": "The read-only agent tool surface remains design-only and has no enforced allowlist or provenance contract.",
        },
        {
            "gate_id": "G07",
            "name": "independent-verification",
            "state": "partial",
            "evidence": {
                "claims": claims["claims"],
                "snapshot_bound": claims["snapshot_bound"],
                "verifications_by_status": claims["verifications_by_status"],
                "supported_mechanism_categories": len(claims["by_mechanism"]),
                "supported_languages_observed": len(claims["by_language"]),
            },
            "blocker": "Independent syntax verification exists, but mechanism coverage is not adequate for an unfrozen proposed cohort.",
        },
    ]
    return {
        "schema_version": 1,
        "audit_id": "opt010-offline-readiness-v1",
        "status": "offline-remediation-or-evidence-needed",
        "recorded_at": "2026-08-18",
        "input_digests": observed_digests,
        "store": {
            "open_mode": "sqlite-uri-mode-ro-plus-query-only",
            "sha256_before": before_store_sha256,
            "sha256_after": after_store_sha256,
            "byte_identical": True,
        },
        "lifecycle_observed": opt010,
        "configuration_bounds": config_bounds,
        "aggregate_inventory": aggregate,
        "gate_classification": gates,
        "decision": {
            "documented_pass": sum(gate["state"] == "documented-pass" for gate in gates),
            "partial": sum(gate["state"] == "partial" for gate in gates),
            "documented_fail": sum(gate["state"] == "documented-fail" for gate in gates),
            "unresolved": sum(gate["state"] == "unresolved" for gate in gates),
            "all_seven_pass": all(
                gate["state"] == "documented-pass" for gate in gates
            ),
            "agentic_experiment_permitted": False,
            "opt_010_status": "open-deferred",
            "smallest_next_prerequisite": (
                "Separately authorize an offline implementation and independent negative-test "
                "qualification of a configuration-driven read-only agent tool allowlist with "
                "immutable-snapshot and per-tool provenance enforcement."
            ),
        },
        "sec_edgar_reserve": {
            "opt_014_role": "inactive-commercially-permissive-structurally-limited-reserve",
            "selected_or_acquired": False,
            "used_by_opt_010": False,
        },
        "accounting": {
            "audit_runs": 1,
            "row_identities_emitted": 0,
            "source_records_rendered": 0,
            "network_reads": 0,
            "network_uploads": 0,
            "provider_calls": 0,
            "provider_reported_tokens": 0,
            "provider_cost_usd": 0.0,
            "repository_materializations": 0,
            "repository_code_executions": 0,
            "scanner_processes": 0,
            "agentic_falsification_runs": 0,
            "production_store_mutations": 0,
            "schema_migrations": 0,
            "assessments_written": 0,
            "labels_written": 0,
            "model_training_runs": 0,
            "rescoring_runs": 0,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite existing audit: {args.output}")
    payload = build_audit(args.root)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        "OPT-010 readiness audit complete: "
        f"pass={payload['decision']['documented_pass']}; "
        f"partial={payload['decision']['partial']}; "
        f"fail={payload['decision']['documented_fail']}"
    )


if __name__ == "__main__":
    main()
