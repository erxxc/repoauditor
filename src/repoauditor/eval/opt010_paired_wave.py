"""Outcome-blind packet construction for the bounded OPT-010 paired wave.

The helper reads only the retained Semgrep SARIF named by the receipt.  It binds the
frozen snapshots, retrieval indexes, and architecture maps, derives mechanisms only
from canonical SARIF rule metadata, and fails closed before credential access when an
exact four-family, forty-identity packet cannot be formed.

Provider execution is deliberately unreachable from a packet-shortfall result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from ..detect.retrieval import RetrievalIndex
from ..falsify.slicing import build_structural_slice
from ..store.models import Finding, Severity
from .opt010_acquisition_qualification import (
    SUBJECTS,
    _detector_input_digest,
    _snapshot_digest,
)
from .opt010_paired_foundation import PROTOCOL_VERSION, SUPPORTED_CELLS


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-010-outcome-blind-packet-paired-run-receipt-2026-08-20.json"
WAVE_RESULT = ROOT / "docs/optimizations/opt-010-prospective-acquisition-instrument-qualification-wave-1-runtime-identity-retry-result-2026-08-19.json"
ARCHITECTURE_RESULT = ROOT / "docs/optimizations/opt-010-architecture-mechanism-eligibility-corrected-retry-result-2026-08-20.json"
WAVE_ROOT = ROOT / "data/artifacts/opt010-acquisition-instrument-qualification-wave-1-runtime-identity-retry"
ARCHITECTURE_ROOT = ROOT / "data/artifacts/opt010-architecture-mechanism-eligibility"
ARTIFACT_ROOT = ROOT / "data/artifacts/opt010-outcome-blind-packet-paired-run"
MAPPING_PATH = ARTIFACT_ROOT / "mechanism-mapping.json"
SHORTFALL_PATH = ARTIFACT_ROOT / "packet-shortfall.json"
PACKET_PATH = ARTIFACT_ROOT / "packet.json"
RESULT_PATH = ROOT / "docs/optimizations/opt-010-outcome-blind-packet-paired-run-result-2026-08-20.json"
FOCUSED_TEST = ROOT / "tests/test_opt_010_outcome_blind_packet_paired_run.py"

ELIGIBLE_SCANNERS = ("semgrep", "semgrep-supplemental")
CWE_MAPPING = {
    "CWE-77": "command_injection",
    "CWE-78": "command_injection",
    "CWE-89": "sql_injection",
    "CWE-502": "unsafe_deserialization",
    "CWE-918": "ssrf",
}
_CWE = re.compile(r"(?i)\bCWE[- ]?(77|78|89|502|918)\b")
MAX_PACKET_IDENTITIES = 40
MAX_FAMILY_IDENTITIES = 20
MAX_NEW_BYTES = 52_428_800
PRODUCTION_STORE_SHA256 = "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a"


@dataclass(frozen=True)
class Candidate:
    identity: str
    subject: str
    language: str
    scanner: str
    rule: str
    path: str
    line_start: int
    line_end: int
    mechanism: str


@dataclass(frozen=True)
class IssueGroup:
    identity: str
    subject: str
    language: str
    path: str
    line_start: int
    line_end: int
    mechanism: str
    member_count: int


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stable_hash(*parts: str) -> str:
    encoded = json.dumps(parts, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _canonical_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(_canonical_bytes(payload) + b"\n")
    os.replace(temporary, path)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key in sorted(value):
            yield from _strings(value[key])
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def mechanism_from_rule_properties(properties: Any) -> str | None:
    """Return one mapped mechanism from rule properties, never from result text."""
    cwes = {
        f"CWE-{match.group(1)}"
        for value in _strings(properties)
        for match in _CWE.finditer(value)
    }
    mechanisms = {CWE_MAPPING[cwe] for cwe in cwes}
    return next(iter(mechanisms)) if len(mechanisms) == 1 else None


def _canonical_path(uri: str) -> str | None:
    normalized = uri.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or "\x00" in normalized
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return None
    return path.as_posix()


def candidates_from_sarif(
    payload: dict[str, Any], *, subject: str, language: str, scanner: str
) -> list[Candidate]:
    """Parse only canonical rule metadata and physical locations from SARIF."""
    if scanner not in ELIGIBLE_SCANNERS or language not in SUPPORTED_CELLS:
        return []
    candidates: list[Candidate] = []
    for run in payload.get("runs", []):
        rules = {
            str(rule.get("id")): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            if rule.get("id")
        }
        for result in run.get("results", []):
            rule_id = str(result.get("ruleId", ""))
            rule = rules.get(rule_id)
            if rule is None:
                continue
            mechanism = mechanism_from_rule_properties(rule.get("properties", {}))
            if mechanism not in SUPPORTED_CELLS[language]:
                continue
            locations = result.get("locations") or []
            if len(locations) != 1:
                continue
            physical = locations[0].get("physicalLocation", {})
            uri = physical.get("artifactLocation", {}).get("uri")
            region = physical.get("region", {})
            if not isinstance(uri, str):
                continue
            path = _canonical_path(uri)
            start = region.get("startLine")
            end = region.get("endLine", start)
            if (
                path is None
                or not isinstance(start, int)
                or not isinstance(end, int)
                or start < 1
                or end < start
            ):
                continue
            identity = _stable_hash(
                PROTOCOL_VERSION,
                subject,
                scanner,
                rule_id,
                path,
                str(start),
                str(end),
                mechanism,
            )
            candidates.append(
                Candidate(
                    identity=identity,
                    subject=subject,
                    language=language,
                    scanner=scanner,
                    rule=rule_id,
                    path=path,
                    line_start=start,
                    line_end=end,
                    mechanism=mechanism,
                )
            )
    return candidates


def deduplicate(candidates: Iterable[Candidate]) -> list[IssueGroup]:
    """Merge transitively overlapping locations within a subject/path/mechanism."""
    buckets: dict[tuple[str, str, str, str], list[Candidate]] = defaultdict(list)
    for item in candidates:
        buckets[(item.subject, item.language, item.path, item.mechanism)].append(item)
    groups: list[IssueGroup] = []
    for (subject, language, path, mechanism), items in sorted(buckets.items()):
        ordered = sorted(items, key=lambda item: (item.line_start, item.line_end, item.identity))
        cluster: list[Candidate] = []
        cluster_end = -1
        for item in ordered:
            if cluster and item.line_start > cluster_end:
                groups.append(_issue_group(subject, language, path, mechanism, cluster))
                cluster = []
                cluster_end = -1
            cluster.append(item)
            cluster_end = max(cluster_end, item.line_end)
        if cluster:
            groups.append(_issue_group(subject, language, path, mechanism, cluster))
    return sorted(groups, key=lambda item: item.identity)


def _issue_group(
    subject: str,
    language: str,
    path: str,
    mechanism: str,
    members: list[Candidate],
) -> IssueGroup:
    identities = sorted(item.identity for item in members)
    return IssueGroup(
        identity=_stable_hash(PROTOCOL_VERSION, "issue-group", *identities),
        subject=subject,
        language=language,
        path=path,
        line_start=min(item.line_start for item in members),
        line_end=max(item.line_end for item in members),
        mechanism=mechanism,
        member_count=len(members),
    )


def select_packet(groups: Iterable[IssueGroup]) -> list[IssueGroup] | None:
    """Apply the frozen family/mechanism/stable-hash round robin."""
    remaining: dict[tuple[str, str], list[IssueGroup]] = defaultdict(list)
    for item in groups:
        remaining[(item.language, item.mechanism)].append(item)
    for items in remaining.values():
        items.sort(key=lambda item: item.identity)
    families = sorted(SUPPORTED_CELLS)
    selected: list[IssueGroup] = []
    family_counts: Counter[str] = Counter()
    while len(selected) < MAX_PACKET_IDENTITIES:
        advanced = False
        for family in families:
            if family_counts[family] >= MAX_FAMILY_IDENTITIES:
                continue
            for mechanism in sorted(SUPPORTED_CELLS[family]):
                bucket = remaining[(family, mechanism)]
                if bucket:
                    selected.append(bucket.pop(0))
                    family_counts[family] += 1
                    advanced = True
                    break
            if len(selected) == MAX_PACKET_IDENTITIES:
                break
        if not advanced:
            return None
    if any(family_counts[family] == 0 for family in families):
        return None
    return selected


def _preflight(receipt: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if not MAPPING_PATH.is_file() or SHORTFALL_PATH.exists() or PACKET_PATH.exists() or RESULT_PATH.exists():
        raise RuntimeError("packet-wave artifact state is not the authorized resume point")
    mapping = json.loads(MAPPING_PATH.read_text(encoding="utf-8"))
    if (
        mapping.get("frozen_before_scanner_artifact_access") is not True
        or mapping.get("cwe_mapping") != CWE_MAPPING
        or mapping.get("eligible_scanners") != list(ELIGIBLE_SCANNERS)
    ):
        raise RuntimeError("pre-artifact mechanism mapping drifted")
    for record in receipt["frozen_inputs"].values():
        if isinstance(record, dict) and _sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen input digest drifted")
    for record in receipt["frozen_instruments"].values():
        if _sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen instrument digest drifted")
    if _sha256(ROOT / "data/repoauditor.db") != PRODUCTION_STORE_SHA256:
        raise RuntimeError("production store digest drifted")
    branch = subprocess.run(
        ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=False)
    if branch != "main" or staged.returncode != 0:
        raise RuntimeError("workspace branch or index drifted")
    return (
        json.loads(WAVE_RESULT.read_text(encoding="utf-8")),
        json.loads(ARCHITECTURE_RESULT.read_text(encoding="utf-8")),
    )


def _validated_supported_candidates(
    wave: dict[str, Any], architecture: dict[str, Any]
) -> tuple[list[Candidate], list[Candidate], list[str]]:
    wave_by_identity = {item["stable_identity_sha256"]: item for item in wave["subjects"]}
    map_by_identity = {item["stable_identity_sha256"]: item for item in architecture["subjects"]}
    metadata_candidates: list[Candidate] = []
    verifier_candidates: list[Candidate] = []
    scanner_hashes: list[str] = []
    for subject in SUBJECTS:
        if subject.language not in SUPPORTED_CELLS:
            continue
        expected = wave_by_identity[subject.stable_identity]
        map_expected = map_by_identity[subject.stable_identity]
        snapshot = WAVE_ROOT / "subjects" / subject.stable_identity / "snapshot"
        head = (snapshot / ".git/HEAD").read_text(encoding="utf-8").strip()
        index = RetrievalIndex().build(snapshot)
        architecture_path = ARCHITECTURE_ROOT / f"architecture-{subject.stable_identity}.json"
        if (
            head != subject.commit
            or _snapshot_digest(snapshot)[0] != expected["snapshot_sha256"]
            or _detector_input_digest(snapshot)[0] != expected["detector_input_sha256"]
            or index.content_digest().removeprefix("sha256:") != expected["retrieval_index_sha256"]
            or _sha256(architecture_path) != map_expected["architecture_map_sha256"]
        ):
            raise RuntimeError("exact snapshot/index/map binding drifted")
        for scanner in ELIGIBLE_SCANNERS:
            sarif_path = WAVE_ROOT / "subjects" / subject.stable_identity / "scanners" / f"{scanner}.sarif"
            scanner_hashes.append(_sha256(sarif_path))
            parsed = json.loads(sarif_path.read_text(encoding="utf-8"))
            extracted = candidates_from_sarif(
                parsed,
                subject=subject.stable_identity,
                language=subject.language,
                scanner=scanner,
            )
            metadata_candidates.extend(extracted)
            for item in extracted:
                source = index.source_text(item.path)
                if source is None:
                    continue
                _, text = source
                if item.line_end > max(1, len(text.splitlines())):
                    continue
                finding = Finding(
                    repo_id=subject.stable_identity,
                    title=item.mechanism.replace("_", " "),
                    file=item.path,
                    line_start=item.line_start,
                    line_end=item.line_end,
                    citation_snippet="",
                    source_tool=item.scanner,
                    confidence=0.0,
                    severity=Severity.INFO,
                )
                if build_structural_slice(index, finding) is not None:
                    verifier_candidates.append(item)
    return metadata_candidates, verifier_candidates, sorted(scanner_hashes)


def _aggregate_counts(groups: list[IssueGroup]) -> dict[str, Any]:
    family = Counter(item.language for item in groups)
    mechanism = Counter(item.mechanism for item in groups)
    return {
        "eligible_issue_groups": len(groups),
        "by_supported_family": {
            name: family[name] for name in sorted(SUPPORTED_CELLS)
        },
        "by_mechanism": {name: mechanism[name] for name in sorted(set(CWE_MAPPING.values()))},
        "supported_families_with_eligible_groups": sum(family[name] > 0 for name in SUPPORTED_CELLS),
    }


def _new_data_bytes() -> int:
    paths = [Path(__file__), FOCUSED_TEST, RESULT_PATH]
    paths.extend(path for path in ARTIFACT_ROOT.rglob("*") if path.is_file())
    return sum(path.stat().st_size for path in paths if path.is_file())


def run() -> dict[str, Any]:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    wave, architecture = _preflight(receipt)
    metadata_candidates, candidates, scanner_hashes = _validated_supported_candidates(
        wave, architecture
    )
    metadata_groups = deduplicate(metadata_candidates)
    groups = deduplicate(candidates)
    packet = select_packet(groups)
    counts = _aggregate_counts(groups)
    if packet is not None:
        raise RuntimeError("complete packet requires the separately implemented live arm path")

    scanner_set_digest = hashlib.sha256("".join(scanner_hashes).encode()).hexdigest()
    shortfall = {
        "schema_version": 1,
        "status": "aggregate-packet-shortfall",
        "mapping_sha256": _sha256(MAPPING_PATH),
        "scanner_artifact_set_sha256": scanner_set_digest,
        "metadata_compatible_results": len(metadata_candidates),
        "metadata_deduplicated_issue_groups": len(metadata_groups),
        "verifier_constructible_results": len(candidates),
        **counts,
        "required_packet_identities": MAX_PACKET_IDENTITIES,
        "required_supported_families": len(SUPPORTED_CELLS),
        "complete_packet_frozen": False,
        "partial_packet_persisted_or_disclosed": False,
        "provider_gate_opened": False,
    }
    _write_json(SHORTFALL_PATH, shortfall)
    result: dict[str, Any] = {
        "schema_version": 1,
        "optimization": "OPT-010",
        "status": "stopped-aggregate-packet-shortfall",
        "interpretation": (
            "The retained supported-cell scanner inventory cannot form the exact frozen "
            "40-identity, four-family packet. This is a bounded wave-one shortfall, not "
            "evidence about issue outcomes or the general feasibility of OPT-010."
        ),
        "mechanism_mapping": {
            "frozen_before_scanner_artifact_access": True,
            "sha256": _sha256(MAPPING_PATH),
        },
        "packet": {
            "metadata_compatible_results": len(metadata_candidates),
            "metadata_deduplicated_issue_groups": len(metadata_groups),
            "verifier_constructible_results": len(candidates),
            **counts,
            "required_identities": MAX_PACKET_IDENTITIES,
            "required_supported_families": len(SUPPORTED_CELLS),
            "complete": False,
            "partial_packet_persisted_or_disclosed": False,
        },
        "unsupported_outer_denominator": {
            "languages": ["Go", "Rust"],
            "state": "verifier_unsupported",
            "admitted_to_packet": 0,
        },
        "paired_execution": {
            "started": False,
            "stop_reason": "exact-packet-shortfall",
            "terminal_state_counts_by_arm": {},
        },
        "resource_accounting": {
            "provider_attempts": 0,
            "public_source_transmissions": 0,
            "provider_reported_tokens": 0,
            "known_dated_price_cost_usd": 0.0,
            "network_reads_or_uploads": 0,
            "keychain_or_credential_reads": 0,
            "production_store_reads": 0,
            "production_store_mutations": 0,
            "scanner_processes": 0,
            "repository_materializations": 0,
            "repository_code_executions": 0,
            "human_reviews": 0,
            "outcomes_read": 0,
            "assessments": 0,
            "labels": 0,
            "model_training_runs": 0,
            "rescoring_runs": 0,
            "workspace_branch_or_index_mutations": 0,
            "commits": 0,
            "merges": 0,
            "pushes": 0,
            "lifecycle_changes": 0,
            "new_data_bytes": 0,
        },
        "production_store": {
            "expected_sha256": PRODUCTION_STORE_SHA256,
            "after_sha256": _sha256(ROOT / "data/repoauditor.db"),
            "byte_identical": _sha256(ROOT / "data/repoauditor.db") == PRODUCTION_STORE_SHA256,
        },
        "gates": {
            "g03b_decided": False,
            "g04_empirical_decided": False,
            "opt010_status_changed": False,
        },
    }
    for _ in range(4):
        _write_json(RESULT_PATH, result)
        result["resource_accounting"]["new_data_bytes"] = _new_data_bytes()
    _write_json(RESULT_PATH, result)
    if result["resource_accounting"]["new_data_bytes"] > MAX_NEW_BYTES:
        raise RuntimeError("new-data ceiling exceeded")
    if not result["production_store"]["byte_identical"]:
        raise RuntimeError("production store changed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("--run is required")
    print(json.dumps(run(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
