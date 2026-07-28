"""Paid manufactured qualification for the OWASP archive-traversal detection lens.

The answer key stays outside the scanned snapshot. This qualifies one prompt/mechanism
pair; it does not estimate real-world precision or recall and does not persist findings.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from ..config import Config, get_config
from ..detect.ensemble import LENS_PROMPT_VERSIONS, LensCandidate, _call_lens
from ..llm import LLMClient, get_llm_client
from ..sourcefiles import read_numbered


class DetectionSentinelCase(BaseModel):
    id: str
    file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    citation_snippet: str
    expected_detection: Literal["raised", "absent"]
    ground_truth_basis: str = Field(min_length=1)


class DetectionSentinelManifest(BaseModel):
    schema_version: str
    kind: str
    purpose: str
    cases: list[DetectionSentinelCase] = Field(min_length=2)

    @model_validator(mode="after")
    def _balanced(self) -> "DetectionSentinelManifest":
        if {case.expected_detection for case in self.cases} != {"raised", "absent"}:
            raise ValueError("detection sentinels require positive and negative controls")
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("detection sentinel ids must be unique")
        return self


class DetectionSentinelObservation(BaseModel):
    sentinel_id: str
    expected: Literal["raised", "absent"]
    observed: Literal["raised", "absent"]
    passed: bool
    candidates: list[LensCandidate]
    semantic_match_count: int


class DetectionSentinelQualification(BaseModel):
    schema_version: str
    snapshot_digest: str
    provider: str
    model: str
    prompt_version: str
    sampling_seed: int | None
    observations: list[DetectionSentinelObservation]
    positive_recovery: float
    negative_recovery: float
    qualified: bool
    model_usage: dict[str, int] | None = None
    evidence_scope: str = (
        "manufactured archive controls only; not real-world precision or recall"
    )


def _digest(snapshot: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in snapshot.rglob("*") if item.is_file()):
        digest.update(path.relative_to(snapshot).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def load_detection_sentinels(
    fixture_root: Path,
) -> tuple[DetectionSentinelManifest, Path, str]:
    fixture_root = Path(fixture_root)
    snapshot = fixture_root / "snapshot"
    manifest_path = fixture_root / "manifest.json"
    if not snapshot.is_dir() or not manifest_path.is_file():
        raise ValueError(f"detection sentinel fixture is incomplete: {fixture_root}")
    manifest = DetectionSentinelManifest.model_validate_json(manifest_path.read_text())
    if manifest.kind != "manufactured_solution":
        raise ValueError("detection sentinel manifest must be manufactured_solution")
    for case in manifest.cases:
        source = (snapshot / case.file).resolve()
        try:
            source.relative_to(snapshot.resolve())
        except ValueError as exc:
            raise ValueError(f"detection sentinel {case.id} escapes snapshot") from exc
        if not source.is_file():
            raise ValueError(f"detection sentinel source is missing: {case.file}")
        lines = source.read_text().splitlines()
        cited = "\n".join(lines[case.line_start - 1:case.line_end])
        if case.citation_snippet not in cited:
            raise ValueError(
                f"detection sentinel {case.id} citation is outside its declared range"
            )
    return manifest, snapshot, _digest(snapshot)


def evaluate_archive_detection_sentinels(
    fixture_root: Path,
    *,
    config: Config | None = None,
    llm: LLMClient | None = None,
) -> DetectionSentinelQualification:
    """Run only OWASP v2 over the fixed positive/negative archive pair."""
    config = config or get_config()
    llm = llm or get_llm_client(config)
    manifest, snapshot, digest = load_detection_sentinels(fixture_root)
    observations: list[DetectionSentinelObservation] = []
    for case in manifest.cases:
        source = snapshot / case.file
        region = f"# FILE: {case.file}\n{read_numbered(source)}"
        completion = _call_lens(
            llm,
            "owasp",
            region,
            context={
                "stage": "qualify-detection",
                "repo_id": "manufactured_archive_controls",
                "lens": "owasp",
                "file": case.file,
                "sentinel_id": case.id,
            },
        )
        candidates = [
            candidate for candidate in completion.value.findings
            if candidate.file.replace("\\", "/").lstrip("./") == case.file
        ]
        semantic_matches = [
            candidate for candidate in candidates
            if _matches_archive_case(candidate, case, source.read_text())
        ]
        if case.expected_detection == "raised":
            observed: Literal["raised", "absent"] = (
                "raised" if semantic_matches else "absent"
            )
        else:
            # The patched file is a deliberately tiny clean control. Any emitted candidate
            # is disclosed as a negative-control failure rather than silently filtered.
            observed = "raised" if candidates else "absent"
        observations.append(DetectionSentinelObservation(
            sentinel_id=case.id,
            expected=case.expected_detection,
            observed=observed,
            passed=observed == case.expected_detection,
            candidates=candidates,
            semantic_match_count=len(semantic_matches),
        ))

    positives = [item for item in observations if item.expected == "raised"]
    negatives = [item for item in observations if item.expected == "absent"]
    return DetectionSentinelQualification(
        schema_version=manifest.schema_version,
        snapshot_digest=digest,
        provider=config.llm.provider,
        model=config.model.name,
        prompt_version=LENS_PROMPT_VERSIONS["owasp"],
        sampling_seed=llm.sampling_seed,
        observations=observations,
        positive_recovery=sum(item.passed for item in positives) / len(positives),
        negative_recovery=sum(item.passed for item in negatives) / len(negatives),
        qualified=all(item.passed for item in observations),
    )


def evaluate_xml_detection_sentinels(
    fixture_root: Path,
    *,
    config: Config | None = None,
    llm: LLMClient | None = None,
) -> DetectionSentinelQualification:
    """Run only OWASP v3 over the fixed positive/negative XML representation pair."""
    config = config or get_config()
    llm = llm or get_llm_client(config)
    manifest, snapshot, digest = load_detection_sentinels(fixture_root)
    observations: list[DetectionSentinelObservation] = []
    for case in manifest.cases:
        source = snapshot / case.file
        region = f"# FILE: {case.file}\n{read_numbered(source)}"
        completion = _call_lens(
            llm,
            "owasp",
            region,
            context={
                "stage": "qualify-xml-detection",
                "repo_id": "manufactured_xml_controls",
                "lens": "owasp",
                "file": case.file,
                "sentinel_id": case.id,
            },
        )
        candidates = [
            candidate for candidate in completion.value.findings
            if candidate.file.replace("\\", "/").lstrip("./") == case.file
        ]
        semantic_matches = [
            candidate for candidate in candidates
            if _matches_xml_case(candidate, case, source.read_text())
        ]
        if case.expected_detection == "raised":
            observed: Literal["raised", "absent"] = (
                "raised" if semantic_matches else "absent"
            )
        else:
            observed = "raised" if candidates else "absent"
        observations.append(DetectionSentinelObservation(
            sentinel_id=case.id,
            expected=case.expected_detection,
            observed=observed,
            passed=observed == case.expected_detection,
            candidates=candidates,
            semantic_match_count=len(semantic_matches),
        ))

    positives = [item for item in observations if item.expected == "raised"]
    negatives = [item for item in observations if item.expected == "absent"]
    return DetectionSentinelQualification(
        schema_version=manifest.schema_version,
        snapshot_digest=digest,
        provider=config.llm.provider,
        model=config.model.name,
        prompt_version=LENS_PROMPT_VERSIONS["owasp"],
        sampling_seed=llm.sampling_seed,
        observations=observations,
        positive_recovery=sum(item.passed for item in positives) / len(positives),
        negative_recovery=sum(item.passed for item in negatives) / len(negatives),
        qualified=all(item.passed for item in observations),
        evidence_scope=(
            "manufactured XML representation controls only; "
            "not real-world precision or recall"
        ),
    )


def _matches_archive_case(
    candidate: LensCandidate,
    case: DetectionSentinelCase,
    source: str,
) -> bool:
    """Require location, citation integrity, and mechanism—not same-file overlap alone."""
    overlaps = (
        candidate.line_start <= case.line_end
        and candidate.line_end >= case.line_start
    )
    text = f"{candidate.title}\n{candidate.rationale or ''}".lower()
    mechanism = (
        "path traversal" in text
        or "zip slip" in text
        or (
            "archive" in text
            and any(term in text for term in ("escape", "outside", "containment", "entry"))
        )
    )
    return overlaps and candidate.citation_snippet in source and mechanism


def _matches_xml_case(
    candidate: LensCandidate,
    case: DetectionSentinelCase,
    source: str,
) -> bool:
    """Require location, citation integrity, and representation-mismatch mechanism."""
    overlaps = (
        candidate.line_start <= case.line_end
        and candidate.line_end >= case.line_start
    )
    text = f"{candidate.title}\n{candidate.rationale or ''}".lower()
    representation = any(
        term in text
        for term in (
            "parser differential",
            "signature wrapping",
            "different parse",
            "distinct representation",
            "separate representation",
            "validated representation",
        )
    )
    security_decision = any(
        term in text for term in ("signature", "authentication", "verified", "validation")
    )
    return (
        overlaps
        and candidate.citation_snippet in source
        and representation
        and security_decision
    )


def render_detection_qualification(result: DetectionSentinelQualification) -> str:
    rows = [
        (
            f"{'PASS' if item.passed else 'MISS'} {item.sentinel_id}: "
            f"expected={item.expected} observed={item.observed} "
            f"candidates={len(item.candidates)} semantic_matches={item.semantic_match_count}"
        )
        for item in result.observations
    ]
    return "\n".join([
        "Manufactured archive-detection qualification",
        *rows,
        (
            f"positive_recovery={result.positive_recovery:.3f}; "
            f"negative_recovery={result.negative_recovery:.3f}; "
            f"qualified={'yes' if result.qualified else 'no'}"
        ),
        f"instrument={result.provider}/{result.model}; scope={result.evidence_scope}",
    ])


def render_xml_detection_qualification(
    result: DetectionSentinelQualification,
) -> str:
    return render_detection_qualification(result).replace(
        "Manufactured archive-detection qualification",
        "Manufactured XML parser-differential detection qualification",
        1,
    )
