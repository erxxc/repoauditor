"""Multi-lens detection ensemble.

Runs each code region through the three framing lenses (OWASP / supply-chain /
agentic-surface), each backed by its versioned prompt under `lenses/`, augmented
with retrieval context (callers/callees and similar patterns pulled from the AST
index). Before persistence, each model citation is anchored to an exact repository
location. A uniquely misattributed citation is deterministically canonicalized; an absent
or ambiguous citation is logged as a validation failure and never becomes a malformed
`Finding`.

Findings from different lenses on the same region are **not** deduplicated here —
cross-lens agreement/disagreement is scoring input for `analyze/` later. Candidates
land with `falsification_status = unresolved`; the falsify stage decides which
survive. Severity from a lens is a *relative* signal, never treated as absolute.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pydantic import BaseModel, Field

from ..config import Config, get_config
from ..ingest import latest_snapshot
from ..llm import LLMClient, get_llm_client
from ..llm.prompt_security import (
    PROMPT_SECURITY_VERSION,
    delimit_repository_evidence,
    secure_system_prompt,
)
from ..map import ArchitectureMap, load_architecture
from ..sourcefiles import iter_source_files, read_numbered
from ..store import db
from ..store.models import (
    DetectionRegionRun,
    FalsificationStatus,
    Finding,
    RunStatus,
    Severity,
    ValidationFailure,
)
from .planning import (
    DetectionProjection,
    plan_detection_regions,
    project_detection_work,
    validate_detection_projection,
)
from .retrieval import RetrievalIndex

logger = logging.getLogger(__name__)

# Lens name -> versioned prompt file. Order is stable so runs are reproducible.
LENSES: dict[str, str] = {
    "owasp": "owasp_v3.md",
    "supply_chain": "supply_chain_v1.md",
    "agentic_surface": "agentic_surface_v1.md",
}
# Prompt version per lens (the v1 lens prompts already request a confidence field, so
# no _v2 was needed for detect). Exposed for the eval regression record.
DETECTION_CONTEXT_VERSION = "detection_context_v2"
LENS_PROMPT_VERSIONS: dict[str, str] = {
    name: f"{file[:-3]}+{PROMPT_SECURITY_VERSION}+{DETECTION_CONTEXT_VERSION}"
    for name, file in LENSES.items()
}
PROMPT_VERSION = "+".join(LENS_PROMPT_VERSIONS[name] for name in LENSES)
CITATION_INTEGRITY_VERSION = "citation_integrity_v1"
_LENS_DIR = Path(__file__).parent / "lenses"
_LENS_PROMPTS: dict[str, str] = {
    name: (_LENS_DIR / filename).read_text() for name, filename in LENSES.items()
}


class LensCandidate(BaseModel):
    """A single candidate a lens raised. Carries its mandatory citation + origin.

    No confidence/severity constraints on the schema itself (structured outputs
    don't enforce numeric bounds); `run_ensemble` clamps and validates in code.
    """

    title: str
    file: str
    line_start: int
    line_end: int
    citation_snippet: str
    severity: Severity
    confidence: float
    trust_boundary_ref: str | None = None
    rationale: str | None = None


class LensFindings(BaseModel):
    """Structured-output container: the findings a lens raised for one region."""

    findings: list[LensCandidate] = Field(default_factory=list)


# Kept as the canonical pre-store shape for the deterministic adapters (which still
# return candidates rather than persisted findings).
class CandidateFinding(BaseModel):
    """A pre-falsification candidate produced by a deterministic tool adapter."""

    title: str
    file: str
    line_start: int
    line_end: int
    citation_snippet: str
    identity_key: str | None = None
    source_tool: str
    producer: str | None = Field(default=None, exclude=True)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    trust_boundary_ref: str | None = None
    rationale: str | None = None


def _retrieval_context_with_provenance(
    index: RetrievalIndex, relative_file: str, file_text: str, *, limit: int = 3
) -> tuple[str, list[dict[str, str | int]]]:
    """Bounded external call-name context for a region (may be empty).

    Direct external callers of functions defined in the primary file carry more semantic
    information than whole-file call-token similarity. The index is syntactic rather than
    type-resolved, so these blocks are explicitly labelled call-name matches. External
    similar-pattern blocks fill any remaining slots; same-file blocks are redundant because
    the complete primary file is already present. The returned provenance describes only
    context that was actually appended; it neither changes selection nor infers an edge.
    """
    definitions = {
        definition.symbol for definition in index.functions_in_file(relative_file)
    }
    related = [
        ("CALL-NAME MATCH", caller, len(matched_symbols))
        for caller, matched_symbols in index.find_callers_matching(definitions)
        if caller.file != relative_file
    ]
    related.sort(
        key=lambda item: (
            _is_test_path(item[1].file),
            -item[2],
            item[1].file,
            item[1].line_start,
            item[1].symbol,
        )
    )
    seen = {
        (caller.file, caller.line_start, caller.symbol)
        for _basis, caller, _score in related
    }
    for similar in index.find_similar_patterns(file_text, limit=limit * 3):
        key = (similar.file, similar.line_start, similar.symbol)
        if similar.file == relative_file or key in seen:
            continue
        seen.add(key)
        related.append(("SIMILAR PATTERN", similar, 0))
    selected = related[:limit]
    if not selected:
        return "", []
    blocks = [
        f"# RELATED {basis}: {info.symbol} ({info.file}:{info.line_start})\n"
        f"{info.source}"
        for basis, info, _score in selected
    ]
    provenance = [
        {
            "basis": basis.lower().replace(" ", "-"),
            "file": info.file,
            "line_start": info.line_start,
            "symbol": info.symbol,
        }
        for basis, info, _score in selected
    ]
    return (
        "\n\n# --- external retrieval context ---\n" + "\n\n".join(blocks),
        provenance,
    )


def _retrieval_context(
    index: RetrievalIndex, relative_file: str, file_text: str, *, limit: int = 3
) -> str:
    """Backward-compatible text projection for callers that do not need provenance."""
    return _retrieval_context_with_provenance(
        index, relative_file, file_text, limit=limit
    )[0]


def _is_test_path(path: str) -> bool:
    normalized = "/" + path.replace("\\", "/").lower().strip("/") + "/"
    return "/test/" in normalized or "/tests/" in normalized or "/spec/" in normalized


class DetectionRun(list[Finding]):
    """List-compatible result with producer counts and generated scanner artifacts."""

    def __init__(
        self,
        findings: list[Finding],
        source_counts: dict[str, int],
        sarif_path: Path | None = None,
        semgrep_status: str | None = None,
        projection: DetectionProjection | None = None,
        selected_regions: list[dict[str, str]] | None = None,
        completed_region_calls: int = 0,
        skipped_completed_region_calls: int = 0,
        scanner_statuses: dict[str, str] | None = None,
        scanner_failures: dict[str, str] | None = None,
        scanner_executions: list[dict] | None = None,
        context_expansions: list[dict] | None = None,
    ):
        super().__init__(findings)
        self.source_counts = source_counts
        self.sarif_path = sarif_path
        self.semgrep_status = semgrep_status
        self.projection = projection
        self.selected_regions = selected_regions or []
        self.completed_region_calls = completed_region_calls
        self.skipped_completed_region_calls = skipped_completed_region_calls
        self.scanner_statuses = scanner_statuses or {}
        self.scanner_failures = scanner_failures or {}
        self.scanner_executions = scanner_executions or []
        self.context_expansions = context_expansions or []


def run_ensemble(
    repo_id: str,
    config: Config | None = None,
    llm: LLMClient | None = None,
    index: RetrievalIndex | None = None,
) -> DetectionRun:
    """Run the three-lens ensemble over an ingested + mapped repo; persist candidates.

    Repo-level entry point: resolves the snapshot, loads the architecture map from
    the store, builds the retrieval index, and runs every lens over every region.
    Returns the persisted (unresolved) findings, each tagged with its `source_lens`.
    """
    config = config or get_config()
    llm = llm or get_llm_client(config)
    threshold = config.llm.confidence_threshold
    snapshot_path, commit = latest_snapshot(config, repo_id)
    architecture = load_architecture(repo_id, commit, config)
    index = index or RetrievalIndex().build(snapshot_path)

    persisted: list[Finding] = []
    artifact_path = (
        config.resolve(config.paths.data_dir)
        / "artifacts" / repo_id / commit / "detect" / "semgrep.sarif"
    )
    sarif_path = None
    semgrep_status = None
    tool_candidates: list[CandidateFinding] = []
    scanner_statuses: dict[str, str] = {}
    scanner_failures: dict[str, str] = {}
    scanner_executions: list[dict] = []
    if config.detect.run_deterministic_tools:
        adapter_result = _run_deterministic_adapters(
            snapshot_path, config, artifact_path
        )
        # Test/scripted adapters historically returned the three-field public contract.
        # Preserve that seam while production adapters attach execution diagnostics.
        tool_candidates, sarif_path, semgrep_status = adapter_result[:3]
        if len(adapter_result) >= 5:
            scanner_statuses, scanner_failures = adapter_result[3:5]
        if len(adapter_result) >= 6:
            scanner_executions = adapter_result[5]
        for cand in tool_candidates:
            persisted.append(_persist_tool_candidate(cand, repo_id, architecture, config))
    else:
        from .deterministic import DETERMINISTIC_SCANNERS, SastAdapter

        sast = SastAdapter(sarif_output_path=artifact_path)
        sast.write_empty_artifact("disabled")
        sarif_path, semgrep_status = artifact_path, sast.run_status
        scanner_statuses = {
            name: "disabled"
            for name in DETERMINISTIC_SCANNERS
        }
        from .deterministic.execution import ScannerExecution

        scanner_executions = [
            ScannerExecution(
                scanner=name,
                status="disabled",
                applicable=None,
                output_valid=False,
                finding_count=0,
                target_count=0,
                target_count_basis="disabled",
            ).model_dump()
            for name in DETERMINISTIC_SCANNERS
        ]

    projection = project_detection_work(
        snapshot_path, config, lens_count=len(LENSES)
    )
    validate_detection_projection(projection, config)
    planned = plan_detection_regions(
        snapshot_path,
        config,
        commit=commit,
        architecture=architecture,
        tool_candidates=tool_candidates,
        index=index,
    )
    completed_region_calls = skipped_completed_region_calls = 0
    context_expansions: list[dict] = []
    for planned_region in planned:
        path = planned_region.path
        rel = planned_region.relative_path
        file_text = read_numbered(path)
        retrieval_text, retrieval_provenance = _retrieval_context_with_provenance(
            index, rel, path.read_text(errors="replace")
        )
        if retrieval_provenance:
            context_expansions.append({
                "primary_file": rel,
                "related": retrieval_provenance,
            })
        region = (
            f"# FILE: {rel}\n{file_text}"
            f"{retrieval_text}"
        )

        for lens in _LENS_PROMPTS:
            region_run = db.start_detection_region(
                DetectionRegionRun(
                    repo_id=repo_id,
                    commit_hash=commit,
                    file=rel,
                    lens=lens,
                    prompt_version=LENS_PROMPT_VERSIONS[lens],
                    selection_basis=planned_region.selection_basis,
                ),
                config,
            )
            if region_run.status is RunStatus.COMPLETED:
                skipped_completed_region_calls += 1
                continue
            try:
                completion = _call_lens(
                    llm,
                    lens,
                    region,
                    context={
                        "stage": "detect", "repo_id": repo_id,
                        "lens": lens, "file": rel,
                    },
                )
                finding_count = 0
                for cand in completion.value.findings:
                    cand = _canonicalize_citation(
                        cand, index, rel, lens, config
                    )
                    if cand is None:
                        continue
                    cand, low = _resolve_confidence(
                        cand, lens, _LENS_PROMPTS[lens],
                        index, repo_id, llm, threshold
                    )
                    cand = _canonicalize_citation(
                        cand, index, rel, lens, config
                    )
                    if cand is None:
                        continue
                    persisted.append(
                        _persist_candidate(cand, lens, repo_id, architecture, config, low)
                    )
                    finding_count += 1
                db.finish_detection_region(
                    region_run.id,
                    RunStatus.COMPLETED,
                    finding_count=finding_count,
                    config=config,
                )
                completed_region_calls += 1
            except BaseException as exc:
                db.finish_detection_region(
                    region_run.id,
                    RunStatus.FAILED,
                    failure_detail=f"{type(exc).__name__}: {exc}"[:4000],
                    config=config,
                )
                raise

    all_findings = db.list_findings(repo_id, config)
    source_counts = {
        "semgrep": sum(c.producer == "semgrep" for c in tool_candidates),
        "semgrep-supplemental": sum(
            c.producer == "semgrep-supplemental" for c in tool_candidates
        ),
        "gitleaks": sum(c.producer == "gitleaks" for c in tool_candidates),
        "pip-audit": sum(c.producer == "pip-audit" for c in tool_candidates),
        "osv-scanner": sum(c.producer == "osv-scanner" for c in tool_candidates),
        "llm-ensemble": sum(f.source_lens is not None for f in all_findings),
    }
    return DetectionRun(
        all_findings,
        source_counts,
        sarif_path,
        semgrep_status,
        projection=projection,
        selected_regions=[
            {"file": item.relative_path, "basis": item.selection_basis}
            for item in planned
        ],
        completed_region_calls=completed_region_calls,
        skipped_completed_region_calls=skipped_completed_region_calls,
        scanner_statuses=scanner_statuses,
        scanner_failures=scanner_failures,
        scanner_executions=scanner_executions,
        context_expansions=context_expansions,
    )


def _call_lens(
    llm: LLMClient,
    lens: str,
    region: str,
    *,
    context: dict,
):
    """Shared structured lens call used by production and manufactured qualification."""
    try:
        prompt = _LENS_PROMPTS[lens]
        prompt_version = LENS_PROMPT_VERSIONS[lens]
    except KeyError as exc:
        raise ValueError(f"unknown detection lens: {lens}") from exc
    return llm.call(
        module="detect",
        prompt_version=prompt_version,
        system=secure_system_prompt(prompt),
        user=delimit_repository_evidence(region),
        schema=LensFindings,
        context=context,
    )


def _same_file(candidate: str, actual: str) -> bool:
    candidate = candidate.replace("\\", "/")
    actual = actual.replace("\\", "/")
    return candidate == actual or candidate.endswith(f"/{actual}") or actual.endswith(
        f"/{candidate}"
    )


def _log_citation_failure(
    cand: LensCandidate,
    lens: str,
    current_file: str,
    error: str,
    config: Config,
) -> None:
    db.insert_validation_failure(
        ValidationFailure(
            module="detect.citation",
            prompt_version=(
                f"{LENS_PROMPT_VERSIONS[lens]}+{CITATION_INTEGRITY_VERSION}"
            ),
            raw_response=cand.model_dump_json()[:2000],
            validation_error=(
                f"{error}; prompt_region={current_file}; declared_file={cand.file}; "
                f"declared_lines={cand.line_start}-{cand.line_end}"
            )[:2000],
        ),
        config,
    )


def _canonicalize_citation(
    cand: LensCandidate,
    index: RetrievalIndex,
    current_file: str,
    lens: str,
    config: Config,
) -> LensCandidate | None:
    """Anchor a verbatim model citation to one deterministic repository location.

    A unique occurrence is canonicalized even when the model copied it from retrieval
    context but attributed it to the primary prompt file. Ambiguous or absent citations
    are logged and rejected rather than persisted as malformed Findings.
    """
    locations = index.locate_citation(cand.citation_snippet)
    if not locations:
        _log_citation_failure(
            cand, lens, current_file,
            "verbatim citation does not occur in any indexed source file", config,
        )
        return None

    declared = [
        location for location in locations if _same_file(cand.file, location.file)
    ]
    overlapping = [
        location for location in declared
        if location.line_start <= cand.line_end and cand.line_start <= location.line_end
    ]
    if len(overlapping) == 1:
        selected = overlapping[0]
    elif len(declared) == 1:
        selected = declared[0]
    elif len(locations) == 1:
        selected = locations[0]
    else:
        _log_citation_failure(
            cand, lens, current_file,
            f"verbatim citation is ambiguous across {len(locations)} locations", config,
        )
        return None

    updates = {
        "file": selected.file,
        "line_start": selected.line_start,
        "line_end": selected.line_end,
    }
    if (
        not _same_file(cand.file, selected.file)
        or cand.line_start != selected.line_start
        or cand.line_end != selected.line_end
    ):
        correction = (
            f"[citation canonicalized by {CITATION_INTEGRITY_VERSION}: "
            f"{cand.file}:{cand.line_start}-{cand.line_end} -> "
            f"{selected.file}:{selected.line_start}-{selected.line_end}]"
        )
        updates["rationale"] = f"{correction} {cand.rationale or ''}".strip()
    return cand.model_copy(update=updates)


def _run_deterministic_adapters(
    snapshot_path: Path, config: Config, sarif_output_path: Path,
) -> tuple[
    list[CandidateFinding],
    Path | None,
    str | None,
    dict[str, str],
    dict[str, str],
    list[dict],
]:
    """Run the SAST / SCA / secret adapters over the snapshot, in parallel.

    Each adapter shells out to an external scanner and already degrades to no findings
    when its binary is absent; `_safe_run` adds a belt-and-suspenders guard so one
    adapter failing never sinks the others (or the whole detect run).
    """
    from .deterministic import SastAdapter, ScaAdapter, SecretsAdapter
    from .deterministic.provenance import supplemental_semgrep_provenance

    timeout = config.detect.tool_timeout_seconds
    sast = SastAdapter(timeout, sarif_output_path=sarif_output_path)
    supplemental_rules, supplemental_digest, _ = supplemental_semgrep_provenance()
    supplemental_path = sarif_output_path.with_name("semgrep-supplemental.sarif")
    supplemental = SastAdapter(
        timeout,
        sarif_output_path=supplemental_path,
        configuration=str(supplemental_rules),
        configuration_label=f"repoauditor-supplemental@sha256:{supplemental_digest}",
        scanner_name="semgrep-supplemental",
        producer="semgrep-supplemental",
        applicable_extensions=frozenset({
            ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
        }),
    )
    sca = ScaAdapter(timeout)
    secrets = SecretsAdapter(timeout)
    adapters = [sast, supplemental, sca, secrets]
    candidates: list[CandidateFinding] = []
    with ThreadPoolExecutor(max_workers=len(adapters)) as pool:
        for cands in pool.map(lambda a: _safe_run(a, snapshot_path), adapters):
            candidates.extend(cands)
    if not sarif_output_path.is_file():
        sast.write_empty_artifact(sast.run_status or "failed")
    if not supplemental_path.is_file():
        supplemental.write_empty_artifact(supplemental.run_status or "failed")
    statuses = {
        "semgrep": sast.run_status or "failed",
        "semgrep-supplemental": supplemental.run_status or "failed",
        **sca.run_statuses,
        "gitleaks": secrets.run_status,
    }
    failures = {
        name: detail
        for name, detail in {
            "semgrep": sast.failure_detail,
            "semgrep-supplemental": supplemental.failure_detail,
            **sca.failure_details,
            "gitleaks": secrets.failure_detail,
        }.items()
        if detail
    }
    executions = [
        sast.execution(),
        supplemental.execution(),
        *sca.executions(),
        secrets.execution(),
    ]
    return (
        candidates,
        sarif_output_path if sarif_output_path.is_file() else None,
        sast.run_status,
        statuses,
        failures,
        [record.model_dump() for record in executions],
    )


def _safe_run(adapter, snapshot_path: Path) -> list[CandidateFinding]:
    try:
        return adapter.run(snapshot_path)
    except Exception as exc:  # an adapter must never break the detect run
        logger.warning("deterministic adapter %s failed: %s", adapter.tool_name, exc)
        detail = f"{type(exc).__name__}: {exc}"[:500]
        if hasattr(adapter, "run_status"):
            adapter.run_status = "failed"
        if hasattr(adapter, "failure_detail"):
            adapter.failure_detail = detail
        for name, status in getattr(adapter, "run_statuses", {}).items():
            if status == "not-run":
                adapter.run_statuses[name] = "failed"
                adapter.failure_details[name] = detail
        return []


def _persist_tool_candidate(
    cand: CandidateFinding, repo_id: str, architecture: ArchitectureMap, config: Config,
) -> Finding:
    """Persist a deterministic-tool candidate as an `unresolved` finding (source_tool set).

    Tool findings carry no trust-boundary reference, so they fall back to the primary
    boundary (`trust_boundary_id(None)`) — the foreign-key link is never null, per the
    architecture-first rule. Severity is a raw tool signal here; it is only ever raised
    later given corroboration or a confirming falsification pass.
    """
    finding = Finding(
        repo_id=repo_id,
        title=cand.title,
        file=cand.file,
        line_start=cand.line_start,
        line_end=max(cand.line_end, cand.line_start),
        citation_snippet=cand.citation_snippet,
        identity_key=cand.identity_key,
        source_tool=cand.source_tool,
        confidence=min(max(cand.confidence, 0.0), 1.0),
        severity=cand.severity,
        falsification_status=FalsificationStatus.UNRESOLVED,
        trust_boundary_id=architecture.trust_boundary_id(cand.trust_boundary_ref),
        description=cand.rationale,
    )
    finding_id = db.upsert_detected_finding(finding, config)
    return finding.model_copy(update={"id": finding_id})


def _resolve_confidence(cand, lens, prompt, index, repo_id, llm, threshold):
    """Low-confidence candidate -> one broader-retrieval re-score. Returns (cand, still_low)."""
    if cand.confidence >= threshold:
        return cand, False
    # Broaden context: callers/callees/similar patterns for this candidate.
    similar = index.find_similar_patterns(cand.citation_snippet, limit=5)
    extra = "\n\n# --- broader retrieval (re-score) ---\n" + "\n\n".join(
        f"# {i.symbol} ({i.file}:{i.line_start})\n{i.source}" for i in similar
    )
    rescore = llm.call(
        module="detect",
        prompt_version=f"{LENS_PROMPT_VERSIONS[lens]}+rescore",
        system=secure_system_prompt(prompt),
        user=delimit_repository_evidence(
            f"Re-score this single candidate with the added context.\n"
            f"citation:\n{cand.citation_snippet}{extra}"
        ),
        schema=LensFindings,
        context={"stage": "detect", "repo_id": repo_id, "lens": lens, "rescore": True},
    )
    for c in rescore.value.findings:
        if c.citation_snippet == cand.citation_snippet:
            return c, c.confidence < threshold
    return cand, True  # re-score did not re-surface it -> still low confidence


def _persist_candidate(
    cand: LensCandidate,
    lens: str,
    repo_id: str,
    architecture: ArchitectureMap,
    config: Config,
    low_confidence: bool = False,
) -> Finding:
    # A finding that stays low-confidence after the re-score is recorded but flagged;
    # it is not rounded up into a confident result (the falsify pass still weighs in).
    description = cand.rationale
    if low_confidence:
        note = f"[low confidence {cand.confidence:.2f} after re-score]"
        description = f"{note} {description or ''}".strip()
    finding = Finding(
        repo_id=repo_id,
        title=cand.title,
        file=cand.file,
        line_start=cand.line_start,
        line_end=max(cand.line_end, cand.line_start),
        citation_snippet=cand.citation_snippet,
        source_lens=lens,
        confidence=min(max(cand.confidence, 0.0), 1.0),
        severity=cand.severity,
        falsification_status=FalsificationStatus.UNRESOLVED,
        trust_boundary_id=architecture.trust_boundary_id(cand.trust_boundary_ref),
        description=description,
    )
    finding_id = db.upsert_detected_finding(finding, config)
    return finding.model_copy(update={"id": finding_id})
