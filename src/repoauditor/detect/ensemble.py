"""Multi-lens detection ensemble.

Runs each code region through the three framing lenses (OWASP / supply-chain /
agentic-surface), each backed by its versioned prompt under `lenses/`, augmented
with retrieval context (callers/callees and similar patterns pulled from the AST
index). Every candidate is persisted as a `Finding` tagged with its `source_lens`.

Findings from different lenses on the same region are **not** deduplicated here —
cross-lens agreement/disagreement is scoring input for `analyze/` later. Candidates
land with `falsification_status = unresolved`; the falsify stage decides which
survive. Severity from a lens is a *relative* signal, never treated as absolute.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from ..config import Config, get_config
from ..ingest import latest_snapshot
from ..llm import LLMClient, get_llm_client
from ..map import ArchitectureMap, load_architecture
from ..sourcefiles import iter_source_files, read_numbered
from ..store import db
from ..store.models import FalsificationStatus, Finding, Severity
from .retrieval import RetrievalIndex

# Lens name -> versioned prompt file. Order is stable so runs are reproducible.
LENSES: dict[str, str] = {
    "owasp": "owasp_v1.md",
    "supply_chain": "supply_chain_v1.md",
    "agentic_surface": "agentic_surface_v1.md",
}
# Prompt version per lens (the v1 lens prompts already request a confidence field, so
# no _v2 was needed for detect). Exposed for the eval regression record.
LENS_PROMPT_VERSIONS: dict[str, str] = {name: file[:-3] for name, file in LENSES.items()}
PROMPT_VERSION = "+".join(LENS_PROMPT_VERSIONS[name] for name in LENSES)
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
    source_tool: str
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    trust_boundary_ref: str | None = None
    rationale: str | None = None


def _retrieval_context(index: RetrievalIndex, file_text: str) -> str:
    """Related call sites for a region, formatted for the prompt (may be empty)."""
    similar = index.find_similar_patterns(file_text, limit=3)
    if not similar:
        return ""
    blocks = [
        f"# RELATED: {info.symbol} ({info.file}:{info.line_start})\n{info.source}"
        for info in similar
    ]
    return "\n\n# --- related call sites (retrieval) ---\n" + "\n\n".join(blocks)


def run_ensemble(
    repo_id: str,
    config: Config | None = None,
    llm: LLMClient | None = None,
    index: RetrievalIndex | None = None,
) -> list[Finding]:
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
    for path in iter_source_files(snapshot_path):
        rel = path.relative_to(snapshot_path).as_posix()
        file_text = read_numbered(path)
        region = f"# FILE: {rel}\n{file_text}{_retrieval_context(index, path.read_text(errors='replace'))}"

        for lens, prompt in _LENS_PROMPTS.items():
            completion = llm.call(
                module="detect",
                prompt_version=LENS_PROMPT_VERSIONS[lens],
                system=prompt,
                user=region,
                schema=LensFindings,
                context={"stage": "detect", "repo_id": repo_id, "lens": lens, "file": rel},
            )
            for cand in completion.value.findings:
                cand, low = _resolve_confidence(cand, lens, prompt, index, repo_id, llm, threshold)
                persisted.append(
                    _persist_candidate(cand, lens, repo_id, architecture, config, low)
                )
    return persisted


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
        system=prompt,
        user=f"Re-score this single candidate with the added context.\n"
             f"citation:\n{cand.citation_snippet}{extra}",
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
    finding_id = db.insert_finding(finding, config)
    return finding.model_copy(update={"id": finding_id})
