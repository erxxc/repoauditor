"""Severity adjudication / normalization — with debate framing.

When several sources (deterministic tools and/or ensemble lenses) flag the same
region but disagree on severity, this stage resolves the conflict into one canonical
`Finding`. It implements a **debate-style adjudication** (structured deliberation
before commit, in the LLM-debate lineage): the conflicting sources' *reasoning* — not
just their severity values — is laid out together, and the adjudicator produces either
a synthesized consensus with documented rationale or an explicit non-consensus. A
non-consensus (or a low-confidence one) is routed to the review/ checkpoint as
`unresolved` rather than being silently resolved to one value. The full debate trail
(every position + the outcome) is persisted so a reviewer can see *why* the sources
disagreed, not just that they did.

The core rule is enforced in code, not just the prompt: the adjudicated severity is
**capped at the strongest severity any single source actually asserted** — evidence
is never manufactured. Because a conflict group has ≥2 independent sources, that
corroboration is what licenses keeping the higher end of the range; single-source
findings are passed through unchanged (no upgrade without corroboration).
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from ..config import Config, get_config
from ..llm import LLMClient, get_llm_client
from ..store import db
from ..store.models import (
    AdjudicationDebate,
    Corroboration,
    DebatePosition,
    FalsificationStatus,
    Finding,
    Severity,
    SourceType,
    cap_severity,
    severity_rank,
)

PROMPT_VERSION = "severity_adjudication_v3"
PROMPT = (Path(__file__).parent / "prompts" / f"{PROMPT_VERSION}.md").read_text()


class Adjudication(BaseModel):
    """Structured output of a severity adjudication: the resolved call + why."""

    severity: Severity
    rationale: str
    # Debate framing (severity_adjudication_v3): False means the sources genuinely
    # conflict and no synthesis is warranted — the finding is routed to review as
    # `unresolved` instead of forcing a pick.
    consensus: bool = True
    # The model's confidence in the resolution (severity_adjudication_v2+). Below the
    # threshold, both original severities are kept and the adjudicated one is `unresolved`.
    confidence: float = 1.0


def _overlaps(a: Finding, b: Finding) -> bool:
    return a.file == b.file and a.line_start <= b.line_end and b.line_start <= a.line_end


def _group_overlapping(findings: list[Finding]) -> list[list[Finding]]:
    """Cluster findings that cover the same file+overlapping lines (order-stable)."""
    groups: list[list[Finding]] = []
    for finding in findings:
        for group in groups:
            if any(_overlaps(finding, member) for member in group):
                group.append(finding)
                break
        else:
            groups.append([finding])
    return groups


def _source_of(finding: Finding) -> tuple[SourceType, str]:
    if finding.source_tool is not None:
        return SourceType.TOOL, finding.source_tool
    return SourceType.LENS, finding.source_lens or "unknown"


def _reasoning_of(finding: Finding) -> str:
    """The argument a source made for its severity — its description, else its title."""
    return (finding.description or finding.title or "").strip()


def _positions(group: list[Finding]) -> list[DebatePosition]:
    """Each source's stance in the debate: its severity call *and* its reasoning."""
    positions: list[DebatePosition] = []
    for finding in group:
        source_type, source_name = _source_of(finding)
        positions.append(
            DebatePosition(
                source_type=source_type,
                source_name=source_name,
                severity=finding.severity,
                reasoning=_reasoning_of(finding),
            )
        )
    return positions


def adjudicate(
    candidates: list[Finding],
    config: Config | None = None,
    llm: LLMClient | None = None,
) -> list[Finding]:
    """Resolve conflicting severities across overlapping findings into canonical ones.

    Single-source (or already-agreeing) groups pass through unchanged. For a group
    where sources disagree, the model proposes a resolution which is then capped at
    the strongest asserted severity; the other sources become corroborations.
    """
    config = config or get_config()
    normalized: list[Finding] = []

    for group in _group_overlapping(candidates):
        severities = {f.severity for f in group}
        if len(group) == 1 or len(severities) == 1:
            normalized.append(_merge(group, group[0].severity, rationale=None))
            continue

        # Genuine conflict — run the debate, then cap at the evidence ceiling.
        llm = llm or get_llm_client(config)
        ceiling = max((f.severity for f in group), key=severity_rank)
        positions = _positions(group)
        completion = llm.call(
            module="normalize",
            prompt_version=PROMPT_VERSION,
            system=PROMPT,
            user=_debate_prompt(group, positions),
            schema=Adjudication,
            context={"stage": "normalize", "repo_id": group[0].repo_id,
                     "file": group[0].file, "severities": sorted(str(s) for s in severities)},
        )

        # No consensus, or a shaky one, is routed to review as `unresolved` — never a
        # forced pick. A synthesized, confident consensus is committed (capped).
        if not completion.value.consensus or completion.low_confidence:
            resolved_finding = _merge_unresolved(
                group, completion.confidence, consensus=completion.value.consensus
            )
            outcome, resolved_severity = "unresolved", None
        else:
            resolved = cap_severity(completion.value.severity, ceiling)
            resolved_finding = _merge(group, resolved, rationale=completion.value.rationale)
            outcome, resolved_severity = "consensus", resolved

        # Persist the full debate trail — not just the final severity — so a reviewer
        # can see why the sources disagreed. Keyed to the representative finding's
        # region, so review/ can look it up from the persisted finding.
        representative = max(group, key=lambda f: f.confidence)
        db.insert_adjudication_debate(
            AdjudicationDebate(
                repo_id=representative.repo_id,
                file=representative.file,
                line_start=representative.line_start,
                line_end=representative.line_end,
                positions=positions,
                outcome=outcome,
                resolved_severity=resolved_severity,
                synthesis_rationale=completion.value.rationale,
            ),
            config,
        )
        normalized.append(resolved_finding)

    return normalized


def _merge_unresolved(
    group: list[Finding], confidence: float | None, consensus: bool
) -> Finding:
    """Non-consensus adjudication: preserve both original severities, status unresolved.

    Triggered when the debate produced no consensus, or a consensus the model was not
    confident in. Each source's proposed severity is recorded as a corroboration note,
    so both calls survive rather than being silently collapsed to one value; the finding
    is routed to review/ as `unresolved`.
    """
    representative = max(group, key=lambda f: f.confidence)
    proposed = ", ".join(f"{name}={f.severity}" for f in group for _, name in [_source_of(f)])
    corroborations = [
        Corroboration(source_type=st, source_name=name, note=str(f.severity))
        for f in group
        for st, name in [_source_of(f)]
    ]
    conf = f"{confidence:.2f}" if confidence is not None else "n/a"
    cause = (
        "sources genuinely conflict (no consensus)"
        if not consensus
        else f"consensus confidence {conf} below threshold"
    )
    description = (
        f"{representative.description or ''}\n"
        f"[adjudication unresolved: {cause}; routed to review; "
        f"sources proposed {proposed}]"
    ).strip()
    return representative.model_copy(
        update={
            "falsification_status": FalsificationStatus.UNRESOLVED,
            "corroborated_by": corroborations,
            "description": description,
        }
    )


def _merge(group: list[Finding], severity: Severity, rationale: str | None) -> Finding:
    """Collapse a group into one canonical finding at `severity`.

    The representative is the highest-confidence finding; the *other* sources in the
    group become its corroborations (this is the cross-source agreement the severity
    rule relies on).
    """
    representative = max(group, key=lambda f: f.confidence)
    rep_source = _source_of(representative)
    corroborations = [
        Corroboration(source_type=st, source_name=name)
        for f in group
        if f is not representative
        for st, name in [_source_of(f)]
        if (st, name) != rep_source
    ]
    description = representative.description
    if rationale:
        description = f"{description or ''}\n[adjudication] {rationale}".strip()
    return representative.model_copy(
        update={
            "severity": severity,
            "corroborated_by": corroborations,
            "description": description,
        }
    )


def _debate_prompt(group: list[Finding], positions: list[DebatePosition]) -> str:
    """Lay out every source's severity *and its reasoning* together, for the debate."""
    lines = [
        f"Overlapping findings on {group[0].file} "
        f"lines {min(f.line_start for f in group)}-{max(f.line_end for f in group)}. "
        f"Each source's proposed severity and its reasoning:",
    ]
    for pos in positions:
        lines.append(
            f"- source={pos.source_name} ({pos.source_type}) "
            f"severity={pos.severity}\n  reasoning: {pos.reasoning or '(none given)'}"
        )
    lines.append("\nShared citation:\n" + group[0].citation_snippet)
    return "\n".join(lines)
