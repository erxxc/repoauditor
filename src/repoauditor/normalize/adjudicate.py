"""Severity adjudication / normalization — with debate framing and enforced upgrade licensing.

When several sources (deterministic tools and/or ensemble lenses) flag the **same underlying
issue** but disagree on severity, this stage resolves the conflict into one canonical
`Finding`. "The same issue" is decided by the shared `repoauditor.matching` module — the very
same matcher `analyze/corroboration.py` uses — so grouping here is CWE-aware and vetoes
co-located-but-different-CWE findings, rather than the old line-overlap-only heuristic that
could treat two distinct issues as one conflict.

It implements a **debate-style adjudication** (structured deliberation before commit): the
conflicting sources' *reasoning* — not just their severity values — is laid out together, and
the adjudicator produces either a synthesized consensus with documented rationale or an
explicit non-consensus. A non-consensus (or a low-confidence one) routes to review/ as
`unresolved` rather than being silently resolved.

The core CLAUDE.md rule is **enforced here, in code, at the right point in the pipeline**:
severity is never upgraded without a license, and there are exactly two licenses —
  (a) a corroborating match from an *independent* source (≥2 distinct sources on the matched
      group), or
  (b) a falsification pass that confirmed reachability (a group member is `confirmed`).
A conflicting-severity group with *neither* license cannot have its higher severity kept: it
routes to `unresolved` → review/. A licensed group runs the debate and the result is **capped
at the strongest severity any single source actually asserted** — evidence is never
manufactured. Single-source (or already-agreeing) groups pass through unchanged.

Because normalize/ runs *before* review/, the resolved severity is **persisted here**
(`db.apply_adjudication`) so it is final and visible to the human reviewer — the licensing
decision is made once, before review, not re-litigated after. (`analyze/corroboration.py`
runs after review and only *scores* agreement; it never changes severity.)
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from ..config import Config, get_config
from ..llm import LLMClient, get_llm_client
from ..matching import MatchGroup, find_matches, source_of
from ..store import db
from ..store.models import (
    AdjudicationDebate,
    Corroboration,
    DebatePosition,
    FalsificationStatus,
    Finding,
    Severity,
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


def _reasoning_of(finding: Finding) -> str:
    """The argument a source made for its severity — its description, else its title."""
    return (finding.description or finding.title or "").strip()


def _positions(members: list[Finding]) -> list[DebatePosition]:
    """Each source's stance in the debate: its severity call *and* its reasoning."""
    positions: list[DebatePosition] = []
    for finding in members:
        src = source_of(finding)
        positions.append(
            DebatePosition(
                source_type=src.source_type,
                source_name=src.source_name,
                severity=finding.severity,
                reasoning=_reasoning_of(finding),
            )
        )
    return positions


def _license(group: MatchGroup) -> str | None:
    """The license (if any) permitting an upgrade for a conflicting group.

    (a) `corroboration` — independently produced evidence flagged the same issue; or
    (b) `falsification` — a member was confirmed reachable by the falsify stage.
    `None` means no upgrade may be kept — route the conflict to review as unresolved.
    """
    if group.has_independent_corroboration:
        return "corroboration"
    if any(f.falsification_status is FalsificationStatus.CONFIRMED for f in group.findings):
        return "falsification"
    return None


def adjudicate(
    candidates: list[Finding],
    config: Config | None = None,
    llm: LLMClient | None = None,
    *,
    persist: bool = True,
) -> list[Finding]:
    """Resolve conflicting severities across same-issue findings into canonical ones.

    Groups with the shared matcher, then per group: single-source / already-agreeing groups
    pass through unchanged (no upgrade); a conflicting group may keep its higher severity
    only if licensed (independently produced corroboration or a falsification confirmation),
    else it
    routes to review as `unresolved`. A licensed resolution is capped at the strongest
    asserted severity; the other sources become corroborations. Resolved severities are
    persisted (so review/ sees them) for findings that carry an id.
    """
    config = config or get_config()
    normalized: list[Finding] = []

    live = [f for f in candidates if f.falsification_status is not FalsificationStatus.KILLED]
    for group in find_matches(live).groups:
        members = group.findings
        severities = {f.severity for f in members}

        # No conflict: single finding or unanimous severity — pass through, no upgrade, no LLM.
        if len(members) == 1 or len(severities) == 1:
            resolved = _merge(members, group.representative.severity, rationale=None)
            _persist_resolution(resolved, config, persist)
            normalized.append(resolved)
            continue

        # Conflicting severities: keeping the higher end is an upgrade that needs a license.
        positions = _positions(members)
        ceiling = max(severities, key=severity_rank)
        licensed_by = _license(group)

        if licensed_by is None:
            # No independent corroboration and no falsification confirmation — cannot license
            # an upgrade. Route to review as unresolved rather than forcing the higher value.
            resolved = _merge_unresolved(
                members, confidence=None, consensus=False,
                cause="severity conflict with no independent corroboration and no "
                      "falsification confirmation to license an upgrade",
            )
            _record_debate(config, members, positions, outcome="unresolved",
                           resolved_severity=None,
                           rationale="unlicensed severity upgrade — routed to review")
            _persist_resolution(resolved, config, persist)
            normalized.append(resolved)
            continue

        # Licensed — run the debate, then cap at the evidence ceiling.
        llm = llm or get_llm_client(config)
        completion = llm.call(
            module="normalize",
            prompt_version=PROMPT_VERSION,
            system=PROMPT,
            user=_debate_prompt(members, positions),
            schema=Adjudication,
            context={"stage": "normalize", "repo_id": members[0].repo_id,
                     "file": members[0].file, "license": licensed_by,
                     "severities": sorted(str(s) for s in severities)},
        )

        if not completion.value.consensus or completion.low_confidence:
            resolved = _merge_unresolved(
                members, completion.confidence, consensus=completion.value.consensus
            )
            outcome, resolved_severity = "unresolved", None
        else:
            resolved_severity = cap_severity(completion.value.severity, ceiling)
            resolved = _merge(members, resolved_severity, rationale=completion.value.rationale)
            outcome = "consensus"

        _record_debate(config, members, positions, outcome, resolved_severity,
                       completion.value.rationale)
        _persist_resolution(resolved, config, persist)
        normalized.append(resolved)

    # Killed candidates are not adjudicated — passed through untouched.
    normalized.extend(f for f in candidates
                      if f.falsification_status is FalsificationStatus.KILLED)
    return normalized


def adjudicate_repo(
    repo_id: str, config: Config | None = None, llm: LLMClient | None = None
) -> list[Finding]:
    """Normalize all stored findings for a repo; thin repo-level stage entry point."""
    config = config or get_config()
    return adjudicate(db.list_findings(repo_id, config), config, llm)


def _persist_resolution(resolved: Finding, config: Config, persist: bool) -> None:
    """Write the resolved severity + corroborations to the store (if the finding is persisted).

    In-memory candidates (id is None) — e.g. unit tests exercising the pure logic — are left
    alone; store-backed findings have their resolved severity made final before review/.
    """
    if persist and resolved.id is not None:
        db.apply_adjudication(resolved, config)


def _record_debate(
    config: Config,
    members: list[Finding],
    positions: list[DebatePosition],
    outcome: str,
    resolved_severity: Severity | None,
    rationale: str | None,
) -> None:
    """Persist the full debate trail (positions + outcome), keyed to the representative region."""
    representative = max(members, key=lambda f: f.confidence)
    db.insert_adjudication_debate(
        AdjudicationDebate(
            repo_id=representative.repo_id,
            file=representative.file,
            line_start=representative.line_start,
            line_end=representative.line_end,
            positions=positions,
            outcome=outcome,
            resolved_severity=resolved_severity,
            synthesis_rationale=rationale,
        ),
        config,
    )


def _merge_unresolved(
    members: list[Finding],
    confidence: float | None,
    consensus: bool,
    cause: str | None = None,
) -> Finding:
    """Non-consensus / unlicensed adjudication: preserve both severities, status unresolved.

    Each source's proposed severity is recorded as a corroboration note, so both calls survive
    rather than being silently collapsed to one value; the finding routes to review/ as
    `unresolved`.
    """
    representative = max(members, key=lambda f: f.confidence)
    proposed = ", ".join(f"{source_of(f).source_name}={f.severity}" for f in members)
    corroborations = [
        Corroboration(source_type=source_of(f).source_type,
                      source_name=source_of(f).source_name, note=str(f.severity))
        for f in members
    ]
    if cause is None:
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


def _merge(members: list[Finding], severity: Severity, rationale: str | None) -> Finding:
    """Collapse a group into one canonical finding at `severity`.

    The representative is the highest-confidence finding; the *other* independent sources in
    the group become its corroborations (the cross-source agreement the severity rule relies on).
    """
    representative = max(members, key=lambda f: f.confidence)
    rep_source = source_of(representative)
    corroborations: list[Corroboration] = []
    seen = {rep_source}
    for finding in members:
        src = source_of(finding)
        if src in seen:
            continue
        seen.add(src)
        corroborations.append(
            Corroboration(source_type=src.source_type, source_name=src.source_name)
        )
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


def _debate_prompt(members: list[Finding], positions: list[DebatePosition]) -> str:
    """Lay out every source's severity *and its reasoning* together, for the debate."""
    lines = [
        f"Overlapping findings on {members[0].file} "
        f"lines {min(f.line_start for f in members)}-{max(f.line_end for f in members)}. "
        f"Each source's proposed severity and its reasoning:",
    ]
    for pos in positions:
        lines.append(
            f"- source={pos.source_name} ({pos.source_type}) "
            f"severity={pos.severity}\n  reasoning: {pos.reasoning or '(none given)'}"
        )
    lines.append("\nShared citation:\n" + members[0].citation_snippet)
    return "\n".join(lines)
