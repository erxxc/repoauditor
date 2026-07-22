"""Cross-source agreement scoring — the downstream analytical layer.

Matching ("which findings across sources are the same issue?") lives in the shared
`repoauditor.matching` module and is called from *two* points: `normalize/adjudicate.py`
(to license severity upgrades before review/) and here. This module owns only the second
half — **agreement scoring** — and reuses the shared matcher rather than reimplementing it.

This layer is purely analytical and runs *after* review/: it produces `Corroboration`
records and populates `corroborated_by` for the confidence narrative (and feeds
`deal_risk.py`'s framing), but it **never mutates `Finding.severity`** — severity is settled
at normalize/ time, before a human reviewer sees it. See `SEVERITY_ENFORCEMENT` for why this
split is safe given the pipeline ordering.

Agreement scoring — weighting rationale
---------------------------------------
For a matched group, an independence-weighted corroboration score in [0, 1] from two signals:
how *many* distinct sources agree (breadth) and how *independent* they are (diversity). This
is our own design choice — no single published constant is being copied, so per the "cite the
published method" convention it is stated as such, with its lineage. Deterministic tools and
LLM lenses fail in *decorrelated* ways (a SAST tool's false positives are pattern-driven, an
LLM lens's are reasoning-driven), so agreement *across* the tool↔lens divide is stronger
evidence than agreement *within* one method class (two lenses can share a correlated blind
spot; two tools a rule lineage). This mirrors the classical ensemble result that error
*diversity*, not member count, drives reliability (Kuncheva, *Combining Pattern Classifiers*,
2004; Dietterich, "Ensemble Methods in Machine Learning", 2000). Concretely:

    independence = 1.0 if the group spans both a tool and a lens, else 0.5
    breadth      = 1 - 1/n           (n = distinct sources; grows, saturates < 1)
    score        = independence * breadth

so a tool+lens pair (0.50) outscores a same-class trio (0.33): independence dominates count.

`store/` owns all persistence: reads via `db.list_findings`, writes only through
`db.add_corroboration`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..config import Config, get_config
from ..matching import (
    Divergence,
    SourceRef,
    find_matches,
    source_of,
)
from ..store import db
from ..store.models import Corroboration, FalsificationStatus, SourceType

logger = logging.getLogger(__name__)

# Why analyze/ scoring changing corroboration records can never change a post-review severity.
# The severity-upgrade rule ("never upgraded without a corroborating source or a confirming
# falsification pass") is ENFORCED in normalize/adjudicate.py, which runs before review/ and
# uses the same shared matcher this module uses. This module runs after review/ and only
# scores agreement — it does not touch severity. And it cannot discover *new* corroboration
# that normalize missed: no detection runs between normalize and analyze (pipeline order is
# detect -> triage -> falsify -> normalize -> analyze), so the finding set is identical at both
# points and the shared matcher is deterministic on it. Both points also exclude KILLED
# findings, so even the reporting view matches what licensing saw.
SEVERITY_ENFORCEMENT = (
    "Severity-upgrade licensing is enforced in normalize/adjudicate.py (before review/) using "
    "the shared matcher. analyze/corroboration.py runs after review/, reuses the same matcher, "
    "and only scores agreement — it never mutates severity. No new sources can appear between "
    "normalize and analyze (detection is upstream of both), so analyze cannot find corroboration "
    "normalize did not, and there is no post-review severity-change path."
)

# Back-compat alias: earlier sessions exported this name; it now points at the resolved note.
SEVERITY_UPGRADE_GAP = SEVERITY_ENFORCEMENT


@dataclass
class CorroborationResult:
    """A matched group of findings and its independence-weighted agreement score."""

    representative_id: int
    representative_title: str
    score: float
    sources: list[SourceRef]  # distinct sources in the group, incl. the representative's
    member_finding_ids: list[int]
    corroborations: list[Corroboration] = field(default_factory=list)  # written rows


# --------------------------------------------------------------------------- #
# Agreement scoring
# --------------------------------------------------------------------------- #
def agreement_score(sources: set[SourceRef]) -> float:
    """Independence-weighted corroboration score in [0, 1]. See the module docstring.

    0.0 for a single source (no corroboration). Otherwise `independence * breadth`, where
    independence is 1.0 iff both a tool and a lens are present (0.5 for same-class agreement)
    and breadth = 1 - 1/n over the number of distinct sources.
    """
    n = len(sources)
    if n < 2:
        return 0.0
    has_tool = any(s.source_type is SourceType.TOOL for s in sources)
    has_lens = any(s.source_type is SourceType.LENS for s in sources)
    independence = 1.0 if (has_tool and has_lens) else 0.5
    breadth = 1.0 - 1.0 / n
    return round(independence * breadth, 4)


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def corroborate(
    repo_id: str, config: Config | None = None, *, persist: bool = True
) -> tuple[list[CorroborationResult], list[Divergence]]:
    """Match a repo's findings across sources (shared matcher) and score their agreement.

    Excludes KILLED findings — a definitive null result is not a second opinion, and dropping
    it keeps this analytical view aligned with what normalize licensed on. Writes a scored
    `Corroboration` row for each non-representative source of every multi-source group, and
    returns the scored groups plus the surfaced divergences. Never modifies `Finding.severity`.
    """
    config = config or get_config()
    findings = [
        f for f in db.list_findings(repo_id, config)
        if f.falsification_status is not FalsificationStatus.KILLED
    ]
    match = find_matches(findings)
    divergences = list(match.divergences)

    results: list[CorroborationResult] = []
    for group in match.groups:
        distinct = group.distinct_sources
        if len(distinct) < 2:
            # A lone source is not corroboration — surface it so "one source flagged, others
            # silent" is visible, not hidden.
            for f in group.findings:
                divergences.append(Divergence(
                    kind="uncorroborated", finding_ids=[f.id],
                    detail=f"only {source_of(f)} flagged this location",
                ))
            continue

        representative = group.representative
        rep_source = source_of(representative)
        score = agreement_score(distinct)

        written: list[Corroboration] = []
        seen: set[SourceRef] = set()
        for member in group.findings:
            src = source_of(member)
            if src == rep_source or src in seen:
                continue  # skip the representative's own source and duplicate sources
            seen.add(src)
            corr = Corroboration(
                finding_id=representative.id,
                source_type=src.source_type,
                source_name=src.source_name,
                note=f"corroborates {representative.file}:"
                     f"{representative.line_start}-{representative.line_end}",
                score=score,
                match_basis=group.basis_for(member),
            )
            if persist:
                db.add_corroboration(corr, config)
            written.append(corr)

        representative.corroborated_by = written  # reflect on the in-memory representative
        results.append(CorroborationResult(
            representative_id=representative.id,
            representative_title=representative.title,
            score=score,
            sources=sorted(distinct, key=lambda s: (s.source_type, s.source_name)),
            member_finding_ids=[f.id for f in group.findings if f.id is not None],
            corroborations=written,
        ))
        logger.info(
            "corroboration group: representative=%s score=%.3f sources=[%s]",
            representative.id, score,
            ", ".join(str(s) for s in sorted(distinct, key=lambda s: (s.source_type, s.source_name))),
        )

    return results, divergences
