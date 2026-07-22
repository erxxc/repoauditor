"""Leadership risk-memo projection — deal-facing, backed by the Monte-Carlo appendix.

Ranks findings by **deal-relevant weight** (`analyze/deal_risk.py`: production exposure,
remediation cost, rep-&-warranty relevance) rather than raw technical severity, and backs the
summary with `analyze/risk_quant`'s FAIR Monte-Carlo appendix. This is what makes it a
deal memo rather than a technical dump.

It reads the **countable, review-gated** finding set: `list_countable_findings` composes the
review gate (via `list_analyzable_findings`), so a finding still blocked at review — an open
`ReviewRequest` with no releasing decision — never appears here, and merged duplicates are
counted once.

A report is a pure read projection of the *findings*: it never mutates a finding or a
severity. By default the deal-weighting and the appendix are computed with `persist=False`,
so generating the memo writes nothing to the store. With `record_audit=True` the memo also
leaves an **audit trail** — a `SimulationRun` row (plus its `RiskScenario` / `PriorSource`
evidence) recording exactly which quantitative model backed the presented memo. That is
purely additive logging: it records what the memo was based on, and still does not touch any
finding or severity. The deal-weighting stays `persist=False` regardless. The appendix's own
artifact files (markdown + charts) are written to disk by `generate_appendix` as its normal
output; this module consumes that output rather than reimplementing it.

The flat `templates/memo_v1.md` is a versioned-artifact placeholder (never edited in place,
per CLAUDE.md). The memo is composed programmatically here — mirroring how
`risk_quant._appendix_markdown` builds its artifact — because the top-risks section and the
embedded appendix are variable-length generated blocks a flat template can't hold. A future
`memo_v2.md` template could supersede this.
"""

from __future__ import annotations

from ..analyze.deal_risk import weigh_deal_risk
from ..analyze.risk_quant import generate_appendix
from ..config import Config, get_config
from ..store import db
from ..store.models import DealRisk, Finding

_TOP_N = 5  # plain-language summary covers the 3-5 highest deal-relevant risks

_EXPOSURE_PHRASE = {
    "direct": "sits on a production / customer-data path",
    "indirect": "sits adjacent to a production integration",
    "internal": "is on an internal-only component",
    "unknown": "has no clearly mapped exposure (treated conservatively)",
}
_REMEDIATION_PHRASE = {
    "fast": "a fast fix (e.g. rotating a credential)",
    "moderate": "a moderate, localized code change",
    "major": "a major change such as a dependency upgrade",
    "redesign": "an architectural redesign",
}

_METHODOLOGY = (
    "Findings are ranked here by **deal-risk weight** — a blend of production/customer-data "
    "exposure, remediation burden, and representation-&-warranty relevance — not by raw "
    "technical severity, so the memo reflects what matters to the transaction rather than the "
    "engineering backlog. Each finding was corroborated across independent lenses/tools and "
    "put through a falsification pass; severity is never asserted without a corroborating "
    "source or a confirmed reachability pass, and anything the pipeline could not resolve is "
    "withheld pending human review (it does not appear above). The loss figures in the "
    "appendix come from a FAIR-style Monte-Carlo model (Freund & Jones) with loss magnitudes "
    "calibrated as 90% confidence intervals (Hubbard & Seiersen); every distribution "
    "parameter traces to a sourced prior (`priors.yaml` / `PriorSource`), and results are "
    "reported as ranges, never single point estimates."
)


def _band_label(dr: DealRisk) -> str:
    return f"deal-risk {dr.weight:.2f} ({dr.band})"


def _risk_paragraph(index: int, finding: Finding, dr: DealRisk, boundary: str) -> list[str]:
    """A one-paragraph, non-technical explanation of a single top deal-relevant risk."""
    exposure = _EXPOSURE_PHRASE.get(dr.production_exposure, "has uncertain exposure")
    remediation = _REMEDIATION_PHRASE.get(dr.remediation_category, "an unscoped remediation")
    rw = (
        "It falls under the kind of security representation typically made in an acquisition "
        "agreement, so it carries diligence weight beyond its engineering cost."
        if dr.rep_warranty_relevant
        else "It does not clearly fall under a standard acquisition security representation."
    )
    return [
        f"### {index}. {finding.title}  —  {_band_label(dr)}",
        "",
        f"This issue {exposure} (trust boundary: {boundary}), and its technical severity is "
        f"rated **{finding.severity}**. Remediation is expected to be {remediation}. {rw} "
        f"It should be factored into remediation planning and, where material, into deal "
        f"terms.",
        "",
    ]


def _strip_h1(markdown: str) -> str:
    """Drop a leading level-1 heading so the appendix nests under the memo's own structure."""
    lines = markdown.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    return "\n".join(lines).lstrip("\n")


def build_memo(
    repo_id: str, config: Config | None = None, *, record_audit: bool = False
) -> str:
    """Render the leadership risk memo for a repo.

    Reads the review-gated finding set and never mutates a finding or severity. When
    `record_audit` is True, the backing Monte-Carlo run is persisted as a `SimulationRun`
    (with its scenario/prior-source evidence) so there is an audit trail of what the
    presented memo was based on — additive logging only; the deal-weighting is still
    computed with `persist=False`.
    """
    config = config or get_config()

    # Deal weights for the review-gated set (persist=False — a report never mutates the store).
    deal = {r.finding_id: r.deal_risk for r in weigh_deal_risk(repo_id, config, persist=False)}
    countable = db.list_countable_findings(repo_id, config)
    boundaries = {
        tb.id: tb.name
        for tb in db.list_trust_boundaries(repo_id, config)
        if tb.id is not None
    }

    # Rank the countable findings by deal_risk_weight (not technical severity).
    ranked = sorted(
        (f for f in countable if f.id in deal),
        key=lambda f: deal[f.id].weight,
        reverse=True,
    )
    top = ranked[:_TOP_N]

    lines = [f"# Security Risk Memo — {repo_id}", "", "## Executive summary", ""]
    if not top:
        lines += ["_No material deal-relevant findings surfaced after review._", ""]
    else:
        lines += [
            f"The {len(top)} highest deal-relevant risks below are ranked by deal-risk weight "
            "(production exposure, remediation burden, and representation-&-warranty "
            "relevance) — not by raw technical severity.",
            "",
        ]
        for i, finding in enumerate(top, 1):
            boundary = boundaries.get(finding.trust_boundary_id, "an unmapped component")
            lines += _risk_paragraph(i, finding, deal[finding.id], boundary)

    # FAIR Monte-Carlo appendix — consume generate_appendix's artifact. persist follows the
    # audit flag: with record_audit the SimulationRun (and its scenario/prior evidence) is
    # written as the memo's audit trail; findings/severity are untouched either way.
    out_dir = config.resolve(config.paths.data_dir) / "reports" / f"{repo_id}_memo"
    appendix_path = generate_appendix(repo_id, config, out_dir=out_dir, persist=record_audit)
    lines += [
        "## Appendix: Quantitative Risk Model (FAIR / Monte Carlo)",
        "",
        f"_Full appendix and charts written to `{out_dir}`._",
        "",
        _strip_h1(appendix_path.read_text()),
        "",
        "## Methodology & confidence",
        "",
        _METHODOLOGY,
    ]
    return "\n".join(lines)
