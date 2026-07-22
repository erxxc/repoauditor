"""Deal-relevant risk weighting — a diligence lens layered alongside technical severity.

Re-weights each finding into a `deal_risk_weight` in [0, 1] that answers a different
question than technical severity: *how much should this finding move an acquisition
decision?* Technical severity is an input, never overwritten — the weight is persisted in a
sidecar `deal_risk` row (same discipline as `triage_result`), so `report/` can order the
same findings by engineering severity or by deal relevance independently.

The weight is a documented blend of four components, each in [0, 1] and each sourced from
`deal_risk.yaml` (CLAUDE.md "no unsourced priors" — nothing here is a silently-invented
magic number; the rep-&-warranty mapping and remediation-cost classes carry a stated basis,
"informed by common M&A security rep language"):

  * **Technical severity** — the finding's own severity, normalized (info=0 … critical=1).
    The impact anchor, so the deal weight never floats free of technical reality.
  * **Production exposure** — does the finding's trust boundary / entity (from the map
    stage) touch a production or customer-data path? Data-at-rest stores and internet-facing
    entry points score high; internal components low; unknown is treated as *moderate*, not
    zero (deal risk should not under-report on missing context).
  * **Remediation burden** — a *categorical* cost/timeline class by finding type
    (fast / moderate / major / redesign), NOT a dollar figure — monetary loss modelling is
    `risk_quant.py`'s job. A hardcoded secret is a fast rotation; a supply-chain issue a
    major version bump; a broken-access-control / trust-boundary flaw a redesign.
  * **Rep-&-warranty relevance** — does this finding category typically fall under a standard
    acquisition security representation? A config-driven lookup (`deal_risk.yaml`), not
    business logic buried in Python.

    weight = w_sev·severity + w_exp·exposure + w_rem·remediation + w_rw·rep_warranty

with the four `w_*` blend weights (summing to 1) also sourced from config. The corroboration
score from `analyze/corroboration.py` is available on the finding and is surfaced in the
rationale as evidence-strength context; it is intentionally *not* folded into the weight
formula, so the number stays fully reconstructable from the four sourced components (and so
the deal weight is not a second, disguised severity signal).

`store/` owns persistence: this module reads via `db.list_analyzable_findings` /
`db.list_trust_boundaries` / `db.list_entities` and writes only through `db.upsert_deal_risk`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import Config, DealCategory, get_config
from ..store import db
from ..store.models import DealRisk, Entity, Finding, TrustBoundary, severity_rank

_CWE_RE = re.compile(r"cwe[-_ ]?(\d+)", re.IGNORECASE)

# Entity kind -> coarse exposure label. Scores come from config; this only names the label.
_KIND_LABEL = {
    "data_store": "direct",
    "entry_point": "direct",
    "integration": "indirect",
    "component": "internal",
}


@dataclass
class DealRiskResult:
    """A finding's deal weighting with its technical severity kept visible alongside."""

    finding_id: int
    title: str
    technical_severity: str  # unchanged — surfaced next to the deal weight, not replaced
    deal_risk: DealRisk


# --------------------------------------------------------------------------- #
# Categorization (config-driven taxonomy; precedence == config order)
# --------------------------------------------------------------------------- #
def _cwes(finding: Finding) -> set[str]:
    text = f"{finding.title} {finding.description or ''}"
    return {m.group(1) for m in _CWE_RE.finditer(text)}


def _finding_category(finding: Finding, config: Config) -> str:
    """Map a finding to a deal-risk category by CWE / keyword / source_tool.

    Recognition rules and precedence live in `deal_risk.yaml`; the first category (in config
    order) whose rules match wins, else `default_category`. No hardcoded taxonomy in Python.
    """
    cwes = _cwes(finding)
    text = f"{finding.title} {finding.description or ''} {finding.citation_snippet}".lower()
    tool = finding.source_tool
    for name, cat in config.deal_risk.categories.items():
        if name == config.deal_risk.default_category:
            continue
        if cwes & set(cat.cwes):
            return name
        if tool is not None and tool in cat.source_tools:
            return name
        if any(kw.lower() in text for kw in cat.keywords):
            return name
    return config.deal_risk.default_category


# --------------------------------------------------------------------------- #
# Component scores
# --------------------------------------------------------------------------- #
def _production_exposure(
    finding: Finding,
    boundaries: dict[int, TrustBoundary],
    entities: dict[int, Entity],
    config: Config,
) -> tuple[str, float, str]:
    """Return (label, score, note) for the finding's production/customer-data exposure."""
    exp = config.deal_risk.exposure
    tb = boundaries.get(finding.trust_boundary_id) if finding.trust_boundary_id else None
    ent = entities.get(finding.entity_id) if finding.entity_id else None

    blob_parts = []
    if tb is not None:
        blob_parts.append(f"{tb.name} {tb.description or ''}")
    if ent is not None:
        blob_parts.append(f"{ent.name} {ent.location or ''}")
    blob = " ".join(blob_parts).lower()

    hit = next((ind for ind in exp.production_indicators if ind.lower() in blob), None)
    if hit is not None:
        return "direct", exp.matched_score, f"production indicator '{hit}' on its boundary"

    if ent is not None:
        kind = str(ent.kind)
        score = exp.entity_kind_scores.get(kind, exp.default_score)
        label = _KIND_LABEL.get(kind, "internal")
        return label, score, f"anchored to a {kind} entity ('{ent.name}')"

    # No entity linkage: a bare boundary with no production indicator is treated as
    # unknown/moderate — never zero.
    where = f"boundary '{tb.name}'" if tb is not None else "no map linkage"
    return "unknown", exp.default_score, f"no production signal ({where})"


def _remediation(category: DealCategory, config: Config) -> tuple[str, float]:
    label = category.remediation
    score = config.deal_risk.remediation_scores.get(label, config.deal_risk.remediation_scores.get("moderate", 0.5))
    return label, score


def _band(weight: float, config: Config) -> str:
    bands = config.deal_risk.bands
    for name in ("critical", "high", "elevated"):
        if name in bands and weight >= bands[name]:
            return name
    return "low"


def _corroboration_score(finding: Finding) -> float:
    """Strongest corroboration score attached to the finding (0.0 if none) — context only."""
    scores = [c.score for c in finding.corroborated_by if c.score is not None]
    return max(scores) if scores else 0.0


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def weigh_deal_risk(
    repo_id: str, config: Config | None = None, *, persist: bool = True
) -> list[DealRiskResult]:
    """Compute the deal-risk weighting for every analyzable finding in a repo.

    Consumes the review-gated finding set (`list_analyzable_findings`, same gate as
    `risk_quant.build_scenarios`), so a finding held at review or killed does not get a deal
    weight until it clears. Persists one `deal_risk` sidecar row per finding (idempotent).
    Technical severity is read as an input and left untouched.
    """
    config = config or get_config()
    findings = db.list_analyzable_findings(repo_id, config)
    boundaries = {tb.id: tb for tb in db.list_trust_boundaries(repo_id, config) if tb.id is not None}
    entities = {e.id: e for e in db.list_entities(repo_id, config) if e.id is not None}
    blend = config.deal_risk.blend

    results: list[DealRiskResult] = []
    for f in findings:
        if f.id is None:
            continue
        category_name = _finding_category(f, config)
        category = config.deal_risk.categories.get(
            category_name, config.deal_risk.categories.get(config.deal_risk.default_category)
        )

        sev_component = severity_rank(f.severity) / 4.0  # info=0 … critical=1
        exp_label, exp_component, exp_note = _production_exposure(f, boundaries, entities, config)
        rem_label, rem_component = _remediation(category, config)
        rw = category.rep_warranty
        rw_component = rw.weight if rw.relevant else 0.0

        weight = (
            blend.severity * sev_component
            + blend.production_exposure * exp_component
            + blend.remediation * rem_component
            + blend.rep_warranty * rw_component
        )
        weight = max(0.0, min(1.0, weight))
        band = _band(weight, config)
        corr = _corroboration_score(f)

        rationale = (
            f"deal-risk {weight:.2f} ({band}) vs technical severity {f.severity}: "
            f"category={category_name}; exposure={exp_label} ({exp_note}); "
            f"remediation={rem_label}; "
            f"rep&warranty={'yes' if rw.relevant else 'no'}"
            f"{f' ({rw.rep_clause})' if rw.relevant else ''}; "
            f"corroboration={corr:.2f} (evidence-strength context, not in the weight)."
        )

        dr = DealRisk(
            finding_id=f.id,
            weight=round(weight, 4),
            band=band,
            production_exposure=exp_label,
            remediation_category=rem_label,
            rep_warranty_category=category_name if rw.relevant else None,
            rep_warranty_relevant=rw.relevant,
            severity_component=round(sev_component, 4),
            exposure_component=round(exp_component, 4),
            remediation_component=round(rem_component, 4),
            rep_warranty_component=round(rw_component, 4),
            rationale=rationale,
        )
        if persist:
            db.upsert_deal_risk(dr, config)
        results.append(DealRiskResult(
            finding_id=f.id, title=f.title,
            technical_severity=str(f.severity), deal_risk=dr,
        ))

    return results
