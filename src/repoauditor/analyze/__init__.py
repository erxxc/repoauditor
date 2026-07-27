"""Analyze stage — cross-source corroboration/divergence + deal-relevant weighting.

`corroboration.py` matches findings across sources and scores their agreement;
`deal_risk.py` re-weights findings into a deal-relevant risk distinct from technical
severity. The FAIR-style risk quantification is in `risk_quant.py`.
"""

from .corroboration import (
    SEVERITY_UPGRADE_GAP,
    CorroborationResult,
    Divergence,
    agreement_score,
    corroborate,
)
from .deal_risk import DealRiskResult, weigh_deal_risk
from .integrity import (
    AuditLevel,
    QuantAuditIssue,
    QuantAuditResult,
    audit_quantitative_inputs,
    render_quant_audit,
)
from .risk_quant import (
    QuantificationArtifacts,
    build_scenarios,
    calibrate_lognormal,
    generate_appendix,
    quantify_appendix,
    monte_carlo,
    tornado_sensitivity,
)

__all__ = [
    "corroborate",
    "agreement_score",
    "CorroborationResult",
    "Divergence",
    "SEVERITY_UPGRADE_GAP",
    "weigh_deal_risk",
    "DealRiskResult",
    "AuditLevel",
    "QuantAuditIssue",
    "QuantAuditResult",
    "audit_quantitative_inputs",
    "render_quant_audit",
    "QuantificationArtifacts",
    "build_scenarios",
    "calibrate_lognormal",
    "generate_appendix",
    "quantify_appendix",
    "monte_carlo",
    "tornado_sensitivity",
]
