"""Analyze stage — cross-source corroboration/divergence + deal-relevant weighting.

Corroboration/deal-risk weighting is future work (see `corroboration.py`,
`deal_risk.py`). The FAIR-style risk quantification is implemented in `risk_quant.py`.
"""

from .risk_quant import (
    build_scenarios,
    calibrate_lognormal,
    generate_appendix,
    monte_carlo,
    tornado_sensitivity,
)

__all__ = [
    "build_scenarios",
    "calibrate_lognormal",
    "generate_appendix",
    "monte_carlo",
    "tornado_sensitivity",
]
