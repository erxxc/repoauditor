"""Read-only integrity audit for quantitative scenario inputs.

This module does not alter scenarios or recommend replacement priors. It checks whether the
current resolved inputs are being used within the population/structural scope supported by
their recorded provenance, and it fails visibly where the evidence cannot justify a claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..config import Config, get_config
from .risk_quant import ScenarioParams, build_scenarios


class AuditLevel(StrEnum):
    BLOCKING = "blocking"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class QuantAuditIssue:
    code: str
    level: AuditLevel
    message: str
    evidence: str


@dataclass(frozen=True)
class QuantAuditResult:
    repo_id: str | None
    issues: tuple[QuantAuditIssue, ...]

    @property
    def blocking(self) -> int:
        return sum(issue.level is AuditLevel.BLOCKING for issue in self.issues)


_EXPERIMENTAL_DISCLOSURE = (
    "EXPERIMENTAL QUANTITATIVE OUTPUT — NOT DECISION-GRADE: the integrity audit found "
    "one or more blocking model-applicability issues. Dollar ranges are retained for "
    "method evaluation only and must not be used for deal, budget, or risk-acceptance "
    "decisions. Run `repoauditor quant-audit <repo-id>` for the attributable evidence."
)


def quantitative_disclosure(result: QuantAuditResult) -> str | None:
    """Return the mandatory presentation gate when the read-only audit is blocking."""
    return _EXPERIMENTAL_DISCLOSURE if result.blocking else None


_BELOW_FREQUENCY_SOURCE_POPULATION = {
    "under_100k", "100k_to_1m", "1m_to_10m",
}


def audit_resolved_inputs(
    scenarios: list[ScenarioParams],
    config: Config,
    *,
    repo_id: str | None = None,
) -> QuantAuditResult:
    """Audit already-resolved scenarios without mutating or simulating them."""
    issues: list[QuantAuditIssue] = []
    revenue_band = config.risk_quant.company_revenue_band
    if revenue_band in _BELOW_FREQUENCY_SOURCE_POPULATION:
        issues.append(QuantAuditIssue(
            code="frequency_population_mismatch",
            level=AuditLevel.WARNING,
            message=(
                "The configured revenue band is outside the population named by the "
                "industry frequency source; applicability is unsupported."
            ),
            evidence=(
                f"company_revenue_band={revenue_band}; frequency prior detail="
                f"{config.priors.frequency['industry_baseline'].detail}"
            ),
        ))
    elif revenue_band == "unknown":
        issues.append(QuantAuditIssue(
            code="frequency_population_unverified",
            level=AuditLevel.WARNING,
            message=(
                "Organization revenue is unknown, so applicability of the >$10M "
                "industry frequency source cannot be verified."
            ),
            evidence="company_revenue_band=unknown",
        ))

    for name, prior in (
        ("magnitude.industry_baseline", config.priors.magnitude["industry_baseline"]),
        ("frequency.industry_baseline", config.priors.frequency["industry_baseline"]),
    ):
        missing = [
            field
            for field in ("effective_date", "data_vintage")
            if not getattr(prior, field)
        ]
        if missing:
            issues.append(QuantAuditIssue(
                code="prior_temporal_scope_unverified",
                level=AuditLevel.WARNING,
                message=(
                    "The configured citation does not establish all temporal scope "
                    "metadata; its edition is not silently reused as an effective date."
                ),
                evidence=f"prior={name}; missing={','.join(missing)}",
            ))
        issues.append(QuantAuditIssue(
            code="prior_uncertainty_scope",
            level=AuditLevel.INFO,
            message=(
                "Aleatory representation and unquantified epistemic limitations are "
                "recorded separately; no distribution was changed."
            ),
            evidence=(
                f"prior={name}; aleatory={prior.aleatory_representation}; "
                f"epistemic={prior.epistemic_status}; "
                f"target_population={prior.target_population}"
            ),
        ))

    for scenario in scenarios:
        if (
            len(scenario.conditional_frequency_lambdas) > 1
            and len(set(scenario.conditional_frequency_lambdas)) == 1
            and scenario.conditional_frequency_source == "frequency.industry_baseline"
        ):
            issues.append(QuantAuditIssue(
                code="organization_frequency_repeated_per_finding",
                level=AuditLevel.BLOCKING,
                message=(
                    "One organization-level annual loss-event baseline is repeated once per "
                    "finding and summed. The cited source does not support treating each "
                    "finding as an independent full-rate organization."
                ),
                evidence=(
                    f"scenario={scenario.name}; findings={len(scenario.finding_ids)}; "
                    f"per-finding lambdas={scenario.conditional_frequency_lambdas}; "
                    f"summed_lambda={scenario.frequency_lambda:.6f}"
                ),
            ))

    if scenarios:
        issues.append(QuantAuditIssue(
            code="magnitude_population_baseline",
            level=AuditLevel.INFO,
            message=(
                "Every scenario currently uses the same all-event, all-sector magnitude "
                "baseline; scenario names do not imply category-specific calibration."
            ),
            evidence="magnitude_source=magnitude.industry_baseline",
        ))

    if (
        config.risk_quant.exposure_overrides
        or config.risk_quant.control_strength_overrides
        or config.risk_quant.loss_scale_overrides
    ):
        issues.append(QuantAuditIssue(
            code="analyst_overrides_present",
            level=AuditLevel.INFO,
            message=(
                "Analyst overrides are explicit engagement inputs, not published priors; "
                "their rationale and sensitivity should be reviewed separately."
            ),
            evidence=(
                f"exposure={sorted(config.risk_quant.exposure_overrides)}; "
                f"control_strength={sorted(config.risk_quant.control_strength_overrides)}; "
                f"loss_scale={sorted(config.risk_quant.loss_scale_overrides)}"
            ),
        ))

    issues.append(QuantAuditIssue(
        code="fair_factor_separation",
        level=AuditLevel.INFO,
        message=(
            "Resolved factors remain structurally separate: validity gates existence, "
            "exposure scales contact frequency, control strength conditions success, and "
            "loss scale changes magnitude."
        ),
        evidence="No EPSS/KEV enrichment is active; no severity-derived proxy is used.",
    ))
    return QuantAuditResult(repo_id=repo_id, issues=tuple(issues))


def audit_quantitative_inputs(
    repo_id: str, config: Config | None = None
) -> QuantAuditResult:
    """Resolve current read-only scenarios and audit their input integrity."""
    config = config or get_config()
    return audit_resolved_inputs(
        build_scenarios(repo_id, config, persist=False),
        config,
        repo_id=repo_id,
    )


def render_quant_audit(result: QuantAuditResult) -> str:
    scope = result.repo_id or "configuration"
    lines = [
        f"Quantitative input integrity — {scope}",
        f"blocking={result.blocking}; total observations={len(result.issues)}",
    ]
    lines.extend(
        f"[{issue.level.value}] {issue.code}: {issue.message} Evidence: {issue.evidence}"
        for issue in result.issues
    )
    if result.blocking:
        lines.append(
            "Quantitative output should not be treated as decision-grade until blocking "
            "items have a sourced resolution; this audit does not change the model."
        )
    return "\n".join(lines)
