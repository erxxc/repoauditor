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

import shutil
from pathlib import Path

from ..analyze.deal_risk import weigh_deal_risk
from ..analyze.risk_quant import QuantificationArtifacts, generate_appendix
from ..config import Config, get_config
from ..review import open_review_requests
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
    "engineering backlog. Each highlighted finding's validation basis is disclosed beside "
    "it: independent "
    "cross-source corroboration, falsification confirmation, or analyst review. Severity is "
    "never asserted without a corroborating source or a confirmed reachability pass, and "
    "anything the pipeline could not resolve is "
    "withheld pending human review (it does not appear above). The loss figures in the "
    "appendix come from a FAIR-style Monte Carlo model with two explicit layers: a "
    "Bernoulli validity gate represents whether each finding is real and exploitable, then "
    "a conditional Poisson rate represents loss-event frequency only when that gate is "
    "open. EPSS and KEV are eligible only as real, dated signals for a CVE-backed finding; "
    "without such enrichment the model uses the explicitly labelled IRIS 2022 industry "
    "baseline rather than inferring a threat signal from severity. Loss magnitude is fitted "
    "to IRIS 2022's published median and p95. Every distribution parameter traces to an "
    "exactly cited prior (`priors.yaml` / `PriorSource`), and results are reported as ranges, "
    "never single point estimates."
)


def _band_label(dr: DealRisk) -> str:
    return f"deal-risk {dr.weight:.2f} ({dr.band})"


def _validation_basis(finding: Finding) -> str:
    if finding.corroborated_by:
        sources = sorted({item.source_name for item in finding.corroborated_by})
        return "independently corroborated" + (f" ({', '.join(sources)})" if sources else "")
    if finding.falsification_status.value == "confirmed":
        return "confirmed by falsification"
    return "released by analyst review"


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
        f"**Validation basis:** {_validation_basis(finding)}.",
        "",
    ]


def _recorded_run_context(repo_id: str, config: Config) -> tuple[object | None, dict]:
    """Latest orchestrated run and its stage summaries; historical gaps stay explicit."""
    runs = db.list_pipeline_runs(config, repo_id=repo_id)
    if not runs:
        return None, {}
    pipeline = runs[0]
    stages = {stage.stage: stage.summary for stage in db.list_stage_runs(pipeline.id, config)}
    return pipeline, stages


def _as_of_lines(
    repo_id: str,
    config: Config,
    *,
    audited_simulation: bool,
) -> list[str]:
    pipeline, stages = _recorded_run_context(repo_id, config)
    snapshots = [item for item in db.list_ingested_repos(config) if item.repo_id == repo_id]
    commit = pipeline.commit_hash if pipeline and pipeline.commit_hash else (
        snapshots[0].commit_hash if snapshots else None
    )
    simulations = db.list_simulation_runs(repo_id, config) if audited_simulation else []
    simulation = simulations[-1] if simulations else None

    llm_records = [summary.get("llm") for summary in stages.values() if summary.get("llm")]
    provider = next((item.get("provider") for item in llm_records if item.get("provider")), None)
    model = next((item.get("model") for item in llm_records if item.get("model")), None)
    prompts: dict[str, str] = {}
    for item in llm_records:
        prompts.update(item.get("prompt_versions") or {})

    detect = stages.get("detect", {})
    coverage = detect.get("scanner_coverage")
    semgrep_status = detect.get("semgrep_status")
    if coverage is None:
        coverage_text = "not recorded for this run"
    elif not coverage.get("checked"):
        coverage_text = "deterministic scanners disabled by configuration"
    elif coverage.get("missing"):
        coverage_text = "incomplete; unavailable: " + ", ".join(coverage["missing"])
    elif semgrep_status not in (None, "complete", "empty"):
        coverage_text = f"incomplete; Semgrep status={semgrep_status}"
    else:
        coverage_text = "complete: Semgrep, gitleaks, pip-audit, OSV-Scanner available"

    triage = stages.get("triage", {})
    evaluations = triage.get("evaluations") or []
    selected = next(
        (item for item in evaluations if item.get("model") == triage.get("model")),
        evaluations[0] if evaluations else None,
    )
    synthetic_share = triage.get("synthetic_share")
    if triage.get("synthetic_dropped"):
        synthetic_text = "0% (synthetic corpus dropped)"
    elif synthetic_share is not None:
        synthetic_text = f"{synthetic_share:.1%}"
    else:
        synthetic_text = "not recorded"
    real_labels = triage.get("real_labels")
    suppressed = triage.get("suppressed")
    triage_model = triage.get("model")

    lines = [
        "## Analysis as of / reproducibility",
        "",
        f"- **Repository commit:** `{commit}`" if commit else "- **Repository commit:** not recorded",
        f"- **Analysis timestamp:** {simulation.created_at}" if simulation and simulation.created_at
        else "- **Analysis timestamp:** not recorded (use `--record-audit`)",
        f"- **Simulation run:** #{simulation.id}; trials={simulation.trials:,}; seed={simulation.seed}"
        if simulation else "- **Simulation run:** not recorded (use `--record-audit`)",
        f"- **Model:** {provider}/{model}" if provider and model else "- **Model:** not recorded",
        "- **Prompt versions:** " + (
            ", ".join(f"{name}={version}" for name, version in sorted(prompts.items()))
            if prompts else "not recorded"
        ),
        f"- **Scanner coverage:** {coverage_text}",
        "",
        "### Triage confidence context",
        "",
        f"- **Triage model:** {triage_model or 'not recorded'}",
        f"- **Real labels:** {real_labels if real_labels is not None else 'not recorded'}",
        f"- **Synthetic training share:** {synthetic_text}",
        f"- **Evaluation basis:** {selected.get('eval_on', 'not recorded') if selected else 'not recorded'}",
        f"- **Evaluation sample:** {selected['n_eval']} finding(s)"
        if selected and selected.get("n_eval") is not None
        else "- **Evaluation sample:** not recorded",
        f"- **Brier score:** {selected['brier']:.4f}" if selected and selected.get("brier") is not None
        else "- **Brier score:** not recorded",
        f"- **Average precision:** {selected['average_precision']:.4f}"
        if selected and selected.get("average_precision") is not None
        else "- **Average precision:** not recorded",
        f"- **Suppressed findings:** {suppressed if suppressed is not None else 'not recorded'}",
        "",
    ]
    return lines


def _strip_h1(markdown: str) -> str:
    """Drop a leading level-1 heading so the appendix nests under the memo's own structure."""
    lines = markdown.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    return "\n".join(lines).lstrip("\n")


def build_memo(
    repo_id: str,
    config: Config | None = None,
    *,
    record_audit: bool = False,
    quantification: QuantificationArtifacts | None = None,
) -> str:
    """Render the leadership risk memo for a repo.

    Reads the review-gated finding set and never mutates a finding or severity. When
    `record_audit` is True, the backing Monte-Carlo run is persisted as a `SimulationRun`
    (with its scenario/prior-source evidence) so there is an audit trail of what the
    presented memo was based on — additive logging only; the deal-weighting is still
    computed with `persist=False`.
    """
    config = config or get_config()
    if quantification is not None and record_audit and not quantification.audit_recorded:
        raise ValueError(
            "record_audit=True requires quantification artifacts produced with persist=True"
        )

    # Deal weights for the review-gated set (persist=False — a report never mutates the store).
    deal = {r.finding_id: r.deal_risk for r in weigh_deal_risk(repo_id, config, persist=False)}
    countable = db.list_countable_findings(repo_id, config)
    pending_reviews = open_review_requests(repo_id, config)
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
    if pending_reviews:
        lines += [
            f"**Completeness note:** {len(pending_reviews)} finding(s) withheld pending "
            "analyst review and excluded from this memo's findings and quantitative totals.",
            "",
        ]

    # FAIR Monte-Carlo appendix. A caller such as ``finalize`` may supply the artifacts
    # from its preceding quantify step; standalone memo generation still quantifies here.
    # Copy reusable artifacts into the memo directory so its relative chart links remain
    # valid without re-running the simulation.
    out_dir = config.resolve(config.paths.data_dir) / "reports" / f"{repo_id}_memo"
    out_dir.mkdir(parents=True, exist_ok=True)
    if quantification is None:
        appendix_path = generate_appendix(repo_id, config, out_dir=out_dir, persist=record_audit)
    else:
        for source in quantification.artifact_paths:
            destination = out_dir / source.name
            if source.resolve() != destination.resolve():
                shutil.copy2(source, destination)
        appendix_path = out_dir / quantification.appendix_path.name
    audited_simulation = record_audit or bool(
        quantification is not None and quantification.audit_recorded
    )
    lines += _as_of_lines(repo_id, config, audited_simulation=audited_simulation)
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


def write_memo(
    repo_id: str,
    config: Config | None = None,
    *,
    record_audit: bool = False,
    quantification: QuantificationArtifacts | None = None,
) -> list[Path]:
    """Render and write the memo, returning every report artifact path."""
    config = config or get_config()
    out_dir = config.resolve(config.paths.data_dir) / "reports" / f"{repo_id}_memo"
    out_dir.mkdir(parents=True, exist_ok=True)
    memo_path = out_dir / "memo.md"
    memo_path.write_text(build_memo(
        repo_id,
        config,
        record_audit=record_audit,
        quantification=quantification,
    ))
    return sorted(path for path in out_dir.iterdir() if path.is_file())
