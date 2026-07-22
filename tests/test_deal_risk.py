"""Tests for analyze/deal_risk.py — deal-relevant re-weighting, alongside (not replacing)
technical severity, from production exposure + categorical remediation cost + a config-driven
rep-&-warranty mapping.
"""

from __future__ import annotations

import pytest

from repoauditor.config import load_deal_risk
from repoauditor.analyze.deal_risk import weigh_deal_risk
from repoauditor.review import raise_review_requests
from repoauditor.store import db
from repoauditor.store.models import (
    Corroboration,
    Entity,
    EntityKind,
    FalsificationStatus,
    Finding,
    SourceType,
    TrustBoundary,
)


@pytest.fixture
def cfg(tmp_config):
    """tmp_config with the real deal_risk.yaml taxonomy attached (mirrors risk_quant tests)."""
    return tmp_config.model_copy(update={"deal_risk": load_deal_risk()})


def _finding(cfg, *, title, desc, sev="high", source_tool=None, source_lens="owasp",
             tb=None, entity=None, status=FalsificationStatus.UNRESOLVED, corr=None):
    return db.insert_finding(Finding(
        repo_id="r", title=title, file="app.py", line_start=1, line_end=1,
        citation_snippet="code",
        source_lens=None if source_tool else source_lens, source_tool=source_tool,
        confidence=0.8, severity=sev, description=desc, falsification_status=status,
        trust_boundary_id=tb, entity_id=entity, corroborated_by=corr or [],
    ), cfg)


def _by_finding(results):
    return {r.finding_id: r.deal_risk for r in results}


# --------------------------------------------------------------------------- #
# Remediation cost category is categorical and driven by finding type.
# --------------------------------------------------------------------------- #
def test_remediation_categories_by_finding_type(cfg):
    db.init_db(cfg)
    secret = _finding(cfg, title="Hardcoded credential", desc="secret [CWE-798]",
                      source_tool="secrets")
    supply = _finding(cfg, title="Vulnerable dependency", desc="flask CVE-2019 [CWE-1104]",
                      source_tool="sca")
    access = _finding(cfg, title="Broken access control", desc="missing authz [CWE-862]")
    injection = _finding(cfg, title="SQL injection", desc="sqli [CWE-89]")

    dr = _by_finding(weigh_deal_risk("r", cfg))
    assert dr[secret].remediation_category == "fast"       # rotate + purge
    assert dr[supply].remediation_category == "major"      # version bump
    assert dr[access].remediation_category == "redesign"   # architectural rework
    assert dr[injection].remediation_category == "moderate"


# --------------------------------------------------------------------------- #
# Production exposure comes from the map stage (trust boundary + entity).
# --------------------------------------------------------------------------- #
def test_production_exposure_from_map(cfg):
    db.init_db(cfg)
    tb = db.insert_trust_boundary(
        TrustBoundary(repo_id="r", name="batch worker",
                      description="background job queue consumer"), cfg)
    store_ent = db.insert_entity(
        Entity(repo_id="r", kind=EntityKind.DATA_STORE, name="users db",
               trust_boundary_id=tb), cfg)
    comp_ent = db.insert_entity(
        Entity(repo_id="r", kind=EntityKind.COMPONENT, name="helper",
               trust_boundary_id=tb), cfg)

    on_store = _finding(cfg, title="issue", desc="x [CWE-89]", tb=tb, entity=store_ent)
    on_comp = _finding(cfg, title="issue", desc="x [CWE-89]", tb=tb, entity=comp_ent)
    no_link = _finding(cfg, title="issue", desc="x [CWE-89]")

    dr = _by_finding(weigh_deal_risk("r", cfg))
    assert dr[on_store].production_exposure == "direct"      # data at rest
    assert dr[on_store].exposure_component == pytest.approx(1.0)
    assert dr[on_comp].production_exposure == "internal"     # internal component
    assert dr[no_link].production_exposure == "unknown"      # no linkage -> moderate, not 0
    assert dr[no_link].exposure_component == pytest.approx(0.5)


def test_production_indicator_keyword_forces_direct(cfg):
    db.init_db(cfg)
    tb = db.insert_trust_boundary(
        TrustBoundary(repo_id="r", name="public HTTP edge",
                      description="customer traffic"), cfg)
    f = _finding(cfg, title="issue", desc="x [CWE-89]", tb=tb)
    dr = _by_finding(weigh_deal_risk("r", cfg))
    assert dr[f].production_exposure == "direct"  # 'public'/'customer' indicator matched


# --------------------------------------------------------------------------- #
# Rep & warranty relevance is a config-driven lookup, not hardcoded.
# --------------------------------------------------------------------------- #
def test_rep_warranty_is_config_driven(cfg):
    db.init_db(cfg)
    secret = _finding(cfg, title="Hardcoded credential", desc="secret [CWE-798]",
                      source_tool="secrets")
    other = _finding(cfg, title="Missing rate limiting", desc="no throttling on route")

    dr = _by_finding(weigh_deal_risk("r", cfg))
    assert dr[secret].rep_warranty_relevant is True
    assert dr[secret].rep_warranty_category == "secret"
    assert dr[secret].rep_warranty_component > 0.0
    # An unmapped finding falls to 'other' — not squarely under a standard security rep.
    assert dr[other].rep_warranty_relevant is False
    assert dr[other].rep_warranty_category is None
    assert dr[other].rep_warranty_component == pytest.approx(0.0)


def test_editing_the_config_changes_the_mapping_without_touching_code(cfg):
    """The mapping is data: flip 'other' to rep-relevant in config and the weight follows."""
    db.init_db(cfg)
    other = _finding(cfg, title="Odd thing", desc="no category match here")
    base = _by_finding(weigh_deal_risk("r", cfg))[other]
    assert base.rep_warranty_relevant is False

    edited = cfg.deal_risk.model_copy(deep=True)
    edited.categories["other"].rep_warranty.relevant = True
    edited.categories["other"].rep_warranty.weight = 1.0
    cfg2 = cfg.model_copy(update={"deal_risk": edited})
    bumped = _by_finding(weigh_deal_risk("r", cfg2))[other]
    assert bumped.rep_warranty_relevant is True
    assert bumped.weight > base.weight  # same finding, heavier deal weight, no code change


# --------------------------------------------------------------------------- #
# The weight is layered alongside — never overwriting — technical severity.
# --------------------------------------------------------------------------- #
def test_weight_is_blended_and_severity_is_never_overwritten(cfg):
    db.init_db(cfg)
    fid = _finding(cfg, title="Hardcoded credential", desc="secret [CWE-798]",
                   sev="high", source_tool="secrets")
    results = weigh_deal_risk("r", cfg)
    dr = results[0].deal_risk

    # The weight equals the documented four-component blend (fully reconstructable).
    b = cfg.deal_risk.blend
    expected = (b.severity * dr.severity_component
                + b.production_exposure * dr.exposure_component
                + b.remediation * dr.remediation_component
                + b.rep_warranty * dr.rep_warranty_component)
    assert dr.weight == pytest.approx(round(min(1.0, expected), 4))
    assert 0.0 <= dr.weight <= 1.0

    # Technical severity is surfaced alongside and the finding row is untouched.
    assert results[0].technical_severity == "high"
    assert db.list_findings("r", cfg)[0].severity == "high"


def test_persisted_and_listed_heaviest_first(cfg):
    db.init_db(cfg)
    _finding(cfg, title="SQL injection", desc="sqli [CWE-89]", sev="critical")
    _finding(cfg, title="Missing rate limiting", desc="no throttling", sev="low")
    weigh_deal_risk("r", cfg)

    rows = db.list_deal_risk("r", cfg)
    assert len(rows) == 2
    assert rows[0].weight >= rows[1].weight  # ordered heaviest-first
    assert all(0.0 <= r.weight <= 1.0 for r in rows)


def test_idempotent_per_finding(cfg):
    db.init_db(cfg)
    _finding(cfg, title="secret", desc="[CWE-798]", source_tool="secrets")
    weigh_deal_risk("r", cfg)
    weigh_deal_risk("r", cfg)  # re-run
    assert len(db.list_deal_risk("r", cfg)) == 1  # UNIQUE(finding_id) upsert, not a dup


# --------------------------------------------------------------------------- #
# Review gate: same discipline as risk_quant — held/killed findings are excluded.
# --------------------------------------------------------------------------- #
def test_review_gate_excludes_held_and_killed(cfg):
    db.init_db(cfg)
    killed = _finding(cfg, title="dead", desc="[CWE-89]",
                      status=FalsificationStatus.KILLED)
    held = _finding(cfg, title="ambiguous", desc="[CWE-89]",
                    status=FalsificationStatus.UNRESOLVED)
    raise_review_requests("r", cfg)  # routes the unresolved one to review (no decision yet)

    weighted = {r.finding_id for r in weigh_deal_risk("r", cfg)}
    assert killed not in weighted
    assert held not in weighted


# --------------------------------------------------------------------------- #
# Corroboration score is context in the rationale, not a hidden term in the weight.
# --------------------------------------------------------------------------- #
def test_corroboration_score_is_context_not_a_weight_term(cfg):
    db.init_db(cfg)
    plain = _finding(cfg, title="secret", desc="[CWE-798]", source_tool="secrets")
    corr = _finding(cfg, title="secret2", desc="[CWE-798]", source_tool="gitleaks",
                    corr=[Corroboration(source_type=SourceType.LENS, source_name="owasp",
                                        score=0.5, match_basis="line_overlap")])
    dr = _by_finding(weigh_deal_risk("r", cfg))
    # Both are the same category/exposure/remediation, so the weight is identical despite
    # one carrying a corroboration score — corroboration informs the rationale, not the math.
    assert dr[plain].weight == pytest.approx(dr[corr].weight)
    assert "corroboration=0.50" in dr[corr].rationale
    assert "corroboration=0.00" in dr[plain].rationale
