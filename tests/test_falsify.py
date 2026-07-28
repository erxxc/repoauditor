"""Tests for the falsification challenger's bounded observe-think-act-reflect loop.

Covers the definition of done: a confident, self-critique-upheld verdict commits early;
a deliberately-ambiguous case runs multiple iterations, logs each one, and degrades to
`unresolved` at the configured limit rather than forcing a verdict; and the self-critique
step can veto a shaky verdict the confidence gate alone would have accepted.
"""

from __future__ import annotations

from pathlib import Path

from repoauditor.config import FalsifyConfig
from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.falsify import challenge_finding
from repoauditor.falsify.challenger import _falsification_context
from repoauditor.falsify.counterexample import RegexGuardWitness
from repoauditor.falsify.outcome import FalsificationOutcome, SelfCritique
from repoauditor.llm import LLMClient, ScriptedBackend
from repoauditor.map import ArchitectureMap, EntryPoint
from repoauditor.review import raise_review_requests
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, Finding

ARCH = ArchitectureMap(repo_id="r", commit="deadbeef")
UAT_SNAPSHOT = Path(__file__).parent / "fixtures" / "uat_lightweight_app" / "snapshot"


def test_supported_finding_context_contains_non_authoritative_slice():
    finding = Finding(
        repo_id="r", title="SQL injection [CWE-89]",
        file="storefront/catalog.py", line_start=39, line_end=39,
        citation_snippet="rows = db.query(sql)", source_tool="semgrep",
        confidence=0.8, severity="high",
    )

    context = _falsification_context(
        RetrievalIndex().build(UAT_SNAPSHOT), finding, ARCH, iteration=1
    )

    assert "DETERMINISTIC PYTHON SLICE" in context
    assert "evidence only" in context
    assert "path feasibility" in context


def test_challenge_persists_structural_claim_without_using_it_as_verdict(tmp_config):
    db.init_db(tmp_config)
    finding = Finding(
        repo_id="r", title="SQL injection [CWE-89]",
        file="storefront/catalog.py", line_start=38, line_end=38,
        citation_snippet="rows = db.query(sql)", source_tool="semgrep",
        confidence=0.8, severity="high",
    )
    finding_id = db.insert_finding(finding, tmp_config)
    finding = finding.model_copy(update={"id": finding_id})

    outcome = challenge_finding(
        finding,
        ARCH,
        LLMClient(
            ScriptedBackend(
                _handler(FalsificationStatus.UNRESOLVED, 0.9, True)
            ),
            tmp_config,
        ),
        index=RetrievalIndex().build(UAT_SNAPSHOT),
        config=tmp_config,
        snapshot_commit="deadbeef",
    )

    assert outcome.status is FalsificationStatus.UNRESOLVED
    claims = db.list_security_claims(finding_id, tmp_config)
    assert len(claims) == 1
    verification = db.list_claim_verifications(claims[0].id, tmp_config)[0]
    assert verification.status.value == "structurally_verified"
    assert "real-world risk are not validated" in verification.reason
    requests = raise_review_requests("r", tmp_config)
    claim_evidence = requests[0].evidence["security_claims"][0]
    assert claim_evidence["verifications"][0]["status"] == "structurally_verified"
    assert "reachability" in claim_evidence["verifications"][0]["reason"]


def _handler(verdict_status, verdict_conf, upholds, critique_conf=0.9):
    def handler(system, user, schema, context):
        if schema is SelfCritique:
            return SelfCritique(upholds=upholds, concern="scripted critique",
                                confidence=critique_conf)
        return FalsificationOutcome(status=verdict_status, rationale="scripted verdict",
                                    reachable=True, confidence=verdict_conf)
    return handler


def _persist_unresolved(cfg, title="Candidate") -> Finding:
    finding = Finding(
        repo_id="r", title=title, file="svc.py", line_start=21, line_end=21,
        citation_snippet='os.popen("ping " + host)', source_tool="semgrep",
        confidence=0.6, severity="critical",
        falsification_status=FalsificationStatus.UNRESOLVED,
    )
    fid = db.insert_finding(finding, cfg)
    return finding.model_copy(update={"id": fid})


def _challenge(cfg, handler, finding):
    return challenge_finding(finding, ARCH, LLMClient(ScriptedBackend(handler), cfg),
                             index=None, config=cfg)


# --------------------------------------------------------------------------- #
# Early commit on a confident, self-critique-upheld verdict
# --------------------------------------------------------------------------- #
def test_confident_upheld_verdict_commits_on_first_iteration(tmp_config):
    db.init_db(tmp_config)
    finding = _persist_unresolved(tmp_config, "Command injection")
    outcome = _challenge(tmp_config, _handler(FalsificationStatus.CONFIRMED, 0.9, True), finding)

    assert outcome.status is FalsificationStatus.CONFIRMED
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert len(trace) == 1                  # committed early, did not burn the budget
    assert trace[0].committed is True
    assert trace[0].critique_upholds is True


def test_confident_kill_commits_and_is_logged(tmp_config):
    db.init_db(tmp_config)
    finding = _persist_unresolved(tmp_config, "False positive")
    outcome = _challenge(tmp_config, _handler(FalsificationStatus.KILLED, 0.9, True), finding)

    assert outcome.status is FalsificationStatus.KILLED
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert len(trace) == 1 and trace[0].committed is True


# --------------------------------------------------------------------------- #
# Degrade to unresolved at the limit (DoD): logs every iteration, forces nothing
# --------------------------------------------------------------------------- #
def test_low_confidence_verdict_exhausts_budget_and_degrades_to_unresolved(tmp_config):
    db.init_db(tmp_config)
    finding = _persist_unresolved(tmp_config, "Ambiguous input")
    # Verdict is a confident-sounding CONFIRMED, but confidence stays below threshold.
    outcome = _challenge(tmp_config, _handler(FalsificationStatus.CONFIRMED, 0.3, True), finding)

    assert outcome.status is FalsificationStatus.UNRESOLVED
    assert "unresolved" in outcome.rationale.lower()
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert len(trace) == 3                       # ran the full (default) budget
    assert all(it.committed is False for it in trace)   # never forced a verdict


def test_iteration_limit_is_config_driven(tmp_config):
    cfg = tmp_config.model_copy(update={"falsify": FalsifyConfig(max_iterations=2)})
    db.init_db(cfg)
    finding = _persist_unresolved(cfg, "Ambiguous")
    outcome = _challenge(cfg, _handler(FalsificationStatus.CONFIRMED, 0.3, True), finding)

    assert outcome.status is FalsificationStatus.UNRESOLVED
    assert len(db.list_falsification_iterations(finding.id, cfg)) == 2


# --------------------------------------------------------------------------- #
# Self-critique can veto a verdict the confidence gate alone would have accepted
# --------------------------------------------------------------------------- #
def test_self_critique_veto_blocks_a_confident_but_unsupported_verdict(tmp_config):
    db.init_db(tmp_config)
    finding = _persist_unresolved(tmp_config, "Over-reaching confirm")
    # High-confidence verdict, but the self-critique never upholds it -> must NOT commit.
    outcome = _challenge(tmp_config, _handler(FalsificationStatus.CONFIRMED, 0.95, False), finding)

    assert outcome.status is FalsificationStatus.UNRESOLVED
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert len(trace) == 3
    assert all(it.critique_upholds is False for it in trace)
    assert all(it.committed is False for it in trace)


def test_shaky_self_critique_confidence_also_blocks_commit(tmp_config):
    db.init_db(tmp_config)
    finding = _persist_unresolved(tmp_config, "Shaky critique")
    # Verdict confident and critique 'upholds', but the critique itself is low-confidence.
    outcome = _challenge(
        tmp_config,
        _handler(FalsificationStatus.CONFIRMED, 0.95, True, critique_conf=0.2),
        finding,
    )
    assert outcome.status is FalsificationStatus.UNRESOLVED
    assert len(db.list_falsification_iterations(finding.id, tmp_config)) == 3


def _regex_bypass_finding(cfg) -> Finding:
    finding = Finding(
        repo_id="r",
        title="Case-sensitive validation bypass",
        file="guards.js",
        line_start=2,
        line_end=2,
        citation_snippet='const blocked = /^safe$/.test(input);',
        source_tool="semgrep",
        confidence=0.9,
        severity="high",
        falsification_status=FalsificationStatus.UNRESOLVED,
    )
    finding_id = db.insert_finding(finding, cfg)
    return finding.model_copy(update={"id": finding_id})


def _regex_handler(witness: RegexGuardWitness | None):
    def handler(system, user, schema, context):
        if schema is SelfCritique:
            return SelfCritique(
                upholds=True,
                concern="reachability, acceptance, and effect are present in the fixture",
                confidence=0.95,
            )
        return FalsificationOutcome(
            status=FalsificationStatus.CONFIRMED,
            rationale="scripted regex-control bypass",
            reachable=True,
            confidence=0.95,
            counterexample_witness=witness,
        )
    return handler


def test_regex_bypass_confirm_without_witness_cannot_commit(tmp_config):
    db.init_db(tmp_config)
    finding = _regex_bypass_finding(tmp_config)

    outcome = _challenge(tmp_config, _regex_handler(None), finding)

    assert outcome.status is FalsificationStatus.UNRESOLVED
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert len(trace) == 3
    assert all(not row.committed for row in trace)
    assert {
        row.counterexample_verification["status"] for row in trace
    } == {"verification_incomplete"}


def test_regex_bypass_confirm_with_matching_input_cannot_commit(tmp_config):
    db.init_db(tmp_config)
    finding = _regex_bypass_finding(tmp_config)
    witness = RegexGuardWitness(
        input="safe",
        control_expression="/^safe$/.test(input)",
        expected_security_effect="input passes the validation control",
    )

    outcome = _challenge(tmp_config, _regex_handler(witness), finding)

    assert outcome.status is FalsificationStatus.UNRESOLVED
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert all(not row.committed for row in trace)
    assert {
        row.counterexample_verification["status"] for row in trace
    } == {"refuted_guard_match"}


def test_regex_bypass_confirm_with_verified_guard_miss_can_commit_and_is_logged(
    tmp_config,
):
    db.init_db(tmp_config)
    finding = _regex_bypass_finding(tmp_config)
    witness = RegexGuardWitness(
        input="SAFE",
        control_expression="/^safe$/.test(input)",
        expected_security_effect="mixed-case input evades a case-sensitive validation guard",
    )

    outcome = _challenge(tmp_config, _regex_handler(witness), finding)

    assert outcome.status is FalsificationStatus.CONFIRMED
    trace = db.list_falsification_iterations(finding.id, tmp_config)
    assert len(trace) == 1 and trace[0].committed
    assert trace[0].counterexample_witness["input"] == "SAFE"
    assert (
        trace[0].counterexample_verification["status"]
        == "verified_guard_miss"
    )


def test_sql_injection_confirms_when_enclosing_route_context_is_retrieved(tmp_config):
    finding = Finding(
        repo_id="uat", title="SQL injection", file="storefront/catalog.py",
        line_start=33, line_end=35,
        citation_snippet='sql = "SELECT" + term + category',
        source_lens="owasp", confidence=0.9, severity="critical",
    )

    def handler(system, user, schema, context):
        supported = (
            '@catalog_bp.route("/products/search")' in user
            and 'request.args.get("q"' in user
        )
        if schema is SelfCritique:
            return SelfCritique(
                upholds=supported, concern="route and request source are present",
                confidence=0.95,
            )
        return FalsificationOutcome(
            status=(
                FalsificationStatus.CONFIRMED
                if supported else FalsificationStatus.UNRESOLVED
            ),
            rationale="scripted evidence-sensitive SQLi verdict",
            reachable=True if supported else None,
            confidence=0.95 if supported else 0.3,
        )

    outcome = challenge_finding(
        finding,
        ArchitectureMap(
            repo_id="uat", commit="fixture",
            entry_points=[EntryPoint(
                name="GET /products/search",
                location="storefront/catalog.py:search_products",
            )],
        ),
        LLMClient(ScriptedBackend(handler), tmp_config),
        RetrievalIndex().build(UAT_SNAPSHOT),
        tmp_config,
    )

    assert outcome.status is FalsificationStatus.CONFIRMED


def test_dead_legacy_sink_kills_after_config_and_registration_evidence(tmp_config):
    finding = Finding(
        repo_id="uat", title="Command injection", file="storefront/legacy.py",
        line_start=33, line_end=34,
        citation_snippet='os.system("curl -s " + source)',
        source_lens="owasp", confidence=0.8, severity="high",
    )
    verdict_iterations: list[int] = []

    def handler(system, user, schema, context):
        supported = (
            "ENABLE_LEGACY_IMPORT = False" in user
            and "app.register_blueprint" in user
            and "legacy_bp" in user
        )
        if schema is SelfCritique:
            return SelfCritique(
                upholds=supported, concern="independent registration/config evidence",
                confidence=0.95,
            )
        verdict_iterations.append(context["iteration"])
        return FalsificationOutcome(
            status=(
                FalsificationStatus.KILLED
                if supported else FalsificationStatus.UNRESOLVED
            ),
            rationale="scripted evidence-sensitive dead-code verdict",
            reachable=False if supported else None,
            confidence=0.95 if supported else 0.3,
        )

    outcome = challenge_finding(
        finding,
        ArchitectureMap(
            repo_id="uat", commit="fixture",
            entry_points=[EntryPoint(
                name="active storefront routes",
                location="storefront/__init__.py:create_app",
            )],
        ),
        LLMClient(ScriptedBackend(handler), tmp_config),
        RetrievalIndex().build(UAT_SNAPSHOT),
        tmp_config,
    )

    assert outcome.status is FalsificationStatus.KILLED
    assert verdict_iterations == [1, 2, 3]
