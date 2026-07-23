"""Evaluation-only falsification convergence and solution-refinement checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.eval.convergence import (
    DEFAULT_PROFILES,
    render_convergence,
    run_finding_convergence,
)
from repoauditor.falsify.outcome import FalsificationOutcome, SelfCritique
from repoauditor.llm import LLMClient, ScriptedBackend
from repoauditor.map import ArchitectureMap
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, Finding

UAT = Path(__file__).parent / "fixtures" / "uat_lightweight_app" / "snapshot"
ARCH = ArchitectureMap(repo_id="r", commit="commit-abc")


def _finding(config) -> Finding:
    finding = Finding(
        repo_id="r",
        title="SQL injection [CWE-89]",
        file="storefront/catalog.py",
        line_start=38,
        line_end=38,
        citation_snippet="rows = db.query(sql)",
        source_tool="semgrep",
        confidence=0.9,
        severity="high",
    )
    finding.id = db.insert_finding(finding, config)
    return finding


def _handler(verdict_for_resolution):
    def handler(_system, _user, schema, context):
        if schema is SelfCritique:
            return SelfCritique(upholds=True, concern="scripted check", confidence=0.95)
        assert context["finding_id"] is not None
        return FalsificationOutcome(
            status=verdict_for_resolution(context["resolution"]),
            rationale="scripted resolution verdict",
            reachable=True,
            confidence=0.9,
        )
    return handler


def _run(tmp_config, verdict_for_resolution, *, seed_supported=True):
    db.init_db(tmp_config)
    finding = _finding(tmp_config)
    backend = ScriptedBackend(_handler(verdict_for_resolution))
    if not seed_supported:
        backend.sampling_seed = None
    result = run_finding_convergence(
        finding,
        snapshot_path=UAT,
        snapshot_commit="commit-abc",
        architecture=ARCH,
        index=RetrievalIndex().build(UAT),
        llm=LLMClient(backend, tmp_config),
        config=tmp_config,
    )
    return finding, result


def test_known_positive_is_stable_and_does_not_mutate_store(tmp_config):
    finding, result = _run(
        tmp_config, lambda _resolution: FalsificationStatus.CONFIRMED
    )

    assert result.classification == "stable"
    assert result.verdict_flip_rate == 0.0
    assert result.first_stable_resolution == "coarse"
    assert all(
        item.structural_claim_status == "structurally_verified"
        for item in result.observations
    )
    assert [
        item.max_iterations for item in result.observations
    ] == [1, 2, 3]
    assert result.observations[0].evidence_characters < (
        result.observations[-1].evidence_characters
    )
    assert db.list_falsification_iterations(finding.id, tmp_config) == []
    assert db.list_security_claims(finding.id, tmp_config) == []
    assert db.get_finding(finding.id, tmp_config).falsification_status is (
        FalsificationStatus.UNRESOLVED
    )


def test_known_negative_is_stable(tmp_config):
    _finding_row, result = _run(
        tmp_config, lambda _resolution: FalsificationStatus.KILLED
    )

    assert result.classification == "stable"
    assert {item.verdict for item in result.observations} == {
        FalsificationStatus.KILLED
    }


def test_context_sensitive_verdict_is_reported_as_oscillating(tmp_config):
    sequence = {
        "coarse": FalsificationStatus.KILLED,
        "standard": FalsificationStatus.CONFIRMED,
        "refined": FalsificationStatus.KILLED,
    }
    _finding_row, result = _run(tmp_config, sequence.__getitem__)

    assert result.classification == "oscillating"
    assert result.verdict_flip_rate == 1.0
    assert result.first_stable_resolution is None


def test_missing_provider_seed_is_disclosed(tmp_config):
    _finding_row, result = _run(
        tmp_config,
        lambda _resolution: FalsificationStatus.CONFIRMED,
        seed_supported=False,
    )

    assert result.sampling_seed is None
    assert "not seed-reproducible" in render_convergence(result)


def test_same_snapshot_and_scripted_instrument_reproduce_result(tmp_config):
    db.init_db(tmp_config)
    finding = _finding(tmp_config)

    def execute():
        return run_finding_convergence(
            finding,
            snapshot_path=UAT,
            snapshot_commit="commit-abc",
            architecture=ARCH,
            index=RetrievalIndex().build(UAT),
            llm=LLMClient(
                ScriptedBackend(
                    _handler(lambda _resolution: FalsificationStatus.CONFIRMED)
                ),
                tmp_config,
            ),
            config=tmp_config,
            profiles=DEFAULT_PROFILES,
        )

    first = execute()
    second = execute()

    assert first.observations == second.observations
    assert first.model_dump(exclude={"observations"}) == second.model_dump(
        exclude={"observations"}
    )


def test_profiles_must_actually_refine_resolution(tmp_config):
    db.init_db(tmp_config)
    finding = _finding(tmp_config)
    duplicate = DEFAULT_PROFILES[0].model_copy(update={"name": "same"})

    with pytest.raises(ValueError, match="does not refine"):
        run_finding_convergence(
            finding,
            snapshot_path=UAT,
            snapshot_commit="commit-abc",
            architecture=ARCH,
            index=RetrievalIndex().build(UAT),
            llm=LLMClient(
                ScriptedBackend(
                    _handler(lambda _resolution: FalsificationStatus.CONFIRMED)
                ),
                tmp_config,
            ),
            config=tmp_config,
            profiles=[DEFAULT_PROFILES[0], duplicate],
        )
