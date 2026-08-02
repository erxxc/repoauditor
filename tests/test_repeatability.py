"""OPT-004 execution is bounded, immutable, and non-mutating."""

import json
from pathlib import Path

import pytest

from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.eval.repeatability import _digest, run_repeatability
from repoauditor.falsify.outcome import FalsificationOutcome, SelfCritique
from repoauditor.ingest import ingest_repo, latest_snapshot
from repoauditor.llm import LLMClient, ScriptedBackend
from repoauditor.llm.backends import BackendUsage
from repoauditor.map import load_architecture
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, Finding

UAT = Path(__file__).parent / "fixtures" / "uat_lightweight_app" / "snapshot"


class MeteredScriptedBackend(ScriptedBackend):
    def __init__(self, handler):
        super().__init__(handler)
        self.tracks_usage = True

    def complete(self, **kwargs):
        result = super().complete(**kwargs)
        self.last_usage = BackendUsage(input_tokens=100, output_tokens=10)
        return result


def _handler(_system, _user, schema, context):
    if schema is SelfCritique:
        return SelfCritique(upholds=True, concern="scripted", confidence=0.95)
    return FalsificationOutcome(
        status=(FalsificationStatus.CONFIRMED
                if context["finding_id"] == 1 else FalsificationStatus.KILLED),
        rationale="scripted repeatability result", reachable=True, confidence=0.9,
    )


def _receipt(tmp_config, tmp_path):
    db.init_db(tmp_config)
    ingested = ingest_repo(str(UAT), tmp_config, repo_id="repeatability-fixture")
    findings = []
    for title, line in (("SQL injection [CWE-89]", 38), ("Benign marker", 5)):
        finding = Finding(
            repo_id=ingested.repo_id, title=title, file="storefront/catalog.py",
            line_start=line, line_end=line, citation_snippet="example",
            source_tool="semgrep", confidence=0.8, severity="medium",
        )
        finding.id = db.insert_finding(finding, tmp_config)
        findings.append(finding)
    snapshot, commit = latest_snapshot(tmp_config, ingested.repo_id)
    architecture = load_architecture(ingested.repo_id, commit, tmp_config)
    index = RetrievalIndex().build(snapshot)
    receipt = {
        "subjects": [
            {"finding_id": item.id,
             "finding_row_digest": _digest(item.model_dump(mode="json"))}
            for item in findings
        ],
        "repository": {"snapshot_commit": commit},
        "held_constant_digests": {
            "architecture_artifact": _digest(architecture.model_dump(mode="json")),
            "retrieval_index": index.content_digest(),
        },
        "instrument": {
            "provider": tmp_config.llm.provider, "model": tmp_config.model.name,
            "repetitions_per_subject": 3,
        },
        "proposed_aggregate_budget": {
            "maximum_provider_calls": 72,
            "maximum_provider_reported_tokens": 250000,
            "maximum_usd": 6.25,
        },
    }
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    return path, receipt, findings


def test_repeatability_runs_six_fresh_observations_without_mutating_findings(
    tmp_config, tmp_path
):
    tmp_config = tmp_config.model_copy(update={
        "model": tmp_config.model.model_copy(update={"name": "claude-opus-4-8"})
    })
    receipt_path, receipt, findings = _receipt(tmp_config, tmp_path)
    backend = MeteredScriptedBackend(_handler)

    result = run_repeatability(
        receipt_path, approved_receipt_digest=_digest(receipt), config=tmp_config,
        llm=LLMClient(backend, tmp_config),
    )

    assert result.status == "complete"
    assert len(result.observations) == 6
    assert result.aggregate_usage == {
        "calls": 24, "known_tokens": 2640, "calculated_cost_usd": 0.018,
    }
    assert all(item["verdict_agreement"] for item in result.subject_metrics)
    assert len({item.pipeline_run_id for item in result.observations}) == 6
    assert all(
        db.get_finding(item.id, tmp_config).falsification_status
        is FalsificationStatus.UNRESOLVED for item in findings
    )
    assert all(db.list_falsification_iterations(item.id, tmp_config) == [] for item in findings)

    calls_before_resume = len(backend.calls)
    resumed = run_repeatability(
        receipt_path, approved_receipt_digest=_digest(receipt), config=tmp_config,
        llm=LLMClient(backend, tmp_config),
    )
    assert resumed.observations == result.observations
    assert len(backend.calls) == calls_before_resume


def test_repeatability_rejects_unapproved_receipt_before_calls(tmp_config, tmp_path):
    tmp_config = tmp_config.model_copy(update={
        "model": tmp_config.model.model_copy(update={"name": "claude-opus-4-8"})
    })
    receipt_path, _receipt_data, _findings = _receipt(tmp_config, tmp_path)
    backend = MeteredScriptedBackend(_handler)

    with pytest.raises(ValueError, match="approved receipt digest"):
        run_repeatability(
            receipt_path, approved_receipt_digest="sha256:not-approved",
            config=tmp_config, llm=LLMClient(backend, tmp_config),
        )

    assert backend.calls == []
