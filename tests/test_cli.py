"""End-to-end CLI tests — the report projections and the review checkpoint commands driven
through the actual typer app, so the "full CLI run no longer dies at report" milestone and
the review list/decide surface are exercised exactly as a user would.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from repoauditor import cli
from repoauditor.config import load_deal_risk, load_priors
from repoauditor.falsify.outcome import FalsificationOutcome
from repoauditor.llm import remaining_pipeline_call_capacity
from repoauditor.map import (
    ArchitectureMap,
    DataStore,
    EntryPoint,
    TrustBoundary as MapTrustBoundary,
)
from repoauditor.review import raise_review_requests
from repoauditor.store import db
from repoauditor.store.models import (
    FalsificationStatus,
    Finding,
    IngestedRepo,
    ModelUsage,
    TriageLabelSource,
    TrustBoundary,
)

runner = CliRunner()


def test_map_stage_writes_ascii_architecture_artifact(tmp_config, monkeypatch, capsys):
    architecture = ArchitectureMap(
        repo_id="shop",
        commit="abcdef1234567890",
        trust_boundaries=[MapTrustBoundary(name="Public HTTP")],
        entry_points=[
            EntryPoint(name="GET /products", trust_boundary="Public HTTP")
        ],
        data_stores=[DataStore(name="catalog", kind="sqlite")],
    )
    monkeypatch.setattr(
        cli, "latest_snapshot", lambda config, repo_id: (Path("snapshot"), architecture.commit)
    )
    monkeypatch.setattr(
        cli, "recover_architecture",
        lambda snapshot, repo_id, commit, config: architecture,
    )

    result = cli._map_stage("shop", tmp_config)
    artifact = (
        tmp_config.paths.data_dir
        / "artifacts"
        / "shop"
        / "architecture-abcdef123456.txt"
    )

    assert result is architecture
    assert artifact.is_file()
    assert "{trust boundary: Public HTTP}" in artifact.read_text()
    assert f"artifact={artifact}" in capsys.readouterr().out


def test_falsify_convergence_cli_is_thin_and_supports_json(tmp_config, monkeypatch):
    from repoauditor.eval.convergence import ConvergenceResult

    result_model = ConvergenceResult(
        repo_id="r",
        finding_id=7,
        snapshot_commit="abc",
        model="scripted",
        provider="anthropic",
        prompt_versions={"falsify": "v1"},
        sampling_seed=None,
        observations=[],
        classification="stable",
        verdict_flip_rate=0.0,
        adjacent_evidence_jaccard=None,
        confidence_spread=0.0,
        first_stable_resolution=None,
    )
    monkeypatch.setattr(
        cli, "evaluate_finding_convergence", lambda finding_id, config: result_model
    )
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(
        cli.db, "get_finding", lambda finding_id, config: SimpleNamespace(repo_id="r")
    )
    monkeypatch.setattr(
        cli, "_metered_repo_stage",
        lambda repo_id, stage, fn, config: (fn(), SimpleNamespace(id=1)),
    )

    result = runner.invoke(
        cli.app, ["falsify-convergence", "7", "--format", "json"]
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["finding_id"] == 7


@pytest.fixture
def wired(tmp_config, monkeypatch):
    """A populated store + `cli.get_config` pointed at it, so the app hits the tmp DB."""
    cfg = tmp_config.model_copy(update={
        "priors": load_priors(), "deal_risk": load_deal_risk(),
    })
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    db.init_db(cfg)
    tb = db.insert_trust_boundary(
        TrustBoundary(repo_id="r", name="public HTTP edge", description="customer traffic"), cfg)
    db.insert_finding(Finding(
        repo_id="r", title="SQL injection", file="app.py", line_start=24, line_end=24,
        citation_snippet="SELECT * FROM users WHERE id = ' + user_id",
        source_lens="owasp", confidence=0.9, severity="critical",
        falsification_status=FalsificationStatus.CONFIRMED, description="sqli [CWE-89]",
        trust_boundary_id=tb), cfg)
    held = db.insert_finding(Finding(
        repo_id="r", title="Ambiguous input", file="app.py", line_start=22, line_end=22,
        citation_snippet="request.args.get('id')", source_lens="owasp", confidence=0.6,
        severity="low", falsification_status=FalsificationStatus.UNRESOLVED,
        description="[CWE-20]", trust_boundary_id=tb), cfg)
    raise_review_requests("r", cfg)   # opens a review request for the unresolved finding
    return cfg, held


def test_report_engineering_cli(wired):
    result = runner.invoke(cli.app, ["report", "r", "--mode", "engineering"])
    assert result.exit_code == 0, result.output
    assert "Engineering Remediation Backlog" in result.stdout
    assert "SELECT * FROM users WHERE id = ' + user_id" in result.stdout  # citation preserved
    assert "Ambiguous input" not in result.stdout                          # held -> excluded
    assert "reported r: wrote" in result.stdout and "backlog.md" in result.stdout


def test_report_memo_cli(wired, monkeypatch):
    def fake_appendix(repo_id, config, *, out_dir, **_kwargs):
        del repo_id, config
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / "risk_appendix.md"
        path.write_text("# Appendix\n\nTest quantification fixture.\n")
        return path

    monkeypatch.setattr("repoauditor.report.memo.generate_appendix", fake_appendix)
    result = runner.invoke(cli.app, ["report", "r", "--mode", "memo"])
    assert result.exit_code == 0, result.output
    assert "Security Risk Memo" in result.stdout
    assert "Appendix: Quantitative Risk Model" in result.stdout
    assert "Ambiguous input" not in result.stdout
    assert "reported r: wrote" in result.stdout and "memo.md" in result.stdout


def test_report_memo_record_audit_cli(wired, monkeypatch):
    def fake_charts(_result, _tornado, out_dir):
        for name in ("loss_exceedance.png", "tornado.png"):
            path = out_dir / name
            path.write_bytes(b"test chart")
        return {"exceedance": "loss_exceedance.png", "tornado": "tornado.png"}

    monkeypatch.setattr("repoauditor.analyze.risk_quant._render_charts", fake_charts)
    cfg, _held = wired
    assert db.list_simulation_runs("r", cfg) == []
    result = runner.invoke(cli.app, ["report", "r", "--mode", "memo", "--record-audit"])
    assert result.exit_code == 0, result.output
    assert "Security Risk Memo" in result.stdout
    # The flag left the audit trail; a plain memo run would not have.
    assert len(db.list_simulation_runs("r", cfg)) == 1


def test_review_list_and_decide_cli(wired):
    cfg, held = wired
    request = db.get_review_request(held, cfg)

    listed = runner.invoke(cli.app, ["review", "list", "r"])
    assert listed.exit_code == 0, listed.output
    assert f"finding #{held}" in listed.stdout
    assert f"request #{request.id}" in listed.stdout

    decided = runner.invoke(cli.app, [
        "review", "decide", "r", str(request.id),
        "--decision", "confirm", "--rationale", "traced the sink; it is reachable",
        "--reviewer", "alice",
    ])
    assert decided.exit_code == 0, decided.output
    assert "recorded decision" in decided.stdout
    # The append-only decision is recorded and releases the finding from the queue.
    assert db.latest_review_decision(request.id, cfg).disposition.value == "confirm"
    assert "No open review requests" in runner.invoke(cli.app, ["review", "list", "r"]).stdout


def test_review_list_json_is_structured(wired):
    _cfg, held = wired
    result = runner.invoke(cli.app, ["review", "list", "r", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload[0]["finding_id"] == held
    assert isinstance(payload[0]["evidence"], dict)


def _sarif_one() -> str:
    return json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "py.cmdi", "name": "Command Injection",
             "properties": {"tags": ["CWE-78"], "security-severity": "9.5"}}]}},
            "results": [{"ruleId": "py.cmdi", "level": "error",
                "message": {"text": "cmdi hit"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "svc/run.py"},
                    "region": {"startLine": 21, "endLine": 21,
                               "snippet": {"text": "os.system(x)"}}}}]}]}]})


@pytest.fixture
def triage_cfg(tmp_config, monkeypatch):
    cfg = tmp_config.model_copy(update={"priors": load_priors()})
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    db.init_db(cfg)
    return cfg


def test_triage_and_manual_label_cli(triage_cfg, tmp_path):
    cfg = triage_cfg
    sp = tmp_path / "scan.sarif"
    sp.write_text(_sarif_one())

    triaged = runner.invoke(cli.app, ["triage", "acme", "--sarif", str(sp)])
    assert triaged.exit_code == 0, triaged.output
    # Cold start: no real labels yet, synthetic teacher owns the whole training mass.
    assert "real=0" in triaged.stdout and "synthetic_share=100%" in triaged.stdout
    assert "eval_on=synthetic" in triaged.stdout
    assert "not real-world performance" in triaged.stdout

    fid = db.list_findings("acme", cfg)[0].id
    labelled = runner.invoke(cli.app, [
        "triage-label", str(fid), "--disposition", "true_positive", "--note", "reachable",
    ])
    assert labelled.exit_code == 0, labelled.output
    assert "true positive" in labelled.stdout and "precedence" in labelled.stdout

    labels = db.list_triage_labels(config=cfg)
    assert len(labels) == 1
    assert labels[0].actionable is True
    assert labels[0].source is TriageLabelSource.MANUAL


def test_triage_label_cli_rejects_untriaged_finding(triage_cfg):
    result = runner.invoke(cli.app, [
        "triage-label", "999", "--disposition", "false_positive",
        "--rationale", "not reachable",
    ])
    assert result.exit_code == 1
    assert "no finding with id 999" in result.output


def test_triage_stats_cli_withholds_curve_below_real_label_gate(triage_cfg):
    result = runner.invoke(cli.app, ["triage-stats"])

    assert result.exit_code == 0, result.output
    assert "real scored labels=0" in result.stdout
    assert ">=40 label gate" in result.stdout
    assert "Synthetic-heavy data is not substituted" in result.stdout


def test_triage_label_cli_records_uncertain_without_training_label(triage_cfg, tmp_path):
    sp = tmp_path / "scan.sarif"
    sp.write_text(_sarif_one())
    assert runner.invoke(cli.app, ["triage", "acme", "--sarif", str(sp)]).exit_code == 0
    fid = db.list_findings("acme", triage_cfg)[0].id

    result = runner.invoke(cli.app, [
        "triage-label", str(fid), "--disposition", "uncertain",
        "--rationale", "needs runtime tenant context", "--analyst", "alice",
        "--dimension", "tenant-isolation", "--dimension", "business-logic",
    ])

    assert result.exit_code == 0, result.output
    assert "excluded from classifier training" in result.stdout
    assert db.list_triage_labels(config=triage_cfg) == []
    assessment = db.list_triage_assessments("acme", triage_cfg)[0]
    assert assessment.analyst == "alice"
    assert assessment.dimensions == ["business-logic", "tenant-isolation"]

    status = runner.invoke(cli.app, ["triage-collection"])
    assert status.exit_code == 0
    assert "usable human labels=0/40" in status.stdout
    assert "explicit abstentions=1" in status.stdout


def test_triage_label_cli_accepts_detailed_non_actionable_reason(triage_cfg, tmp_path):
    sp = tmp_path / "scan.sarif"
    sp.write_text(_sarif_one())
    assert runner.invoke(cli.app, ["triage", "acme", "--sarif", str(sp)]).exit_code == 0
    fid = db.list_findings("acme", triage_cfg)[0].id

    result = runner.invoke(cli.app, [
        "triage-label", str(fid), "--disposition", "mitigated",
        "--rationale", "parameterized query blocks the flow", "--analyst", "alice",
    ])

    assert result.exit_code == 0, result.output
    assert "mitigated" in result.stdout
    assert db.list_triage_labels(config=triage_cfg)[0].actionable is False
    assert db.list_triage_assessments("acme", triage_cfg)[0].disposition.value == "mitigated"


def test_review_decide_rejects_wrong_repo(wired):
    cfg, held = wired
    request = db.get_review_request(held, cfg)
    result = runner.invoke(cli.app, [
        "review", "decide", "WRONG", str(request.id),
        "--decision", "dismiss", "--rationale", "n/a",
    ])
    assert result.exit_code == 1
    assert "belongs to repo" in result.output


def _wire_run_stages(monkeypatch, requests):
    calls = []
    monkeypatch.setattr(cli, "_preflight", lambda config: cli.PreflightResult())

    def stage(name, value=None):
        def invoke(*args, **kwargs):
            calls.append(name)
            return value
        return invoke

    monkeypatch.setattr(
        cli, "_ingest_stage", stage(
            "ingest", SimpleNamespace(repo_id="acme", commit="abc", snapshot_path=Path("snapshot"))
        )
    )
    monkeypatch.setattr(cli, "latest_snapshot", lambda config, repo_id: (Path("snapshot"), "abc"))
    monkeypatch.setattr(
        cli, "_map_stage",
        stage("map", SimpleNamespace(repo_id="acme", commit="abc")),
    )
    monkeypatch.setattr(
        cli, "_detect_stage", stage(
            "detect", SimpleNamespace(
                sarif_path=Path("scan.sarif"), semgrep_status="complete", source_counts={}
            )
        )
    )
    def triage(repo_id, config, sarif=None, threshold=0.5):
        assert sarif == Path("scan.sarif")
        calls.append("triage")
        return SimpleNamespace(
            n_real_labels=7,
            synthetic_share=0.25,
            synthetic_dropped=False,
            n_suppressed=2,
            model_name="xgboost",
            evaluations=[SimpleNamespace(
                model_name="xgboost", eval_on="real", brier=0.11,
                average_precision=0.82, n_eval=8, split_strategy="real_row_random",
                split_detail="grouped validation not yet available (1 engagements, need 8)",
            )],
        )

    monkeypatch.setattr(cli, "_triage_stage", triage)
    monkeypatch.setattr(cli, "_falsify_stage", stage("falsify"))
    monkeypatch.setattr(cli, "_normalize_stage", stage("normalize"))
    monkeypatch.setattr(cli, "raise_review_requests", stage("checkpoint", requests))
    monkeypatch.setattr(cli, "open_review_requests", lambda repo_id, config: requests)
    return calls


def test_run_stops_cleanly_with_open_review_requests(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    requests = [SimpleNamespace(id=7, finding_id=11)]
    calls = _wire_run_stages(monkeypatch, requests)

    result = runner.invoke(cli.app, ["run", "/target"])

    assert result.exit_code == 0, result.output
    assert calls == ["ingest", "map", "detect", "triage", "falsify", "normalize", "checkpoint"]
    assert "stopped at review checkpoint with 1 open request" in result.stdout
    assert "repoauditor review list acme" in result.stdout


def test_run_stops_cleanly_when_no_review_is_needed(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    calls = _wire_run_stages(monkeypatch, [])

    result = runner.invoke(cli.app, ["run", "/target"])

    assert result.exit_code == 0, result.output
    assert calls[-1] == "checkpoint"
    assert "no findings require review" in result.stdout
    assert "repoauditor finalize acme" in result.stdout

    pipeline = db.list_pipeline_runs(tmp_config, repo_id="acme")[0]
    summaries = {stage.stage: stage.summary for stage in db.list_stage_runs(pipeline.id, tmp_config)}
    assert summaries["detect"]["scanner_coverage"] == {"checked": True, "missing": []}
    assert summaries["detect"]["model_usage"] == "not recorded"
    assert summaries["map"]["llm"]["prompt_versions"]["map"] == "architecture_recovery_v2"
    assert summaries["triage"]["real_labels"] == 7
    assert summaries["triage"]["evaluations"][0] == {
        "model": "xgboost", "eval_on": "real", "brier": 0.11,
        "average_precision": 0.82, "n_eval": 8,
        "split_strategy": "real_row_random",
        "split_detail": "grouped validation not yet available (1 engagements, need 8)",
    }

    db.insert_model_usage(
        ModelUsage(
            pipeline_run_id=pipeline.id,
            stage="detect",
            module="detect",
            prompt_version="lens_v1",
            provider="anthropic",
            model="test-model",
            usage_available=True,
            input_tokens=100,
            output_tokens=20,
            cache_read_tokens=10,
            cache_write_tokens=0,
            latency_ms=250,
        ),
        tmp_config,
    )
    detail = runner.invoke(cli.app, ["runs", "show", str(pipeline.id)])
    assert detail.exit_code == 0, detail.output
    assert "elapsed=" in detail.stdout
    assert "summary:" in detail.stdout
    assert '"model_usage": "not recorded"' in detail.stdout
    assert "model usage: calls=1; processed-tokens=130" in detail.stdout
    assert "unknown-usage-calls=0" in detail.stdout


def test_run_points_back_to_bounded_queue_when_findings_are_deferred(
    tmp_config, monkeypatch
):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    calls = _wire_run_stages(monkeypatch, [])
    monkeypatch.setattr(
        cli, "_falsify_stage",
        lambda repo_id, config: (
            calls.append("falsify"),
            SimpleNamespace(deferred_count=2),
        )[1],
    )
    monkeypatch.setattr(
        cli.db, "list_deferred_findings",
        lambda repo_id, config: [SimpleNamespace(id=91), SimpleNamespace(id=92)],
    )

    result = runner.invoke(cli.app, ["run", "/target with spaces"])

    assert result.exit_code == 0, result.output
    assert "2 finding(s) remain deferred" in result.stdout
    assert "not ready for analysis" in result.stdout
    assert "repoauditor resume acme" in result.stdout
    assert "repoauditor finalize" not in result.stdout
    assert "normalize" not in calls
    assert "checkpoint" not in calls


def _resume_fixture(tmp_config, monkeypatch, count=2):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(cli, "_preflight", lambda config: cli.PreflightResult())
    db.init_db(tmp_config)
    snapshot = tmp_config.raw_dir / "acme" / "abc"
    snapshot.mkdir(parents=True)
    db.record_ingested_repo(IngestedRepo(
        repo_id="acme", source="/original/source", commit_hash="abc"
    ), tmp_config)
    root = db.start_pipeline_run("/original/source", tmp_config)
    db.update_pipeline_run_identity(root.id, "acme", "abc", tmp_config)
    db.finish_pipeline_run(root.id, cli.RunStatus.COMPLETED, config=tmp_config)
    ids = [
        db.insert_finding(Finding(
            repo_id="acme", title=f"candidate-{index}", file="app.py",
            line_start=index, line_end=index, citation_snippet=f"sink-{index}",
            source_lens="owasp", confidence=0.8, severity="high",
            falsification_status=FalsificationStatus.DEFERRED,
        ), tmp_config)
        for index in range(1, count + 1)
    ]
    return ids


def test_resume_uses_fresh_budget_without_repeating_upstream_stages(
    tmp_config, monkeypatch
):
    ids = _resume_fixture(tmp_config, monkeypatch)
    observed = {}

    class Batch(list):
        deferred_count = 1

    def falsify(repo_id, config):
        observed["capacity"] = remaining_pipeline_call_capacity(config)
        db.update_falsification(
            ids[0], FalsificationStatus.CONFIRMED, "confirmed in batch", config
        )
        return Batch([FalsificationOutcome(
            status=FalsificationStatus.CONFIRMED, rationale="confirmed in batch"
        )])

    monkeypatch.setattr(cli, "_falsify_stage", falsify)
    monkeypatch.setattr(
        cli, "_map_stage", lambda *args, **kwargs: pytest.fail("map must not repeat")
    )
    monkeypatch.setattr(
        cli, "_detect_stage", lambda *args, **kwargs: pytest.fail("detect must not repeat")
    )
    monkeypatch.setattr(
        cli, "_triage_stage", lambda *args, **kwargs: pytest.fail("triage must not repeat")
    )
    monkeypatch.setattr(
        cli, "_normalize_stage",
        lambda *args, **kwargs: pytest.fail("normalize waits for an empty backlog"),
    )

    result = runner.invoke(cli.app, ["resume", "acme"])

    assert result.exit_code == 0, result.output
    assert observed["capacity"] == tmp_config.llm.max_calls_per_pipeline_run
    assert "backlog 2 -> 1" in result.stdout
    assert "Next: repoauditor resume acme" in result.stdout
    pipeline = db.list_pipeline_runs(tmp_config, repo_id="acme")[0]
    assert pipeline.source == "/original/source"
    assert pipeline.commit_hash == "abc"
    assert pipeline.parent_run_id is not None
    assert [item.id for item in db.list_pipeline_run_chain(pipeline.id, tmp_config)] == [
        pipeline.parent_run_id, pipeline.id
    ]
    assert [stage.stage for stage in db.list_stage_runs(pipeline.id, tmp_config)] == [
        "falsify"
    ]


def test_resume_clears_backlog_then_normalizes_and_opens_checkpoint_ndjson(
    tmp_config, monkeypatch
):
    ids = _resume_fixture(tmp_config, monkeypatch)
    calls = []

    class Batch(list):
        deferred_count = 0

    def falsify(repo_id, config):
        calls.append("falsify")
        for finding_id in ids:
            db.update_falsification(
                finding_id, FalsificationStatus.CONFIRMED, "confirmed", config
            )
        return Batch([
            FalsificationOutcome(
                status=FalsificationStatus.CONFIRMED, rationale="confirmed"
            )
            for _ in ids
        ])

    monkeypatch.setattr(cli, "_falsify_stage", falsify)
    monkeypatch.setattr(
        cli, "_normalize_stage",
        lambda repo_id, config: (
            calls.append("normalize"), db.list_findings(repo_id, config)
        )[1],
    )
    monkeypatch.setattr(
        cli, "raise_review_requests",
        lambda repo_id, config, **kwargs: (calls.append("checkpoint"), [])[1],
    )
    monkeypatch.setattr(cli, "open_review_requests", lambda repo_id, config: [])

    result = runner.invoke(cli.app, ["resume", "acme", "--format", "ndjson"])

    assert result.exit_code == 0, result.output
    events = [json.loads(line) for line in result.stdout.splitlines()]
    assert calls == ["falsify", "normalize", "checkpoint"]
    assert [event["stage"] for event in events if event["status"] == "started"] == [
        "preflight", "falsify", "normalize", "review checkpoint"
    ]
    assert events[-1]["stage"] == "resume"
    assert events[-1]["deferred_findings"] == 0
    assert events[-1]["next_command"] == "repoauditor finalize acme"


def test_resume_failure_is_attributed_to_its_fresh_pipeline_run(
    tmp_config, monkeypatch
):
    _resume_fixture(tmp_config, monkeypatch, count=1)
    monkeypatch.setattr(
        cli, "_falsify_stage",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("provider timeout")),
    )

    result = runner.invoke(cli.app, ["resume", "acme"])

    assert result.exit_code == 1
    assert "pipeline failed at falsify: RuntimeError: provider timeout" in result.output
    pipeline = db.list_pipeline_runs(tmp_config, repo_id="acme")[0]
    assert pipeline.status.value == "failed"
    assert pipeline.failed_stage == "falsify"


@pytest.mark.parametrize(
    ("command", "stage_attr", "stage_name"),
    [
        ("map", "_map_stage", "map"),
        ("detect", "_detect_stage", "detect"),
        ("normalize", "_normalize_stage", "normalize"),
    ],
)
def test_standalone_model_stage_has_fresh_durable_budget(
    tmp_config, monkeypatch, command, stage_attr, stage_name
):
    _resume_fixture(tmp_config, monkeypatch, count=0)
    observed = {}

    def invoke(repo_id, config):
        observed["capacity"] = remaining_pipeline_call_capacity(config)
        return []

    monkeypatch.setattr(cli, stage_attr, invoke)
    result = runner.invoke(cli.app, [command, "acme"])

    assert result.exit_code == 0, result.output
    assert observed["capacity"] == tmp_config.llm.max_calls_per_pipeline_run
    pipeline = db.list_pipeline_runs(tmp_config, repo_id="acme")[0]
    assert pipeline.status.value == "completed"
    assert pipeline.parent_run_id is None
    assert [item.stage for item in db.list_stage_runs(pipeline.id, tmp_config)] == [
        stage_name
    ]


def test_standalone_detect_persists_region_plan_and_scanner_coverage(
    tmp_config, monkeypatch
):
    _resume_fixture(tmp_config, monkeypatch, count=0)
    projection = SimpleNamespace(
        source_files=12,
        unbounded_base_calls=36,
        planned_regions=6,
        planned_base_calls=18,
        omitted_regions=6,
    )
    detection = cli.DetectionRun(
        [],
        {
            "semgrep": 0, "gitleaks": 1, "pip-audit": 2,
            "osv-scanner": 0, "llm-ensemble": 3,
        },
        Path("scan.sarif"),
        "empty",
        projection=projection,
        selected_regions=[{
            "file": "storefront/account.py",
            "selection_basis": "architecture-map",
        }],
        completed_region_calls=18,
        scanner_statuses={
            "semgrep": "empty", "gitleaks": "complete",
            "pip-audit": "complete", "osv-scanner": "partial",
        },
        scanner_failures={
            "osv-scanner": "recursive discovery failed; explicit fallback used",
        },
        scanner_executions=[{
            "scanner": "semgrep",
            "status": "empty",
            "applicable": True,
            "output_valid": True,
            "finding_count": 0,
            "target_count": 12,
            "target_count_basis": "scanner-reported-files",
            "version": "1.170.0",
            "configuration": "pinned-test",
            "failure_detail": None,
        }],
        context_expansions=[{
            "primary_file": "storefront/account.py",
            "related": [{
                "basis": "call-name-match",
                "file": "storefront/component_b.py",
                "line_start": 30,
                "symbol": "dispatch",
            }],
        }],
    )
    monkeypatch.setattr(cli, "_detect_stage", lambda repo_id, config: detection)

    result = runner.invoke(cli.app, ["detect", "acme"])

    assert result.exit_code == 0, result.output
    pipeline = db.list_pipeline_runs(tmp_config, repo_id="acme")[0]
    stage = db.list_stage_runs(pipeline.id, tmp_config)[0]
    assert stage.summary["region_plan"]["selected"] == [{
        "file": "storefront/account.py",
        "selection_basis": "architecture-map",
    }]
    assert stage.summary["region_plan"]["planned_regions"] == 6
    assert stage.summary["scanner_statuses"]["osv-scanner"] == "partial"
    assert "explicit fallback" in stage.summary["scanner_failures"]["osv-scanner"]
    assert stage.summary["scanner_executions"][0]["target_count"] == 12
    assert stage.summary["scanner_executions"][0]["output_valid"] is True
    assert stage.summary["context_expansions"][0]["related"][0]["file"] == (
        "storefront/component_b.py"
    )
    detail = runner.invoke(cli.app, ["runs", "show", str(pipeline.id)])
    assert detail.exit_code == 0, detail.output
    assert '"planned_regions": 6' in detail.stdout
    assert "storefront/account.py" in detail.stdout
    assert "storefront/component_b.py" in detail.stdout
    assert '"target_count": 12' in detail.stdout


def test_scanner_canaries_cli_writes_report_and_fails_closed(
    tmp_config, monkeypatch, tmp_path
):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    report_path = tmp_path / "scanner-canaries.json"
    monkeypatch.setattr(
        cli,
        "run_scanner_canaries",
        lambda timeout: SimpleNamespace(passed=True),
    )
    monkeypatch.setattr(
        cli,
        "render_scanner_canaries",
        lambda report: '{"schema_version":1,"passed":true}\n',
    )

    passed = runner.invoke(
        cli.app, ["scanner-canaries", "--output", str(report_path)]
    )

    assert passed.exit_code == 0, passed.output
    assert report_path.read_text() == '{"schema_version":1,"passed":true}\n'

    monkeypatch.setattr(
        cli,
        "run_scanner_canaries",
        lambda timeout: SimpleNamespace(passed=False),
    )
    failed = runner.invoke(cli.app, ["scanner-canaries"])

    assert failed.exit_code == 1


def test_standalone_falsify_is_metered_and_points_to_resume(
    tmp_config, monkeypatch
):
    _resume_fixture(tmp_config, monkeypatch, count=1)
    observed = {}

    class Batch(list):
        deferred_count = 1

    def invoke(repo_id, config):
        observed["capacity"] = remaining_pipeline_call_capacity(config)
        return Batch()

    monkeypatch.setattr(cli, "_falsify_stage", invoke)
    result = runner.invoke(cli.app, ["falsify", "acme"])

    assert result.exit_code == 0, result.output
    assert observed["capacity"] == tmp_config.llm.max_calls_per_pipeline_run
    assert "Next: repoauditor resume acme" in result.stdout
    pipeline = db.list_pipeline_runs(tmp_config, repo_id="acme")[0]
    assert pipeline.parent_run_id is None
    assert db.list_stage_runs(pipeline.id, tmp_config)[0].stage == "falsify"


def test_doctor_model_probe_has_durable_budget_scope(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(cli, "_preflight", lambda config: cli.PreflightResult())
    observed = {}

    def probe(config):
        observed["capacity"] = remaining_pipeline_call_capacity(config)
        return SimpleNamespace(
            ready=True, error=None, provider="anthropic", model="test",
            response_format="json_schema",
        )

    monkeypatch.setattr(cli, "check_model", probe)
    result = runner.invoke(cli.app, ["doctor", "--check-model"])

    assert result.exit_code == 0, result.output
    assert observed["capacity"] == tmp_config.llm.max_calls_per_pipeline_run
    pipeline = db.list_pipeline_runs(tmp_config)[0]
    assert pipeline.source == "diagnostic:model-check"
    assert db.list_stage_runs(pipeline.id, tmp_config)[0].stage == "doctor"


def test_qualification_evaluation_has_durable_budget_scope(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    observed = {}
    fake = SimpleNamespace(
        qualified=True,
        model_dump_json=lambda **kwargs: '{"qualified": true}',
    )

    def evaluate(*args, **kwargs):
        observed["capacity"] = remaining_pipeline_call_capacity(tmp_config)
        return fake

    monkeypatch.setattr(cli, "evaluate_manufactured_sentinels", evaluate)
    monkeypatch.setattr(cli, "render_sentinel_qualification", lambda value: "qualified")
    result = runner.invoke(cli.app, ["qualify-instrument"])

    assert result.exit_code == 0, result.output
    assert observed["capacity"] == tmp_config.llm.max_calls_per_pipeline_run
    pipeline = db.list_pipeline_runs(tmp_config)[0]
    assert pipeline.source == "evaluation:manufactured-sentinels"
    assert db.list_stage_runs(pipeline.id, tmp_config)[0].stage == "qualify-instrument"


def test_run_ndjson_emits_parseable_stage_events(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    _wire_run_stages(monkeypatch, [])

    result = runner.invoke(cli.app, ["run", "/target", "--format", "ndjson"])

    assert result.exit_code == 0, result.output
    events = [json.loads(line) for line in result.stdout.splitlines()]
    assert all({"stage", "status", "timestamp"} <= event.keys() for event in events)
    assert {event["stage"] for event in events} >= {
        "preflight", "ingest", "map", "detect", "triage", "falsify", "normalize", "run",
    }
    assert events[-1]["status"] == "completed"
    assert events[-1]["next_command"] == "repoauditor finalize acme"


def test_repos_list_defaults_latest_and_supports_json_all(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    db.init_db(tmp_config)
    for commit in ("old", "new"):
        db.record_ingested_repo(
            IngestedRepo(repo_id="acme", source="/src/acme", commit_hash=commit), tmp_config
        )

    latest = runner.invoke(cli.app, ["repos", "list"])
    assert latest.exit_code == 0, latest.output
    assert "new" in latest.stdout and "old" not in latest.stdout
    assert "\t" not in latest.stdout

    history = runner.invoke(cli.app, ["repos", "list", "--all", "--format", "json"])
    assert history.exit_code == 0, history.output
    assert {item["commit_hash"] for item in json.loads(history.stdout)} == {"old", "new"}


def test_run_attributes_stage_failure(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(cli, "_preflight", lambda config: cli.PreflightResult())
    monkeypatch.setattr(
        cli, "_ingest_stage", lambda source, config: SimpleNamespace(
            repo_id="acme", commit="abc", snapshot_path=Path("snapshot")
        )
    )
    monkeypatch.setattr(cli, "latest_snapshot", lambda config, repo_id: (Path("snapshot"), "abc"))
    monkeypatch.setattr(
        cli, "_map_stage", lambda repo_id, config: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    result = runner.invoke(cli.app, ["run", "/target"])

    assert result.exit_code == 1
    assert "pipeline failed at map: RuntimeError: boom" in result.output


def test_run_resumes_after_last_completed_stage(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    calls = _wire_run_stages(monkeypatch, [])
    original_map = cli._map_stage
    attempts = 0

    def fail_once(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("interrupted")
        return original_map(*args, **kwargs)

    monkeypatch.setattr(cli, "_map_stage", fail_once)
    first = runner.invoke(cli.app, ["run", "/target"])
    second = runner.invoke(cli.app, ["run", "/target"])

    assert first.exit_code == 1
    assert second.exit_code == 0, second.output
    assert "resuming run #" in second.stdout
    assert calls.count("ingest") == 1
    assert calls.count("map") == 1
    assert db.list_pipeline_runs(tmp_config)[0].status.value == "completed"


def test_individual_stage_failure_is_concise(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    result = runner.invoke(cli.app, ["map", "missing-repo"])

    assert result.exit_code == 1
    assert "map failed: FileNotFoundError: no ingested repository named missing-repo" in result.output
    assert "Traceback" not in result.output


def test_debug_preserves_unexpected_exception(tmp_config, monkeypatch):
    _resume_fixture(tmp_config, monkeypatch, count=0)
    monkeypatch.setattr(
        cli, "_detect_stage", lambda repo_id, config: (_ for _ in ()).throw(RuntimeError("boom"))
    )

    result = runner.invoke(cli.app, ["--debug", "detect", "acme"])

    assert result.exit_code == 1
    assert isinstance(result.exception, RuntimeError)
    assert str(result.exception) == "boom"
    assert "detect failed:" not in result.output


def test_root_help_describes_two_phase_workflow():
    result = runner.invoke(cli.app, ["--help"])

    assert result.exit_code == 0
    assert "two-phase workflow" in result.output
    assert "review" in result.output
    assert "finalize" in result.output

    # Rich may elide option names when rendering help without a real terminal.
    # Assert the generated command surface directly; separate tests exercise each
    # option's behavior through CliRunner.
    root_options = {
        option
        for parameter in get_command(cli.app).params
        for option in parameter.opts
    }
    assert {"--debug", "--quiet", "--verbose"} <= root_options


def test_triage_acquisition_plan_exposes_opt029_controls(tmp_config, monkeypatch):
    captured = {}
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(cli.db, "init_db", lambda config: None)

    def build(config, **options):
        captured.update(options)
        return SimpleNamespace(options=options, entries=(), input_digest="digest")

    monkeypatch.setattr(cli, "build_review_acquisition_plan", build)
    monkeypatch.setattr(
        cli,
        "render_review_acquisition_plan",
        lambda plan: json.dumps({"options": plan.options}, sort_keys=True) + "\n",
    )

    output = tmp_config.paths.data_dir / "acquisition-plan.json"
    result = runner.invoke(cli.app, [
        "triage-acquisition-plan",
        "--limit", "12",
        "--max-per-engagement", "5",
        "--max-per-family", "2",
        "--include-vendor-generated",
        "--pre-post-pair", "repo-pre:repo-post",
        "--output", str(output),
    ])

    assert result.exit_code == 0
    assert captured == {
        "limit": 12,
        "max_per_engagement": 5,
        "max_prior_human_labels_per_rule": 5,
        "max_per_family_per_engagement": 2,
        "include_vendor_generated": True,
        "pre_post_pairs": (("repo-pre", "repo-post"),),
    }
    assert json.loads(output.read_text())["options"]["limit"] == 12


def test_triage_acquisition_plan_rejects_malformed_pre_post_pair(
    tmp_config, monkeypatch,
):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(cli.db, "init_db", lambda config: None)

    result = runner.invoke(cli.app, [
        "triage-acquisition-plan",
        "--pre-post-pair", "missing-separator",
    ])

    assert result.exit_code == 1
    assert "expected PRE:POST" in result.output


def test_run_stops_before_ingest_when_preflight_fails(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(
        cli,
        "_preflight",
        lambda config: cli.PreflightResult(credential_error="ANTHROPIC_API_KEY is not set"),
    )
    monkeypatch.setattr(
        cli, "_ingest_stage", lambda source, config: pytest.fail("ingest should not run")
    )

    result = runner.invoke(cli.app, ["run", "/target"])

    assert result.exit_code == 1
    assert "preflight requirements are not satisfied" in result.output


def test_finalize_refuses_open_review_request(wired, monkeypatch):
    cfg, held = wired
    monkeypatch.setattr(cli, "raise_review_requests", lambda repo_id, config: [])
    request = db.get_review_request(held, cfg)

    result = runner.invoke(cli.app, ["finalize", "r"])

    assert result.exit_code == 1
    assert f"#{request.id} (finding #{held})" in result.output
    assert "repoauditor review list r" in result.output


def test_finalize_refuses_deferred_findings_before_reporting(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    db.init_db(tmp_config)
    deferred_id = db.insert_finding(Finding(
        repo_id="r", title="not examined", file="app.py", line_start=1, line_end=1,
        citation_snippet="candidate", source_lens="owasp", confidence=0.7,
        severity="high", falsification_status=FalsificationStatus.DEFERRED,
    ), tmp_config)
    monkeypatch.setattr(
        cli, "raise_review_requests",
        lambda *args, **kwargs: pytest.fail("review should not run before backlog clears"),
    )

    result = runner.invoke(cli.app, ["finalize", "r"])

    assert result.exit_code == 1
    assert f"#{deferred_id}" in result.output
    assert "have not been falsified yet" in result.output
    assert "repoauditor resume r" in result.output


def test_finalize_runs_quantify_and_both_reports(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(cli, "raise_review_requests", lambda repo_id, config: [])
    monkeypatch.setattr(cli, "open_review_requests", lambda repo_id, config: [])
    calls = []
    quantification = object()
    monkeypatch.setattr(
        cli, "_quantify_stage",
        lambda repo_id, config, **kwargs: (
            calls.append(("quantify", kwargs)), quantification
        )[1],
    )
    monkeypatch.setattr(
        cli, "_report_stage",
        lambda repo_id, config, mode, **kwargs: calls.append(("report", mode, kwargs)),
    )

    result = runner.invoke(cli.app, ["finalize", "r", "--trials", "100", "--seed", "4"])

    assert result.exit_code == 0, result.output
    assert calls == [
        ("quantify", {"trials": 100, "seed": 4, "record_audit": False}),
        ("report", cli.ReportMode.ENGINEERING, {"print_report": False}),
        ("report", cli.ReportMode.MEMO, {
            "quantification": quantification, "print_report": False,
        }),
    ]
    assert "finalize complete for r" in result.stdout


def test_finalize_print_reports_restores_markdown_output(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(cli, "raise_review_requests", lambda repo_id, config: [])
    monkeypatch.setattr(cli, "open_review_requests", lambda repo_id, config: [])
    monkeypatch.setattr(cli, "_quantify_stage", lambda *args, **kwargs: object())
    print_values = []

    def report_stage(repo_id, config, mode, **kwargs):
        print_values.append(kwargs["print_report"])
        return []

    monkeypatch.setattr(cli, "_report_stage", report_stage)
    result = runner.invoke(cli.app, ["finalize", "r", "--print-reports"])

    assert result.exit_code == 0, result.output
    assert print_values == [True, True]


def test_finalize_rerun_versions_scenarios_by_simulation_run(tmp_config, monkeypatch):
    """An audited rerun is append-only history, with no unowned duplicate scenarios."""
    cfg = tmp_config.model_copy(update={
        "priors": load_priors(), "deal_risk": load_deal_risk(),
    })
    db.init_db(cfg)
    db.insert_finding(Finding(
        repo_id="r", title="SQL injection", file="app.py", line_start=24, line_end=24,
        citation_snippet="query + user_input", source_tool="semgrep", confidence=0.9,
        severity="critical", falsification_status=FalsificationStatus.CONFIRMED,
        description="sqli [CWE-89]",
    ), cfg)
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    monkeypatch.setattr(cli, "raise_review_requests", lambda repo_id, config: [])
    monkeypatch.setattr(cli, "open_review_requests", lambda repo_id, config: [])
    monkeypatch.setattr(cli, "_report_stage", lambda *args, **kwargs: [])

    for seed in (4, 5):
        result = runner.invoke(cli.app, [
            "finalize", "r", "--record-audit", "--trials", "100", "--seed", str(seed),
        ])
        assert result.exit_code == 0, result.output

    runs = db.list_simulation_runs("r", cfg)
    scenarios = db.list_risk_scenarios("r", cfg)
    assert len(runs) == len(scenarios) == 2
    assert [scenario.simulation_run_id for scenario in scenarios] == [run.id for run in runs]
    assert len(db.list_scenario_inputs("r", cfg)) == 6  # three inputs per version


def test_stage_summary_includes_timestamps_and_elapsed(triage_cfg, tmp_path):
    sarif = tmp_path / "scan.sarif"
    sarif.write_text(_sarif_one())
    result = runner.invoke(cli.app, ["triage", "acme", "--sarif", str(sarif)])

    assert result.exit_code == 0, result.output
    assert "triage started" in result.stdout
    assert "elapsed " in result.stdout


def test_quiet_run_prints_only_checkpoint_and_recap(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    _wire_run_stages(monkeypatch, [])

    result = runner.invoke(cli.app, ["--quiet", "run", "/target"])

    assert result.exit_code == 0, result.output
    assert "preflight:" not in result.stdout
    assert "run complete for acme" in result.stdout
    assert "run recap:" in result.stdout


def test_verbose_emits_extra_stage_metadata(triage_cfg, tmp_path):
    sarif = tmp_path / "scan.sarif"
    sarif.write_text(_sarif_one())
    result = runner.invoke(
        cli.app, ["--verbose", "triage", "acme", "--sarif", str(sarif)]
    )

    assert result.exit_code == 0, result.output
    assert f"SARIF={sarif}" in result.stdout
    assert "action-threshold=0.5" in result.stdout
