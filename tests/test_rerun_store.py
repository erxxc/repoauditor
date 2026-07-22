from repoauditor.store import db
from repoauditor.store.models import (
    AdjudicationDebate, DebatePosition, Entity, EntityKind, Finding,
    RunStatus, Severity, SourceType, TrustBoundary,
)


def test_map_detect_and_normalize_writes_are_idempotent(tmp_config):
    db.init_db(tmp_config)
    boundary = TrustBoundary(repo_id="repo", name="edge", description="first")
    first_boundary = db.upsert_trust_boundary(boundary, tmp_config)
    second_boundary = db.upsert_trust_boundary(
        boundary.model_copy(update={"description": "refreshed"}), tmp_config
    )
    assert first_boundary == second_boundary

    entity = Entity(repo_id="repo", kind=EntityKind.ENTRY_POINT, name="GET /",
                    location="app.py:1", trust_boundary_id=first_boundary)
    assert db.upsert_entity(entity, tmp_config) == db.upsert_entity(entity, tmp_config)

    finding = Finding(repo_id="repo", title="issue", file="app.py", line_start=1,
                      line_end=1, citation_snippet="danger()", source_tool="semgrep",
                      confidence=.8, severity=Severity.HIGH)
    first_finding = db.upsert_detected_finding(finding, tmp_config)
    db.update_falsification(first_finding, "confirmed", "reachable", tmp_config)
    assert db.upsert_detected_finding(finding, tmp_config) == first_finding
    assert db.get_finding(first_finding, tmp_config).falsification_status == "confirmed"

    debate = AdjudicationDebate(
        repo_id="repo", file="app.py", line_start=1, line_end=1,
        positions=[DebatePosition(source_type=SourceType.TOOL, source_name="semgrep",
                                  severity=Severity.HIGH, reasoning="rule")],
        outcome="consensus", resolved_severity=Severity.HIGH,
        synthesis_rationale="supported",
    )
    assert db.insert_adjudication_debate(debate, tmp_config) == db.insert_adjudication_debate(
        debate.model_copy(update={"synthesis_rationale": "still supported"}), tmp_config
    )


def test_pipeline_and_stage_run_records_capture_failure_and_artifacts(tmp_config):
    db.init_db(tmp_config)
    run = db.start_pipeline_run("/repo", tmp_config)
    db.update_pipeline_run_identity(run.id, "repo", "abc123", tmp_config)
    db.start_stage_run(run.id, "detect", tmp_config)
    db.finish_stage_run(run.id, "detect", RunStatus.FAILED,
                        failure_detail="tool unavailable", config=tmp_config)
    db.finish_pipeline_run(run.id, RunStatus.FAILED, failed_stage="detect",
                           failure_detail="tool unavailable", artifacts=["scan.sarif"],
                           config=tmp_config)

    saved = db.get_pipeline_run(run.id, tmp_config)
    assert saved.repo_id == "repo"
    assert saved.status is RunStatus.FAILED
    assert saved.failed_stage == "detect"
    assert saved.artifacts == ["scan.sarif"]
    stages = db.list_stage_runs(run.id, tmp_config)
    assert [(stage.stage, stage.status) for stage in stages] == [("detect", RunStatus.FAILED)]
