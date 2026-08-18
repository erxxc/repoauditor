from __future__ import annotations

from datetime import datetime, timezone

from repoauditor.detect import ensemble
from repoauditor.eval.novelty_wave import (
    _json_safe,
    _load_completed_architecture,
    owasp_only_scope,
)
from repoauditor.store import db
from repoauditor.store.models import Entity, EntityKind, TrustBoundary


def test_owasp_only_scope_restores_ensemble_identity():
    original_lenses = ensemble.LENSES
    original_prompts = ensemble._LENS_PROMPTS
    original_versions = ensemble.LENS_PROMPT_VERSIONS

    with owasp_only_scope():
        assert set(ensemble.LENSES) == {"owasp"}
        assert set(ensemble._LENS_PROMPTS) == {"owasp"}
        assert set(ensemble.LENS_PROMPT_VERSIONS) == {"owasp"}

    assert ensemble.LENSES is original_lenses
    assert ensemble._LENS_PROMPTS is original_prompts
    assert ensemble.LENS_PROMPT_VERSIONS is original_versions


def test_retry_loader_restores_all_planning_entity_classes(tmp_config):
    db.init_db(tmp_config)
    boundary_id = db.upsert_trust_boundary(
        TrustBoundary(repo_id="repo", name="edge"), tmp_config
    )
    for kind, name in (
        (EntityKind.ENTRY_POINT, "route"),
        (EntityKind.DATA_STORE, "database"),
        (EntityKind.INTEGRATION, "queue"),
    ):
        db.upsert_entity(
            Entity(
                repo_id="repo",
                kind=kind,
                name=name,
                location=f"{name}.py:1",
                trust_boundary_id=(
                    boundary_id if kind is EntityKind.ENTRY_POINT else None
                ),
            ),
            tmp_config,
        )

    architecture = _load_completed_architecture("repo", "abc", tmp_config)

    assert [item.name for item in architecture.entry_points] == ["route"]
    assert [item.name for item in architecture.data_stores] == ["database"]
    assert [item.name for item in architecture.integrations] == ["queue"]


def test_stage_summary_serialization_converts_nested_advisory_timestamps():
    observed = datetime(2026, 8, 13, 16, 46, tzinfo=timezone.utc)

    value = _json_safe({
        "scanner_executions": [{"advisory_database_checked_at": observed}],
    })

    assert value == {
        "scanner_executions": [{
            "advisory_database_checked_at": "2026-08-13T16:46:00+00:00",
        }],
    }
