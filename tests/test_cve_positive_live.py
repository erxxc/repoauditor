"""Bounded live evaluation for the frozen CVE-positive acquisition pairs.

This is evaluation infrastructure, not training or pipeline logic. A pair must be selected
explicitly, its pre-fix snapshot always runs before its post-fix control, and the existing
pipeline call/token/batch limits remain authoritative. Detector output never becomes a
label, and scoring covers only the advisory-derived target declared before execution.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from repoauditor import cli
from repoauditor.store import db
from test_benchmark_corpus import (
    _append_live_uat_result,
    _live_prompt_versions,
    _pipeline_evidence,
    _run_live_pipeline,
)
from uat_scoring import score_independent_target


FIXTURES = Path(__file__).parent / "fixtures"
MANIFEST = FIXTURES / "cve_positive_acquisition_cohort.json"


def _project(slug: str) -> dict:
    manifest = json.loads(MANIFEST.read_text())
    matches = [item for item in manifest["projects"] if item["slug"] == slug]
    if len(matches) != 1:
        available = ", ".join(item["slug"] for item in manifest["projects"])
        raise ValueError(f"unknown CVE-positive pair {slug!r}; available: {available}")
    return matches[0]


def _pair(slug: str, root: Path) -> list[SimpleNamespace]:
    project = _project(slug)
    result = []
    for short_variant, source_variant, commit in (
        ("pre", "pre_fix", project["vulnerable_commit"]),
        ("post", "post_fix", project["fixed_commit"]),
    ):
        repo_id = f"acquisition_cve_{slug}_{short_variant}"
        target = {
            **project["target"],
            "cve": "/".join(project["cve_ids"]),
        }
        result.append(SimpleNamespace(
            repo_id=repo_id,
            snapshot_path=root / repo_id / "snapshot",
            expected={
                "source": {
                    "kind": "independent",
                    "evaluation_role": "cve_positive_acquisition",
                    "project_id": slug,
                    "project": project["project"],
                    "variant": source_variant,
                    "pinned_commit": commit,
                    "pre_fix_commit": project["vulnerable_commit"],
                    "post_fix_commit": project["fixed_commit"],
                    "license": project["license"],
                    "cve": "/".join(project["cve_ids"]),
                    "ground_truth": (
                        "Human-reviewed advisory and isolated security patch; never "
                        "inferred from repoauditor output."
                    ),
                },
                "findings": [target] if source_variant == "pre_fix" else [],
                "expected_absent": [target] if source_variant == "post_fix" else [],
            },
        ))
    return result


def test_cve_positive_pair_builder_preserves_pre_post_order_and_target():
    pair = _pair("pyjwt_cve_2022_29217", Path("/nonexistent"))

    assert [item.expected["source"]["variant"] for item in pair] == [
        "pre_fix", "post_fix",
    ]
    assert pair[0].expected["findings"][0]["file"] == "jwt/algorithms.py"
    assert pair[1].expected["expected_absent"][0]["cve"] == "CVE-2022-29217"
    assert all(
        item.expected["source"]["evaluation_role"] == "cve_positive_acquisition"
        for item in pair
    )


@pytest.mark.live
def test_cve_positive_live_pair(tmp_config, monkeypatch):
    """Evaluate one explicitly selected pre/post pair and retain terminal evidence."""
    slug = os.environ.get("REPOAUDITOR_CVE_POSITIVE_PAIR", "").strip()
    if not slug:
        pytest.skip("REPOAUDITOR_CVE_POSITIVE_PAIR is required for paid pair evaluation")
    root = Path(os.environ.get(
        "REPOAUDITOR_CVE_POSITIVE_ROOT", str(FIXTURES)
    )).resolve()
    pair = _pair(slug, root)
    missing = [str(item.snapshot_path) for item in pair if not item.snapshot_path.is_dir()]
    if missing:
        raise RuntimeError(
            "CVE-positive pair is not materialized: " + ", ".join(missing)
        )

    data_dir = Path(os.environ.get(
        "REPOAUDITOR_UAT_DATA_DIR", "live-cve-positive-data"
    )).resolve()
    tmp_config = tmp_config.model_copy(update={
        "paths": tmp_config.paths.model_copy(update={
            "data_dir": data_dir,
            "raw_dir": data_dir / "raw",
            "db_path": data_dir / "repoauditor.db",
        })
    })
    db.init_db(tmp_config)
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    artifact = Path(os.environ.get(
        "REPOAUDITOR_UAT_RESULTS", "live-cve-positive-results.json"
    ))
    max_batches = int(os.environ.get("REPOAUDITOR_UAT_MAX_BATCHES", "2"))
    if not 1 <= max_batches <= 6:
        raise ValueError("REPOAUDITOR_UAT_MAX_BATCHES must be between 1 and 6")

    for fixture in pair:
        repo_id: str | None = None
        try:
            repo_id = _run_live_pipeline(
                fixture, tmp_config, max_batches=max_batches
            )
            score = score_independent_target(
                db.list_findings(repo_id, tmp_config), fixture.expected
            )
        except BaseException as exc:
            if repo_id is None:
                matches = [
                    item for item in db.list_ingested_repos(tmp_config)
                    if Path(item.source).resolve() == fixture.snapshot_path.resolve()
                ]
                repo_id = matches[-1].repo_id if matches else fixture.repo_id
            _append_live_uat_result(
                artifact,
                fixture,
                tmp_config,
                status="failed",
                pipeline=_pipeline_evidence(tmp_config, repo_id),
                failure_detail=f"{type(exc).__name__}: {exc}"[:4000],
            )
            raise
        _append_live_uat_result(
            artifact,
            fixture,
            tmp_config,
            status="completed",
            score=score,
            run=SimpleNamespace(prompt_versions=_live_prompt_versions()),
            pipeline=_pipeline_evidence(tmp_config, repo_id),
        )
