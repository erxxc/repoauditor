"""Benchmark-corpus harness — real, documented fixtures beyond the 2 scripted golden repos.

The corpus (see `tests/fixtures/README.md`): a 25-case subset of the **OWASP Benchmark for
Python** plus **CVE-tagged repos** (gunicorn CVE-2024-1135; a vulnerable-dependency manifest
for CVE-2020-14343 / CVE-2018-1000656). These are detected by the live LLM lens and/or the
deterministic SAST/SCA tools.

The honest-baseline story this module encodes:

* **Deferred (turnkey).** The LLM detect/falsify/normalize numbers need the live model
  (`REPOAUDITOR_LLM=live`); the SAST/SCA numbers need semgrep/pip-audit/osv. None are present
  in a bare CI env, and *scripting* answers for 25+ cases would make precision/recall circular.
  So the corpus's model-capability baseline is produced by `test_corpus_live_baseline`
  (marked `live`), which records one `EvalRun` per fixture when a key is present. The paid
  path also enters a durable pipeline usage scope, fails before scoring deferred work, and
  publishes authoritative usage totals with its result.
* **Honest, and runs now.** The deterministic **secrets adapter** (gitleaks, installed) is
  scored against a real secrets ground truth and recorded as an `EvalRun`. And the scripted
  detect->falsify->normalize *pipeline logic* is recorded per stage — deterministic, and
  clearly labelled as pipeline-logic, not model capability.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import FIXTURES_DIR, _load_fixture, benchmark_corpus_ids
from repoauditor.detect import run_ensemble
from repoauditor.detect.deterministic import SecretsAdapter
from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.eval import record_and_check
from repoauditor.falsify import challenge
from repoauditor.ingest import ingest_repo
from repoauditor.llm import model_usage_scope
from repoauditor.map import recover_architecture
from repoauditor.normalize import adjudicate
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, RunStatus

# The scorer + pipeline driver are the golden harness's; reuse them rather than fork a
# second, drifting copy (tests/ is on the path in prepend import mode — no __init__.py).
from test_golden_harness import (  # noqa: E402
    _confirmed,
    _lens_only,
    _run_pipeline,
    score_precision_recall,
)
from uat_scoring import score_live_uat
from fixtures.audit_corpus_readiness import build_corpus_readiness


def _append_live_uat_result(
    path: Path, benchmark_repo, score: dict, run, config,
    *, pipeline_run_id: int | None = None, model_usage: dict | None = None,
) -> None:
    """Append one paid-run result when the explicit UAT artifact path is configured."""
    if path.is_file():
        document = json.loads(path.read_text())
    else:
        document = {
            "schema_version": 2,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "live-model",
            "methodology": (
                "Mixed benchmark corpus with human-reviewed ground truth. Each result "
                "retains its corpus kind: purpose-built fixture results are not evidence "
                "of independent real-world performance, while independent-project labels "
                "cover one documented historical CVE and are not exhaustive."
            ),
            "scanner_coverage": os.environ.get(
                "REPOAUDITOR_UAT_SCANNER_COVERAGE", "environment-dependent"
            ),
            "results": [],
        }
    document["results"].append({
        "repo_id": benchmark_repo.repo_id,
        "kind": benchmark_repo.expected["source"]["kind"],
        "provider": config.llm.provider,
        "model": config.model.name,
        "prompt_versions": run.prompt_versions,
        "pipeline_run_id": pipeline_run_id,
        "model_usage": model_usage,
        "evaluation": score,
    })
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n")


# --------------------------------------------------------------------------- #
# 1. The corpus is real and well-formed (sourcing + citation discipline).
# --------------------------------------------------------------------------- #
def test_benchmark_corpus_is_present():
    """The documented corpus actually exists (OWASP subset + the CVE fixtures)."""
    ids = benchmark_corpus_ids()
    assert "owasp_benchmark_py" in ids
    assert any(i.startswith("cve_") for i in ids), ids


def test_corpus_fixture_is_well_formed(benchmark_repo):
    """Every corpus fixture: snapshot present, sourced, and no finding without a citation.

    The last is the CLAUDE.md 'no finding without a citation' rule applied to ground truth —
    an expected finding that can't be matched by a citation substring is not defensible.
    """
    exp = benchmark_repo.expected
    assert exp.get("source"), "fixture must document its source (no unsourced fixtures)"
    source = exp["source"]
    assert source.get("kind") in {"benchmark", "fixture", "independent"}
    assert (benchmark_repo.snapshot_path.parent / "README.md").is_file()
    materialized = benchmark_repo.snapshot_path.is_dir()
    if materialized:
        assert any(benchmark_repo.snapshot_path.rglob("*")), "empty snapshot"
    else:
        assert source.get("materialization") == "pinned-acquisition-only"
        assert source.get("pinned_commit"), "acquisition-only entry needs an exact commit"
    findings = exp.get("findings")
    assert isinstance(findings, list), "fixture must declare a ground-truth findings list"
    if source["kind"] == "independent":
        assert source.get("pinned_commit")
        assert source.get("license")
        assert source.get("ground_truth")
        assert source.get("variant") in {"pre_fix", "post_fix"}
        if source["variant"] == "pre_fix":
            assert findings, "vulnerable snapshot needs a known-positive finding"
        else:
            assert not findings, "patched snapshot must not retain the fixed finding"
            assert exp.get("expected_absent"), "patched snapshot needs an explicit negative control"
    for f in [*findings, *exp.get("expected_absent", [])]:
        assert f.get("file"), f"finding without a file: {f}"
        assert f.get("citation_contains"), f"finding without a citation anchor: {f}"
        # The cited file must exist in the snapshot (the anchor points at real code).
        if materialized:
            assert (benchmark_repo.snapshot_path / f["file"]).is_file(), \
                f"cited file not in snapshot: {f['file']}"
    if materialized:
        for f in findings:
            cited_text = (benchmark_repo.snapshot_path / f["file"]).read_text(errors="ignore")
            assert f["citation_contains"] in cited_text, \
                f"citation anchor not present in vulnerable snapshot: {f['file']}"


def test_independent_corpus_has_eight_real_projects_with_pre_post_pairs():
    records = []
    for repo_id in benchmark_corpus_ids():
        fixture = _load_fixture(repo_id)
        if fixture.expected["source"]["kind"] == "independent":
            records.append(fixture.expected["source"])
    projects = {record["project_id"] for record in records}
    assert len(projects) == 8
    assert {record["language"] for record in records} == {
        "Python", "JavaScript", "Java", "Ruby",
    }
    for project in projects:
        variants = {record["variant"] for record in records if record["project_id"] == project}
        assert variants == {"pre_fix", "post_fix"}


def test_corpus_kinds_keep_fixtures_and_benchmarks_out_of_independent_gate():
    kinds = {
        repo_id: _load_fixture(repo_id).expected["source"]["kind"]
        for repo_id in benchmark_corpus_ids()
    }
    assert kinds["owasp_benchmark_py"] == "benchmark"
    assert kinds["uat_lightweight_app"] == "fixture"
    assert kinds["cve_gunicorn_smuggling"] == "fixture"
    assert kinds["cve_vulnerable_deps"] == "fixture"
    assert kinds["anchor_owasp_juice_shop"] == "benchmark"
    assert kinds["anchor_owasp_webgoat"] == "benchmark"
    assert kinds["anchor_owasp_railsgoat"] == "benchmark"


def test_all_new_public_entries_are_pinned_acquisition_only():
    entries = [
        _load_fixture(repo_id) for repo_id in benchmark_corpus_ids()
        if repo_id.startswith("independent_") or repo_id.startswith("anchor_owasp_")
    ]
    assert len(entries) == 19  # eight pre/post pairs plus three OWASP anchors
    assert all(
        fixture.expected["source"].get("materialization") == "pinned-acquisition-only"
        for fixture in entries
    )
    assert all(fixture.expected["source"].get("pinned_commit") for fixture in entries)


def test_protected_holdout_is_one_complete_independent_pre_post_pair():
    protected = [
        _load_fixture(repo_id).expected["source"]
        for repo_id in benchmark_corpus_ids()
        if _load_fixture(repo_id).expected["source"].get("evaluation_role")
        == "protected_holdout"
    ]

    assert len(protected) == 2
    assert {source["project_id"] for source in protected} == {"serialize_javascript"}
    assert {source["variant"] for source in protected} == {"pre_fix", "post_fix"}
    assert all(source["kind"] == "independent" for source in protected)
    assert all(source["pinned_commit"] for source in protected)
    assert all(source["license"] for source in protected)
    assert all("never inferred" in source["ground_truth"].lower() for source in protected)


def test_offline_corpus_readiness_is_metadata_complete_and_network_free():
    report = build_corpus_readiness(FIXTURES_DIR)

    assert report["metadata_ready"] is True
    assert report["network_accessed"] is False
    assert report["summary"]["independent_project_count"] == 8
    assert report["summary"]["protected_holdout_count"] == 2
    assert report["summary"]["calibration_fixture_count"] == 1
    # Acquisition-only source is deliberately not vendored. This field, rather than an
    # implicit skip, tells the operator whether cache restoration is still required.
    assert report["online_execution_ready"] is (
        report["summary"]["protected_holdout_materialized_count"] == 2
    )


@pytest.mark.integration
def test_materialized_juice_shop_retrieval_index_builds():
    """Cache-backed native-parser smoke test; never calls scanners or a model."""
    fixture = _load_fixture("anchor_owasp_juice_shop")
    if not fixture.snapshot_path.is_dir():
        pytest.skip("Juice Shop pinned snapshot is not materialized")

    index = RetrievalIndex().build(fixture.snapshot_path)

    assert index.snapshot_path == fixture.snapshot_path.resolve()


def test_live_uat_artifact_is_explicitly_fixture_derived(tmp_config, tmp_path, monkeypatch):
    artifact = tmp_path / "live-uat.json"
    fixture = _load_fixture("uat_lightweight_app")
    monkeypatch.setenv("REPOAUDITOR_UAT_SCANNER_COVERAGE", "not-installed-live-model-only")

    _append_live_uat_result(
        artifact,
        fixture,
        {
            "methodology": "confirmed countable fixture scoring",
            "final_countable_confirmed": {
                "precision": 0.75, "recall": 0.5, "tp": 3, "fp": 1, "fn": 3,
            },
        },
        SimpleNamespace(prompt_versions={"detect": "owasp_v1"}),
        tmp_config,
        pipeline_run_id=17,
        model_usage={"calls": 4, "input_tokens": 100, "output_tokens": 20},
    )

    document = json.loads(artifact.read_text())
    assert "not evidence of independent real-world performance" in document["methodology"]
    assert "not exhaustive" in document["methodology"]
    assert document["scanner_coverage"] == "not-installed-live-model-only"
    assert document["results"][0]["kind"] == "fixture"
    assert document["results"][0]["pipeline_run_id"] == 17
    assert document["results"][0]["model_usage"]["calls"] == 4
    final = document["results"][0]["evaluation"]["final_countable_confirmed"]
    assert final["precision"] == 0.75


# --------------------------------------------------------------------------- #
# 2. Deterministic secrets adapter (gitleaks) — a REAL precision/recall baseline.
# --------------------------------------------------------------------------- #
# Ground truth: which snapshot file carries a planted, real credential. gitleaks is the
# only deterministic detector installed here, so this is the one non-scripted, non-live
# detection number the corpus can produce today.
_SECRETS_GROUND_TRUTH = {
    "example_vuln_repo": {"app.py"},        # a strong-pattern Stripe `sk_live_` token
    "command_injection_svc": {"service.py"},  # a plain-text DB password ("hunter2-...")
}


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
@pytest.mark.integration
def test_secrets_adapter_precision_recall_baseline(tmp_config, capsys):
    """Score the real gitleaks adapter against the secrets ground truth; record an EvalRun.

    This is an honest, real-tool number — no model, no scripting. It deliberately exposes
    gitleaks' real limitation: it catches the high-entropy Stripe token but misses the
    plain-text password, so recall is well below 1.0. That the number is *not* a rigged
    1.0/1.0 is the point of a defensible benchmark.
    """
    db.init_db(tmp_config)
    adapter = SecretsAdapter()

    tp = fp = expected_total = 0
    for repo, secret_files in _SECRETS_GROUND_TRUTH.items():
        cands = adapter.run(FIXTURES_DIR / repo / "snapshot")
        flagged = {Path(c.file).name for c in cands}
        expected_total += len(secret_files)
        tp += len(flagged & secret_files)
        fp += len(flagged - secret_files)  # a flagged non-secret file would be a false positive

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / expected_total if expected_total else 1.0

    run = record_and_check(
        lineage="secrets_adapter",
        precision=precision, recall=recall,
        prompt_versions={"secrets_tool": "gitleaks"},  # deterministic tool, not a prompt
        config=tmp_config,
    )
    with capsys.disabled():
        print(f"\n[secrets adapter / gitleaks] precision={precision:.2f} recall={recall:.2f} "
              f"(tp={tp} fp={fp} of {expected_total} planted)")

    assert run.regressed_from_prior is False
    # Robust invariants (not brittle to a gitleaks version bump): everything it flagged is a
    # real secret, and it catches at least the strong-pattern token.
    assert precision >= 0.99, f"gitleaks flagged a non-secret file: precision={precision}"
    assert recall >= 0.5, f"gitleaks missed the strong-pattern secret too: recall={recall}"


# --------------------------------------------------------------------------- #
# 3. Scripted detect->falsify->normalize: per-stage PIPELINE-LOGIC EvalRuns.
# --------------------------------------------------------------------------- #
def test_scripted_pipeline_records_per_stage_evalruns(
    tmp_config, fixture_repo, scripted_llm, stub_deterministic_tools
):
    """Extend the scripted golden pipeline through normalize and record a per-stage EvalRun.

    First time `severity_adjudication_v3` runs inside the golden harness end to end (it was
    previously scored only on the 2-fixture correctness sweep). The numbers here are
    deterministic PIPELINE-LOGIC precision/recall — NOT model capability (that needs the
    live run). Recording detect/falsify/normalize per stage puts any future regression in
    that logic on the record. normalize must not drop a true positive: a confirmed,
    single-source (or agreeing) finding passes through v3 unchanged.
    """
    db.init_db(tmp_config)
    _run_pipeline(fixture_repo, tmp_config, scripted_llm)  # ingest->map->detect->falsify
    expected = fixture_repo.expected["findings"]

    def score():
        return score_precision_recall(
            _lens_only(_confirmed(db.list_findings(fixture_repo.repo_id, tmp_config))), expected)

    # detect (raw): the planted false positive is still present -> precision < 1.
    raw = score_precision_recall(
        _lens_only(db.list_findings(fixture_repo.repo_id, tmp_config)), expected)
    post_falsify = score()

    # normalize: adjudicate (v3) over the full finding set, then re-score the survivors.
    adjudicate(db.list_findings(fixture_repo.repo_id, tmp_config), tmp_config, scripted_llm)
    post_normalize = score()

    assert raw["precision"] < 1.0, "detect should still carry the planted false positive"
    assert (post_falsify["precision"], post_falsify["recall"]) == (1.0, 1.0)
    # v3 does not regress falsify's result — no true positive is dropped or de-confirmed.
    assert (post_normalize["precision"], post_normalize["recall"]) == (1.0, 1.0)

    for stage, sc in (("detect", raw), ("falsify", post_falsify), ("normalize", post_normalize)):
        run = record_and_check(
            lineage=f"{fixture_repo.repo_id}::{stage}",
            precision=sc["precision"], recall=sc["recall"], config=tmp_config)
        assert run.regressed_from_prior is False


# --------------------------------------------------------------------------- #
# 4. Live end-to-end corpus baseline (DEFERRED) — the honest model-capability number.
# --------------------------------------------------------------------------- #
@pytest.mark.live
def test_corpus_live_baseline(tmp_config, benchmark_repo, capsys):
    """Run the real pipeline (map->detect->falsify->normalize) over each corpus fixture.

    This is the turnkey deferred baseline: it produces the honest, model-driven
    precision/recall for the OWASP subset and the CVE repos, recorded as one `EvalRun` per
    fixture. Runs only under `REPOAUDITOR_LLM=live` (and gains SAST/SCA coverage when
    semgrep/pip-audit/osv are installed). The loose gate reports the number rather than
    hard-failing a non-deterministic model.
    """
    from repoauditor.llm import get_llm_client

    if not benchmark_repo.snapshot_path.is_dir():
        pytest.skip(
            "pinned acquisition-only corpus entry is not materialized; run "
            "tests/fixtures/materialize_public_corpus.py first"
        )

    db.init_db(tmp_config)
    pipeline = db.start_pipeline_run(str(benchmark_repo.snapshot_path), tmp_config)
    assert pipeline.id is not None
    try:
        llm = get_llm_client(tmp_config)
        result = ingest_repo(str(benchmark_repo.snapshot_path), tmp_config,
                             repo_id=benchmark_repo.repo_id)
        db.update_pipeline_run_identity(
            pipeline.id, result.repo_id, result.commit, tmp_config
        )
        with model_usage_scope(pipeline.id):
            recover_architecture(
                result.snapshot_path, result.repo_id, result.commit, tmp_config, llm
            )
            run_ensemble(result.repo_id, tmp_config, llm=llm)
            challenge(result.repo_id, tmp_config, llm=llm)
            deferred = [
                finding for finding in db.list_findings(result.repo_id, tmp_config)
                if finding.falsification_status is FalsificationStatus.DEFERRED
            ]
            if deferred:
                raise RuntimeError(
                    f"live corpus run stopped with {len(deferred)} deferred findings; "
                    "do not normalize or score an incomplete run"
                )
            adjudicate(db.list_findings(result.repo_id, tmp_config), tmp_config, llm)

        findings = db.list_findings(result.repo_id, tmp_config)
        if benchmark_repo.expected.get("planted_cases"):
            scanner_coverage = os.environ.get(
                "REPOAUDITOR_UAT_SCANNER_COVERAGE", "environment-dependent"
            )
            available_source_types = (
                {"lens"}
                if scanner_coverage == "not-installed-live-model-only"
                else {"lens", "tool"}
            )
            score = score_live_uat(
                findings,
                benchmark_repo.expected,
                available_source_types=available_source_types,
            )
            final = score["final_countable_confirmed"]
            lineage = f"corpus-v2::{benchmark_repo.repo_id}"
        else:
            # Non-UAT corpus fixtures retain their existing legacy scorer. They do not carry
            # the planted-case source/disposition metadata needed for the v2 UAT method.
            legacy_survivors = [
                finding for finding in findings
                if finding.falsification_status is not FalsificationStatus.KILLED
            ]
            final = score_precision_recall(
                legacy_survivors, benchmark_repo.expected["findings"]
            )
            score = {"methodology": "legacy corpus scorer", "final_countable_confirmed": final}
            lineage = f"corpus::{benchmark_repo.repo_id}"
        run = record_and_check(
            lineage=lineage,
            precision=final["precision"], recall=final["recall"], config=tmp_config)
    except BaseException as exc:
        db.finish_pipeline_run(
            pipeline.id, RunStatus.FAILED,
            failure_detail=f"{type(exc).__name__}: {exc}"[:4000],
            config=tmp_config,
        )
        raise
    else:
        db.finish_pipeline_run(pipeline.id, RunStatus.COMPLETED, config=tmp_config)

    artifact_path = os.environ.get("REPOAUDITOR_UAT_RESULTS")
    if artifact_path:
        _append_live_uat_result(
            Path(artifact_path), benchmark_repo, score, run, tmp_config,
            pipeline_run_id=pipeline.id,
            model_usage=db.summarize_model_usage(pipeline.id, tmp_config),
        )

    with capsys.disabled():
        print(f"\n[live corpus] {benchmark_repo.repo_id}: "
              f"precision={final['precision']:.2f} recall={final['recall']:.2f} "
              f"(tp={final['tp']} fp={final['fp']} fn={final['fn']})")
    assert run.id is not None
