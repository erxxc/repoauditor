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
  (marked `live`), which records one `EvalRun` per fixture when a key is present.
* **Honest, and runs now.** The deterministic **secrets adapter** (gitleaks, installed) is
  scored against a real secrets ground truth and recorded as an `EvalRun`. And the scripted
  detect->falsify->normalize *pipeline logic* is recorded per stage — deterministic, and
  clearly labelled as pipeline-logic, not model capability.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from conftest import FIXTURES_DIR, benchmark_corpus_ids
from repoauditor.detect import run_ensemble
from repoauditor.detect.deterministic import SecretsAdapter
from repoauditor.eval import record_and_check
from repoauditor.falsify import challenge
from repoauditor.ingest import ingest_repo
from repoauditor.map import recover_architecture
from repoauditor.normalize import adjudicate
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, Finding

# The scorer + pipeline driver are the golden harness's; reuse them rather than fork a
# second, drifting copy (tests/ is on the path in prepend import mode — no __init__.py).
from test_golden_harness import (  # noqa: E402
    _confirmed,
    _lens_only,
    _run_pipeline,
    score_precision_recall,
)


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
    assert benchmark_repo.snapshot_path.is_dir()
    assert any(benchmark_repo.snapshot_path.rglob("*")), "empty snapshot"

    exp = benchmark_repo.expected
    assert exp.get("source"), "fixture must document its source (no unsourced fixtures)"
    assert exp.get("findings"), "fixture must declare ground-truth findings"
    for f in exp["findings"]:
        assert f.get("file"), f"finding without a file: {f}"
        assert f.get("citation_contains"), f"finding without a citation anchor: {f}"
        # The cited file must exist in the snapshot (the anchor points at real code).
        assert (benchmark_repo.snapshot_path / f["file"]).is_file(), \
            f"cited file not in snapshot: {f['file']}"


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
def test_scripted_pipeline_records_per_stage_evalruns(tmp_config, fixture_repo, scripted_llm):
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

    db.init_db(tmp_config)
    llm = get_llm_client(tmp_config)
    result = ingest_repo(str(benchmark_repo.snapshot_path), tmp_config,
                         repo_id=benchmark_repo.repo_id)
    recover_architecture(result.snapshot_path, result.repo_id, result.commit, tmp_config, llm)
    run_ensemble(result.repo_id, tmp_config, llm=llm)
    challenge(result.repo_id, tmp_config, llm=llm)
    adjudicate(db.list_findings(result.repo_id, tmp_config), tmp_config, llm)

    confirmed: list[Finding] = [
        f for f in db.list_findings(result.repo_id, tmp_config)
        if f.falsification_status is not FalsificationStatus.KILLED
    ]
    score = score_precision_recall(confirmed, benchmark_repo.expected["findings"])
    run = record_and_check(
        lineage=f"corpus::{benchmark_repo.repo_id}",
        precision=score["precision"], recall=score["recall"], config=tmp_config)

    with capsys.disabled():
        print(f"\n[live corpus] {benchmark_repo.repo_id}: "
              f"precision={score['precision']:.2f} recall={score['recall']:.2f} "
              f"(tp={score['tp']} fp={score['fp']} fn={score['fn']})")
    assert run.id is not None
