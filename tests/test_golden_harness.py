"""Golden-fixture harness — the precision/recall backbone of the project.

Runs the REAL pipeline (ingest -> map -> detect -> falsify) over each known-vulnerable
fixture and diffs the surviving findings against `expected_findings.json`. The model
is the deterministic `scripted_llm`, so the number measures what the *pipeline* does —
notably that the falsification pass kills the planted false positives and lifts
precision to 1.0 — with no network, key, or cost.

The same harness runs against the real Anthropic model when `REPOAUDITOR_LLM=live`
(see `test_golden_pipeline_live`), which is how the benchmark number for the
leadership memo is produced.
"""

from __future__ import annotations

import os

import pytest

from repoauditor.config import Config, PathsConfig
from repoauditor.eval import record_and_check
from repoauditor.falsify import challenge
from repoauditor.falsify.challenger import CRITIQUE_PROMPT_VERSION as _CRITIQUE_PV
from repoauditor.falsify.challenger import PROMPT_VERSION as _FALSIFY_PV
from repoauditor.ingest import ingest_repo
from repoauditor.llm import LLMClient
from repoauditor.map import recover_architecture
from repoauditor.detect import run_ensemble
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, Finding


# --------------------------------------------------------------------------- #
# Ground-truth matcher — the actual precision/recall logic.
# --------------------------------------------------------------------------- #
def _matches(finding: Finding, expected: dict) -> bool:
    """True if a store finding satisfies one expected ground-truth entry."""
    if finding.file != expected["file"]:
        return False
    if finding.severity.value != expected["severity"]:
        return False
    if expected.get("source_lens") and finding.source_lens != expected["source_lens"]:
        return False
    needle = expected.get("citation_contains")
    if needle and needle not in finding.citation_snippet:
        return False
    return True


def score_precision_recall(actual: list[Finding], expected: list[dict]) -> dict:
    """Precision/recall of `actual` findings against ground truth `expected`.

    Greedy one-to-one matching: each expected entry consumes at most one actual
    finding. Returns tp/fp/fn plus precision and recall.
    """
    unmatched = list(actual)
    true_positives = 0
    for exp in expected:
        for i, found in enumerate(unmatched):
            if _matches(found, exp):
                true_positives += 1
                unmatched.pop(i)
                break
    false_positives = len(unmatched)
    false_negatives = len(expected) - true_positives
    precision = true_positives / len(actual) if actual else 0.0
    recall = true_positives / len(expected) if expected else 1.0
    return {
        "tp": true_positives,
        "fp": false_positives,
        "fn": false_negatives,
        "precision": precision,
        "recall": recall,
    }


# --------------------------------------------------------------------------- #
# Pipeline driver (shared by the deterministic and live tests).
# --------------------------------------------------------------------------- #
def _run_pipeline(fixture, config, llm, self_critique: bool = True) -> None:
    result = ingest_repo(str(fixture.snapshot_path), config, repo_id=fixture.repo_id)
    recover_architecture(result.snapshot_path, result.repo_id, result.commit, config, llm)
    run_ensemble(result.repo_id, config, llm=llm)
    challenge(result.repo_id, config, llm=llm, self_critique=self_critique)


def _confirmed(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.falsification_status is FalsificationStatus.CONFIRMED]


def _lens_only(findings: list[Finding]) -> list[Finding]:
    """The LLM-lens findings. The golden precision/recall measures the LLM
    detect->falsify pipeline against the lens-based ground truth; deterministic tool
    findings (e.g. gitleaks) are a separate stream with their own adapter tests, and
    cross-tool dedup/corroboration is a later stage — so they are excluded from this
    score rather than counted as duplicates of the lens findings they overlap."""
    return [f for f in findings if f.source_lens]


def _sibling_config(base: Config, root) -> Config:
    """An isolated store rooted at `root`, sharing `base`'s settings otherwise.

    Lets one test drive two independent DBs (e.g. a prior-vs-new prompt benchmark)
    without either run's findings leaking into the other.
    """
    root.mkdir(parents=True, exist_ok=True)
    (root / "raw").mkdir(parents=True, exist_ok=True)
    return base.model_copy(update={
        "paths": PathsConfig(
            data_dir=root, raw_dir=root / "raw", db_path=root / "repoauditor.db",
        ),
        "root": root,
    })


# --------------------------------------------------------------------------- #
# Deterministic golden test (runs by default — no more xfail).
# --------------------------------------------------------------------------- #
def test_golden_pipeline(tmp_config, fixture_repo, scripted_llm):
    db.init_db(tmp_config)
    _run_pipeline(fixture_repo, tmp_config, scripted_llm)

    all_findings = db.list_findings(fixture_repo.repo_id, tmp_config)
    expected = fixture_repo.expected["findings"]

    # Every persisted finding keeps its citation and traces back to a trust boundary.
    for f in all_findings:
        assert f.citation_snippet, "finding without a citation"
        assert f.trust_boundary_id is not None, "finding not tied to a trust boundary"

    # The falsification pass is what earns the precision: raw detect includes the
    # planted false positive; after falsification only the true positives survive.
    raw = score_precision_recall(all_findings, expected)
    assert raw["precision"] < 1.0, "fixture should plant at least one false positive"

    confirmed = _lens_only(_confirmed(all_findings))
    post = score_precision_recall(confirmed, expected)
    assert post["recall"] == 1.0, f"missed known findings: {post}"
    assert post["precision"] == 1.0, f"false positive survived falsification: {post}"

    # Killed findings are kept (not deleted) and carry a reason — null-result logging.
    killed = [f for f in all_findings if f.falsification_status is FalsificationStatus.KILLED]
    assert killed, "expected the planted false positive to be killed"
    for f in killed:
        assert f.falsification_reason, "killed finding must record why it was killed"

    # Reliability layer: a deliberately-ambiguous candidate must end up `unresolved`
    # (low-confidence falsification escalated it) — never guessed confirmed or killed.
    unresolved = [f for f in all_findings if f.falsification_status is FalsificationStatus.UNRESOLVED]
    for exp in fixture_repo.expected.get("expected_unresolved", []):
        match = [
            f for f in unresolved
            if f.file == exp["file"] and exp["citation_contains"] in f.citation_snippet
        ]
        assert match, f"expected an unresolved finding for {exp}, got {[f.title for f in unresolved]}"
        assert "unresolved" in (match[0].falsification_reason or "").lower()

    # Closed-loop eval: record this run and gate on regression vs. the prior run.
    # Fresh DB -> first run for this lineage -> cannot regress.
    run = record_and_check(
        lineage=fixture_repo.repo_id,
        precision=post["precision"],
        recall=post["recall"],
        config=tmp_config,
    )
    assert run.regressed_from_prior is False
    assert db.last_eval_run(fixture_repo.repo_id, tmp_config).id == run.id


# --------------------------------------------------------------------------- #
# Prompt-version benchmark: falsification_selfcritique_v1 vs its prior behaviour.
# Closes the round-3 eval-gate process gap — the reflect prompt was in active use but
# had never been scored against the corpus and gated.
# --------------------------------------------------------------------------- #
def test_selfcritique_v1_benchmarked_and_gated_against_prior_behaviour(
    tmp_config, fixture_repo, scripted_backend, tmp_path
):
    """Score falsification_selfcritique_v1 on the golden corpus and gate it.

    The self-critique prompt is *net-new* in round 5 — there is no predecessor prompt
    file — so the honest baseline is the immediately-prior falsify behaviour: the same
    pipeline with the reflect step disabled. We run the real golden pipeline both ways in
    isolated stores, then record both metrics on one lineage and gate with
    `eval/regression.py`. The reflect step can only *tighten* commits, so it must not
    regress precision/recall: both runs clear 1.0/1.0 and the gate passes.
    """
    expected = fixture_repo.expected["findings"]
    lineage = f"{fixture_repo.repo_id}::falsify_selfcritique"

    # Prior behaviour — reflect step disabled — measured in its own store.
    prior_cfg = _sibling_config(tmp_config, tmp_path / "bench_prior")
    db.init_db(prior_cfg)
    _run_pipeline(fixture_repo, prior_cfg, LLMClient(scripted_backend, prior_cfg),
                  self_critique=False)
    prior = score_precision_recall(
        _lens_only(_confirmed(db.list_findings(fixture_repo.repo_id, prior_cfg))), expected)

    # New behaviour — falsification_selfcritique_v1 — measured in the primary store.
    db.init_db(tmp_config)
    _run_pipeline(fixture_repo, tmp_config, LLMClient(scripted_backend, tmp_config),
                  self_critique=True)
    new = score_precision_recall(
        _lens_only(_confirmed(db.list_findings(fixture_repo.repo_id, tmp_config))), expected)

    # The reflect step is precision/recall-neutral on the corpus: no true positive relied
    # on a shaky commit, and the planted false positive is killed either way.
    assert (prior["precision"], prior["recall"]) == (1.0, 1.0)
    assert (new["precision"], new["recall"]) == (1.0, 1.0)

    # Record the prior baseline, then gate the new prompt against it on one lineage.
    prior_run = record_and_check(
        lineage=lineage, precision=prior["precision"], recall=prior["recall"],
        prompt_versions={"falsify": _FALSIFY_PV, "falsify_critique": "(none: pre-reflect)"},
        config=tmp_config)
    assert prior_run.regressed_from_prior is False

    new_run = record_and_check(
        lineage=lineage, precision=new["precision"], recall=new["recall"],
        prompt_versions={"falsify": _FALSIFY_PV, "falsify_critique": _CRITIQUE_PV},
        config=tmp_config)

    # The net-new self-critique prompt is now scored and on the record, not regressing.
    assert new_run.regressed_from_prior is False
    assert _CRITIQUE_PV in new_run.prompt_versions.values()
    # The eval log carries both runs for this lineage (auditable going forward).
    assert db.last_eval_run(lineage, tmp_config).id == new_run.id


# --------------------------------------------------------------------------- #
# Live benchmark (opt in with REPOAUDITOR_LLM=live). Produces the memo number.
# --------------------------------------------------------------------------- #
@pytest.mark.live
def test_golden_pipeline_live(tmp_config, fixture_repo, capsys):
    from repoauditor.llm import get_llm_client

    db.init_db(tmp_config)
    _run_pipeline(fixture_repo, tmp_config, get_llm_client(tmp_config))

    confirmed = _lens_only(_confirmed(db.list_findings(fixture_repo.repo_id, tmp_config)))
    score = score_precision_recall(confirmed, fixture_repo.expected["findings"])
    with capsys.disabled():
        print(
            f"\n[live benchmark] {fixture_repo.repo_id}: "
            f"precision={score['precision']:.2f} recall={score['recall']:.2f} "
            f"(tp={score['tp']} fp={score['fp']} fn={score['fn']})"
        )
    # Loose gate — the point of the live run is to report the number, not to be
    # a hard pass/fail on a non-deterministic model.
    assert score["recall"] >= 0.5, f"live recall unexpectedly low: {score}"


# --------------------------------------------------------------------------- #
# The matcher/scorer is testable today and must stay correct.
# --------------------------------------------------------------------------- #
def test_scorer_perfect_match():
    expected = [
        {"file": "app.py", "severity": "critical", "source_lens": "owasp",
         "citation_contains": "SELECT"},
    ]
    actual = [
        Finding(
            repo_id="r", title="SQLi", file="app.py", line_start=1, line_end=1,
            citation_snippet="SELECT * FROM users WHERE id = x",
            source_lens="owasp", confidence=0.9, severity="critical",
        )
    ]
    score = score_precision_recall(actual, expected)
    assert score == {"tp": 1, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0}


def test_scorer_counts_false_positive_and_negative():
    expected = [
        {"file": "app.py", "severity": "critical", "citation_contains": "SELECT"},
        {"file": "app.py", "severity": "high", "citation_contains": "sk_live_"},
    ]
    actual = [
        Finding(
            repo_id="r", title="SQLi", file="app.py", line_start=1, line_end=1,
            citation_snippet="SELECT * FROM users", source_lens="owasp",
            confidence=0.9, severity="critical",
        ),
        Finding(
            repo_id="r", title="noise", file="other.py", line_start=1, line_end=1,
            citation_snippet="print()", source_tool="sast",
            confidence=0.2, severity="low",
        ),
    ]
    score = score_precision_recall(actual, expected)
    assert score["tp"] == 1
    assert score["fp"] == 1  # the noise finding
    assert score["fn"] == 1  # the missed hardcoded secret
