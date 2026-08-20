"""Shared pytest fixtures + the scripted-LLM canned data for the golden harness.

`scripted_llm` returns a deterministic `LLMClient` (scripted backend) whose handler routes on the
structured `context` each stage passes (repo_id / stage / lens / citation). The canned
responses in `FIXTURE_LLM` deliberately include planted false positives so the harness
measures what the *pipeline* does — specifically, that the falsification pass kills the
false positives and lifts precision to 1.0. No network, key, or cost; fully reproducible.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest


# These historical/evaluation tests intentionally bind retained evidence under
# the git-ignored data tree.  Keep the allowlist explicit so clean checkouts do
# not silently broaden what the required fast lane omits.
_LOCAL_EVIDENCE_TEST_FILES = frozenset(
    {
        "test_opt_002_bounded_review_result.py",
        "test_opt_003_final_label_followup_result.py",
        "test_opt_003_temporal_report_result.py",
        "test_opt_003_wave_2_review_result.py",
        "test_opt_009_citation_diagnosis.py",
        "test_opt_009_citation_diagnosis_receipt.py",
        "test_opt_009_citation_diagnosis_result.py",
        "test_opt_009_closure_merge_attempt.py",
        "test_opt_009_closure_merge_corrected_retry_receipt.py",
        "test_opt_009_closure_merge_receipt.py",
        "test_opt_009_closure_result.py",
        "test_opt_009_corrected_retry_receipt.py",
        "test_opt_009_detection_wave_1_result.py",
        "test_opt_009_eligibility_audit.py",
        "test_opt_009_instrument_qualification_receipt.py",
        "test_opt_009_instrument_qualification_result.py",
        "test_opt_009_novelty_instrument.py",
        "test_opt_009_serialization_retry_receipt.py",
        "test_opt_009_serialization_retry_result.py",
        "test_opt_010_acquisition_instrument_qualification_wave_1.py",
        "test_opt_010_architecture_mechanism_eligibility_final_retry_receipt.py",
        "test_opt_010_bounded_negative_feasibility_closure.py",
        "test_opt_010_bounded_negative_feasibility_closure_receipt.py",
        "test_opt_010_java_ruby_scanner_cell_coverage_corrected_acceptance_receipt.py",
        "test_opt_010_java_ruby_scanner_cell_coverage_corrected_acceptance_retry_receipt.py",
        "test_opt_010_java_ruby_scanner_cell_coverage_receipt.py",
        "test_opt_010_java_ruby_source_augmentation_acquisition.py",
        "test_opt_010_java_ruby_source_augmentation_acquisition_screen_corrected_retry_receipt.py",
        "test_opt_010_java_ruby_source_augmentation_acquisition_screen_final_retry_receipt.py",
        "test_opt_010_java_ruby_source_augmentation_acquisition_screen_receipt.py",
        "test_opt_010_java_ruby_source_augmentation_selection_receipt.py",
        "test_opt_010_java_ssrf_retained_source_screen.py",
        "test_opt_010_java_ssrf_retained_source_screen_receipt.py",
        "test_opt_010_java_ssrf_supplemental_qualification.py",
        "test_opt_010_java_ssrf_supplemental_rule_qualification_receipt.py",
        "test_opt_010_offline_containment_foundation_receipt.py",
        "test_opt_010_offline_readiness_audit_receipt.py",
        "test_opt_010_outcome_blind_packet_paired_run.py",
        "test_opt_010_prospective_source_selection.py",
        "test_opt_010_prospective_source_selection_corrected_retry.py",
        "test_opt_010_prospective_source_selection_receipt.py",
        "test_opt_010_protected_cohort_design_receipt.py",
        "test_opt_010_readiness_audit.py",
        "test_opt_010_scanner_cell_coverage.py",
        "test_opt_010_scanner_cell_coverage_acceptance.py",
        "test_opt_010_supported_primary_augmentation_acceptance.py",
        "test_opt_010_supported_primary_augmentation_corrected_acceptance_receipt.py",
        "test_opt_010_supported_primary_augmentation_receipt.py",
        "test_opt_014_acquisition_design.py",
        "test_opt_014_descriptive_scope_closure.py",
        "test_opt_014_descriptive_scope_closure_receipt.py",
        "test_opt_014_eligibility_audit.py",
        "test_opt_014_eligibility_audit_receipt.py",
        "test_opt_014_prior_predictive.py",
        "test_opt_014_prior_predictive_receipt.py",
    }
)
_LOCAL_EVIDENCE_ROOT = Path(__file__).resolve().parents[1] / "data"


def pytest_collection_modifyitems(config, items):
    """Apply live and retained-local-evidence collection boundaries."""
    live_enabled = os.environ.get("REPOAUDITOR_LLM") == "live"
    skip_live = pytest.mark.skip(
        reason="live test — set REPOAUDITOR_LLM=live to run against the real Anthropic API"
    )
    skip_local_evidence = pytest.mark.skip(
        reason="local evidence test — the git-ignored data tree is unavailable"
    )
    for item in items:
        if item.path.name in _LOCAL_EVIDENCE_TEST_FILES:
            item.add_marker(pytest.mark.local_evidence)
            if not _LOCAL_EVIDENCE_ROOT.exists():
                item.add_marker(skip_local_evidence)
        if not live_enabled and "live" in item.keywords:
            item.add_marker(skip_live)

from repoauditor.config import Config, PathsConfig
from repoauditor.detect.ensemble import LensCandidate, LensFindings
from repoauditor.falsify.outcome import FalsificationOutcome, SelfCritique
from repoauditor.llm import LLMClient, ScriptedBackend
from repoauditor.map.schema import ArchitectureExtraction
from repoauditor.normalize.adjudicate import Adjudication
from repoauditor.store.models import FalsificationStatus, Severity

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# A shared public-HTTP boundary used by both fixtures.
_PUBLIC_EDGE = {
    "name": "public HTTP edge",
    "description": "Unauthenticated HTTP requests enter here.",
}

# Per-repo canned model output. Keyed by the ingest repo_id (== fixture dir name).
# `candidates` is keyed by (lens, file). Every list mixes true positives with a
# planted false positive whose citation contains "@app.route" — the scripted
# falsifier kills exactly those, so precision goes 0.75 (raw detect) -> 1.0 (post-falsify).
FIXTURE_LLM: dict[str, dict] = {
    "example_vuln_repo": {
        "architecture": {
            "trust_boundaries": [_PUBLIC_EDGE],
            "entry_points": [
                {"name": "GET /user", "location": "app.py:19", "trust_boundary": "public HTTP edge"},
                {"name": "GET /fetch", "location": "app.py:28", "trust_boundary": "public HTTP edge"},
            ],
            "data_stores": [{"name": "app.db", "kind": "sqlite", "location": "app.py:23"}],
            "integrations": [
                {"name": "outbound HTTP (requests)", "direction": "outbound", "location": "app.py:32"}
            ],
        },
        "candidates": {
            ("owasp", "app.py"): [
                {"title": "Hardcoded API token", "file": "app.py", "line_start": 16, "line_end": 16,
                 "citation_snippet": 'API_TOKEN = "sk_live_51H8xExampleHardcodedSecretDoNotUse0000"',
                 "severity": "high", "confidence": 0.9, "trust_boundary_ref": "public HTTP edge",
                 "rationale": "Live-looking secret committed in source."},
                {"title": "SQL injection via unsanitized id parameter", "file": "app.py",
                 "line_start": 24, "line_end": 24,
                 "citation_snippet": 'rows = conn.execute("SELECT * FROM users WHERE id = " + user_id).fetchall()',
                 "severity": "critical", "confidence": 0.95, "trust_boundary_ref": "public HTTP edge",
                 "rationale": "User input concatenated into a SQL query."},
                {"title": "Server-side request forgery (SSRF)", "file": "app.py",
                 "line_start": 32, "line_end": 32,
                 "citation_snippet": "return requests.get(url).text",
                 "severity": "high", "confidence": 0.9, "trust_boundary_ref": "public HTTP edge",
                 "rationale": "Server fetches an attacker-supplied URL."},
                # planted false positive — killed by the falsifier (high-confidence kill).
                {"title": "Unauthenticated route may allow open redirect", "file": "app.py",
                 "line_start": 28, "line_end": 28,
                 "citation_snippet": '@app.route("/fetch")',
                 "severity": "medium", "confidence": 0.6, "trust_boundary_ref": "public HTTP edge",
                 "rationale": "Route decorator has no auth."},
                # deliberately AMBIGUOUS candidate: detect is confident it's worth
                # raising, but the falsifier cannot establish exploitability, reports
                # LOW confidence, and the reliability layer escalates it to `unresolved`
                # rather than guessing confirmed/killed.
                {"title": "Unvalidated user input reaches request handler", "file": "app.py",
                 "line_start": 22, "line_end": 22,
                 "citation_snippet": 'user_id = request.args.get("id")',
                 "severity": "low", "confidence": 0.6, "trust_boundary_ref": "public HTTP edge",
                 "rationale": "Input read without validation; exploitability depends on downstream use."},
            ],
        },
    },
    "command_injection_svc": {
        "architecture": {
            "trust_boundaries": [_PUBLIC_EDGE],
            "entry_points": [
                {"name": "GET /ping", "location": "service.py:17", "trust_boundary": "public HTTP edge"},
            ],
            "data_stores": [],
            "integrations": [],
        },
        "candidates": {
            ("owasp", "service.py"): [
                {"title": "Hardcoded database credential", "file": "service.py",
                 "line_start": 14, "line_end": 14,
                 "citation_snippet": 'DB_PASSWORD = "hunter2-prod-db-password"',
                 "severity": "high", "confidence": 0.9, "trust_boundary_ref": "public HTTP edge",
                 "rationale": "Database password committed in source."},
                {"title": "Command injection via host parameter", "file": "service.py",
                 "line_start": 21, "line_end": 21,
                 "citation_snippet": 'return os.popen("ping -c 1 " + host).read()',
                 "severity": "critical", "confidence": 0.95, "trust_boundary_ref": "public HTTP edge",
                 "rationale": "User input concatenated into a shell command."},
                # planted false positive — killed by the falsifier.
                {"title": "Missing rate limiting on /ping", "file": "service.py",
                 "line_start": 17, "line_end": 17,
                 "citation_snippet": '@app.route("/ping")',
                 "severity": "low", "confidence": 0.3, "trust_boundary_ref": "public HTTP edge",
                 "rationale": "No rate limiting on the route."},
            ],
        },
    },
}


def _scripted_handler(system, user, schema, context):
    """Deterministic model: route on schema + structured context. No prose parsing."""
    repo_id = context.get("repo_id")
    data = FIXTURE_LLM.get(repo_id, {})

    if schema is ArchitectureExtraction:
        return ArchitectureExtraction(**data["architecture"])

    if schema is LensFindings:
        key = (context.get("lens"), context.get("file"))
        cands = data.get("candidates", {}).get(key, [])
        return LensFindings(findings=[LensCandidate(**c) for c in cands])

    if schema is SelfCritique:
        # Reflect step of the challenger loop. The scripted verdicts are already
        # well-formed, so the self-critique upholds them at high confidence — a
        # confident confirm/kill therefore commits on iteration 1 (unchanged pipeline
        # behaviour); the deliberately-ambiguous candidate is blocked by its own LOW
        # verdict confidence regardless of the critique, and degrades to unresolved.
        return SelfCritique(upholds=True, concern="verdict is supported by the evidence.",
                            confidence=0.9)

    if schema is FalsificationOutcome:
        citation = context.get("citation", "")
        if 'request.args.get("id")' in citation:  # the deliberately ambiguous candidate
            # High-status guess, but LOW confidence -> the client flags it and the
            # falsify stage escalates to `unresolved` instead of accepting the guess.
            return FalsificationOutcome(
                status=FalsificationStatus.CONFIRMED,
                rationale="Cannot establish whether this input reaches a dangerous sink from "
                          "the available context.",
                reachable=None,
                confidence=0.3,
            )
        if "@app.route" in citation:  # the planted false positives
            return FalsificationOutcome(
                status=FalsificationStatus.KILLED,
                rationale="A route decorator is not attacker-controlled input and reaches no "
                          "dangerous sink; the flagged pattern is not a vulnerability.",
                reachable=False,
                confidence=0.9,
            )
        return FalsificationOutcome(
            status=FalsificationStatus.CONFIRMED,
            rationale="Reachable from an unauthenticated HTTP entry point with attacker-controlled "
                      "input and no mitigating control in the retrieved context.",
            reachable=True,
            confidence=0.9,
        )

    if schema is Adjudication:  # not exercised by the golden pipeline; safe default
        return Adjudication(severity=Severity.LOW, rationale="conservative default")

    raise AssertionError(f"scripted handler got unexpected schema: {schema.__name__}")


@dataclass(frozen=True)
class FixtureRepo:
    repo_id: str
    snapshot_path: Path
    expected: dict


@pytest.fixture
def tmp_config(tmp_path: Path) -> Config:
    """An isolated test config with a right-sized synthetic training corpus."""
    config = Config(
        paths=PathsConfig(
            data_dir=tmp_path,
            raw_dir=tmp_path / "raw",
            db_path=tmp_path / "repoauditor.db",
        ),
        root=tmp_path,
    )
    return config.model_copy(update={
        "triage": config.triage.model_copy(update={"synthetic_corpus_size": 200})
    })


@pytest.fixture
def scripted_backend() -> ScriptedBackend:
    """The config-free scripted model backend.

    The backend routes purely on schema + context and holds no `Config`, so it can be
    wrapped in an `LLMClient` bound to *any* store — useful when a test needs to drive
    two isolated stores (e.g. a prior-vs-new prompt benchmark) with the same model.
    """
    return ScriptedBackend(_scripted_handler)


@pytest.fixture
def scripted_llm(tmp_config, scripted_backend) -> LLMClient:
    """Deterministic reliability client for the whole pipeline (routes via FIXTURE_LLM).

    Wraps the scripted backend in the real `LLMClient`, so validation, retry, confidence
    gating, and ValidationFailure logging are exercised end-to-end — only the model call
    is scripted.
    """
    return LLMClient(scripted_backend, tmp_config)


@pytest.fixture
def stub_deterministic_tools(monkeypatch):
    """Replace scanner subprocesses with a deterministic adapter result.

    Scripted-model tests validate pipeline ordering and data flow, not scanner binaries.
    They still pass through ``run_ensemble``'s real deterministic-adapter seam and receive
    the same tuple shape, including a valid SARIF artifact.  Real binary behavior remains
    covered by the explicitly marked integration tests in ``test_deterministic.py`` and
    ``test_benchmark_corpus.py``.
    """
    def fake_adapters(snapshot_path, config, sarif_output_path):
        del snapshot_path, config
        sarif_output_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_output_path.write_text(
            json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8"
        )
        return [], sarif_output_path, "complete"

    monkeypatch.setattr(
        "repoauditor.detect.ensemble._run_deterministic_adapters", fake_adapters
    )


def _load_fixture(repo_id: str) -> FixtureRepo:
    repo_dir = FIXTURES_DIR / repo_id
    expected = json.loads((repo_dir / "expected_findings.json").read_text())
    return FixtureRepo(repo_id=repo_id, snapshot_path=repo_dir / "snapshot", expected=expected)


def benchmark_corpus_ids() -> list[str]:
    """Real, documented benchmark-corpus fixtures: not scripted, and carrying ground truth.

    These are the OWASP Benchmark for Python subset + the CVE-tagged repos. They are
    detected by the live LLM lens and/or the deterministic SAST/SCA tools — never by a
    scripted model — so they are excluded from the deterministic scripted golden test and
    exercised by `tests/test_benchmark_corpus.py` instead. Scripting canned answers for
    them would make their precision/recall circular. See `tests/fixtures/README.md`.

    A corpus fixture is identified *explicitly* by carrying an `expected_findings.json`
    (its ground truth), not merely by "any dir not scripted" — other kinds of fixture can
    now live under `fixtures/` (e.g. `multilang_retrieval/`, which exercises the retrieval
    index and has no vuln ground truth) without being mistaken for a benchmark repo.
    """
    available = sorted(
        p.name for p in FIXTURES_DIR.iterdir()
        if p.is_dir() and p.name not in FIXTURE_LLM
        and (p / "expected_findings.json").is_file()
    )
    selected = os.environ.get("REPOAUDITOR_CORPUS_IDS", "").strip()
    if not selected:
        return available
    requested = [repo_id.strip() for repo_id in selected.split(",") if repo_id.strip()]
    unknown = sorted(set(requested) - set(available))
    if unknown:
        raise ValueError(
            "REPOAUDITOR_CORPUS_IDS contains unknown fixture(s): " + ", ".join(unknown)
        )
    return list(dict.fromkeys(requested))


# The deterministic golden test can only run fixtures it has scripted model output for,
# so discovery is gated on `FIXTURE_LLM` (not "every dir under fixtures/"). This is what
# lets the benchmark corpus live alongside the scripted fixtures without breaking the
# scripted harness — a fixture without canned responses simply isn't parametrized here.
@pytest.fixture(params=sorted(FIXTURE_LLM))
def fixture_repo(request: pytest.FixtureRequest) -> FixtureRepo:
    """One scripted known-vulnerable fixture repo with its ground-truth expected findings.

    `repo_id` is the fixture dir name; the harness ingests each fixture under that id
    (overriding the basename-derived id, since every snapshot dir is named `snapshot`).
    """
    return _load_fixture(request.param)


@pytest.fixture(params=benchmark_corpus_ids())
def benchmark_repo(request: pytest.FixtureRequest) -> FixtureRepo:
    """One real, documented benchmark-corpus fixture (OWASP subset / CVE repo)."""
    return _load_fixture(request.param)
