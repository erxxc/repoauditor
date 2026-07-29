"""Tests for the deterministic tool adapters and their wiring into the detect ensemble.

`parse()` is tested against captured tool output (no binary needed); `run()` is tested
for graceful degradation and, for the one tool installed here (gitleaks), end to end. The
secret-redaction guarantee — the raw credential never reaches the store — is asserted
explicitly. The ensemble test proves tool findings land in the same table as lens
findings, tagged with `source_tool`.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

import repoauditor.detect.ensemble as ensemble_module
from repoauditor.detect import run_ensemble
from repoauditor.detect.ensemble import CandidateFinding
from repoauditor.detect.deterministic import SastAdapter, ScaAdapter, SecretsAdapter
from repoauditor.detect.deterministic.secrets_adapter import _redact
from repoauditor.ingest import ingest_repo
from repoauditor.map import recover_architecture
from repoauditor.store import db
from repoauditor.store.models import Severity

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# SAST (Semgrep SARIF) — reuses the shared triage.features SARIF reader
# --------------------------------------------------------------------------- #
_SARIF = json.dumps({
    "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "python.audit.dangerous-os-exec", "name": "dangerous-os-exec",
             "properties": {"tags": ["CWE-78"], "security-severity": "8.5"}},
        ]}},
        "results": [{
            "ruleId": "python.audit.dangerous-os-exec",
            "level": "error",
            "message": {"text": "OS command injection via os.popen"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "service.py"},
                "region": {"startLine": 21, "endLine": 21,
                           "snippet": {"text": 'os.popen("ping " + host)'}},
            }}],
        }],
    }],
})


def test_sast_adapter_parses_semgrep_sarif_into_candidates():
    cands = SastAdapter().parse(_SARIF)
    assert len(cands) == 1
    c = cands[0]
    assert c.source_tool == "sast"
    assert c.file == "service.py" and c.line_start == 21
    assert c.severity is Severity.HIGH          # security-severity 8.5 -> high
    assert "os.popen" in c.citation_snippet
    assert "CWE-78" in (c.rationale or "")


@pytest.mark.integration
def test_sast_adapter_run_returns_a_list_without_raising(tmp_path):
    assert isinstance(SastAdapter().run(tmp_path), list)


def test_sast_adapter_writes_empty_sarif_when_semgrep_is_unavailable(tmp_path, monkeypatch):
    artifact = tmp_path / "artifacts" / "semgrep.sarif"
    monkeypatch.setattr("repoauditor.detect.deterministic.sast_adapter.shutil.which",
                        lambda _binary: None)

    adapter = SastAdapter(sarif_output_path=artifact)
    assert adapter.run(tmp_path) == []
    assert adapter.run_status == "unavailable"
    doc = json.loads(artifact.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"] == []


def test_sast_adapter_preserves_valid_sarif_outside_snapshot(tmp_path, monkeypatch):
    snapshot = tmp_path / "raw" / "acme" / "abc123"
    snapshot.mkdir(parents=True)
    artifact = tmp_path / "artifacts" / "acme" / "abc123" / "detect" / "semgrep.sarif"

    class Completed:
        stdout = _SARIF

    monkeypatch.setattr("repoauditor.detect.deterministic.sast_adapter.shutil.which",
                        lambda _binary: "/usr/bin/semgrep")
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        report = Path(command[command.index("--json-output") + 1])
        report.write_text(
            json.dumps({"paths": {"scanned": [str(snapshot / "service.py")]}})
        )
        return Completed()

    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sast_adapter.subprocess.run", run
    )

    findings = SastAdapter(sarif_output_path=artifact).run(snapshot)

    assert len(findings) == 1
    assert calls[0][0] == [
        "semgrep",
        "scan",
        "--sarif",
        "--quiet",
        "--no-git-ignore",
        "--project-root",
        str(snapshot),
        "--json-output",
        calls[0][0][calls[0][0].index("--json-output") + 1],
        "--config",
        "auto",
        str(snapshot),
    ]
    assert artifact.read_text(encoding="utf-8") == _SARIF
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert not (snapshot / "semgrep.sarif").exists()


def test_sast_adapter_fails_closed_when_semgrep_selects_zero_targets(
    tmp_path, monkeypatch
):
    snapshot = tmp_path / "raw" / "ignored"
    snapshot.mkdir(parents=True)
    (snapshot / "service.py").write_text("dangerous(user_input)\n")
    artifact = tmp_path / "artifacts" / "semgrep.sarif"

    class Completed:
        returncode = 0
        stdout = _SARIF
        stderr = ""

    def run(command, **kwargs):
        report = Path(command[command.index("--json-output") + 1])
        report.write_text(json.dumps({"paths": {"scanned": []}}))
        return Completed()

    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sast_adapter.shutil.which",
        lambda _binary: "/usr/bin/semgrep",
    )
    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sast_adapter.subprocess.run", run
    )

    adapter = SastAdapter(sarif_output_path=artifact)

    assert adapter.run(snapshot) == []
    assert adapter.run_status == "failed"
    assert adapter.failure_detail == "Semgrep selected zero targets"
    assert json.loads(artifact.read_text())["runs"][0]["results"] == []


# --------------------------------------------------------------------------- #
# SCA (pip-audit + OSV-Scanner)
# --------------------------------------------------------------------------- #
def test_sca_adapter_parses_pip_audit_json():
    raw = json.dumps({"dependencies": [
        {"name": "flask", "version": "0.5", "vulns": [
            {"id": "PYSEC-2019-179", "fix_versions": ["0.12.3"],
             "description": "XSS in Flask"}]},
    ]})
    cands = ScaAdapter().parse_pip_audit(raw, manifest="requirements.txt")
    assert len(cands) == 1
    c = cands[0]
    assert c.source_tool == "sca"
    assert c.identity_key == "sca:pypi:flask:0.5:pysec-2019-179"
    assert c.file == "requirements.txt" and c.line_start == 1 and c.line_end == 1
    assert "flask" in c.citation_snippet and "PYSEC-2019-179" in c.citation_snippet


def test_sca_adapter_parses_osv_scanner_json_and_auto_detects_format():
    raw = json.dumps({"results": [{
        "source": {"path": "requirements.txt", "type": "lockfile"},
        "packages": [{
            "package": {"name": "django", "version": "2.0", "ecosystem": "PyPI"},
            "vulnerabilities": [{"id": "GHSA-abcd", "summary": "SQLi in Django"}],
        }],
    }]})
    cands = ScaAdapter().parse(raw)  # auto-detects OSV by the "results" key
    assert len(cands) == 1
    c = cands[0]
    assert c.source_tool == "sca" and c.file == "requirements.txt" and c.line_start == 1
    assert c.identity_key == "sca:pypi:django:2.0:ghsa-abcd"
    assert "django" in c.citation_snippet and "GHSA-abcd" in c.citation_snippet


def test_sca_adapter_explicitly_scans_requirements_when_osv_recursive_discovery_fails(
        tmp_path, monkeypatch):
    requirement = tmp_path / "requirements.txt"
    requirement.write_text("requests==2.19.1\n")
    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.shutil.which",
        lambda binary: f"/usr/bin/{binary}",
    )

    class RecursiveFailure:
        returncode = 128
        stdout = ""
        stderr = "No package sources found, --help for usage information."

    class ExplicitSuccess:
        returncode = 1
        stderr = ""
        stdout = json.dumps({"results": [{
            "source": {"path": str(requirement), "type": "lockfile"},
            "packages": [{
                "package": {
                    "name": "requests", "version": "2.19.1", "ecosystem": "PyPI",
                },
                "vulnerabilities": [{
                    "id": "CVE-2018-18074", "summary": "Credential forwarding",
                }],
            }],
        }]})

    calls = iter([RecursiveFailure(), ExplicitSuccess()])
    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        return next(calls)

    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.subprocess.run", fake_run,
    )
    adapter = ScaAdapter()

    findings = adapter._run_osv_scanner(tmp_path)

    assert len(findings) == 1
    assert findings[0].producer == "osv-scanner"
    assert findings[0].file == "requirements.txt"
    assert commands[0] == [
        "osv-scanner",
        "scan",
        "source",
        "--format",
        "json",
        "--recursive",
        "--no-ignore",
        str(tmp_path),
    ]
    assert commands[1][-2:] == [
        "--lockfile", str(requirement),
    ]
    assert adapter.run_statuses["osv-scanner"] == "partial"
    assert "Other manifest types may be uncovered" in (
        adapter.failure_details["osv-scanner"]
    )


def test_sca_adapter_marks_no_package_sources_not_applicable(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.shutil.which",
        lambda binary: f"/usr/bin/{binary}",
    )

    class NoSources:
        returncode = 128
        stdout = ""
        stderr = (
            "Scanning template requirements\n"
            + ("package discovery detail " * 30)
            + "\nNo package sources found, --help for usage information."
        )

    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.subprocess.run",
        lambda *args, **kwargs: NoSources(),
    )
    adapter = ScaAdapter()

    assert adapter._run_osv_scanner(tmp_path) == []
    assert adapter.run_statuses["osv-scanner"] == "not-applicable"
    assert "osv-scanner" not in adapter.failure_details


def test_sca_adapter_marks_empty_explicit_requirements_not_applicable(
    tmp_path, monkeypatch
):
    (tmp_path / "requirements.txt").write_text("# template placeholder\n")
    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.shutil.which",
        lambda binary: f"/usr/bin/{binary}",
    )

    class NoSources:
        returncode = 128
        stdout = ""
        stderr = "No package sources found, --help for usage information."

    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.subprocess.run",
        lambda *args, **kwargs: NoSources(),
    )
    adapter = ScaAdapter()

    assert adapter._run_osv_scanner(tmp_path) == []
    assert adapter.run_statuses["osv-scanner"] == "not-applicable"
    assert "osv-scanner" not in adapter.failure_details


def test_sca_adapter_records_pip_audit_execution_failure(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.shutil.which",
        lambda binary: f"/usr/bin/{binary}",
    )

    class Failed:
        returncode = 2
        stdout = ""
        stderr = "failed to prepare isolated environment"

    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.subprocess.run",
        lambda *args, **kwargs: Failed(),
    )
    adapter = ScaAdapter()

    assert adapter._run_pip_audit(tmp_path) == []
    assert adapter.run_statuses["pip-audit"] == "failed"
    assert "isolated environment" in adapter.failure_details["pip-audit"]


def test_sca_adapter_falls_back_to_exact_direct_pins(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.shutil.which",
        lambda binary: f"/usr/bin/{binary}",
    )

    class Failed:
        returncode = 2
        stdout = ""
        stderr = "failed to prepare isolated environment"

    class Direct:
        returncode = 1
        stderr = ""
        stdout = json.dumps({"dependencies": [{
            "name": "requests", "version": "2.19.1",
            "vulns": [{"id": "CVE-2018-18074", "fix_versions": ["2.20.0"]}],
        }]})

    calls = iter([Failed(), Direct()])
    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.subprocess.run",
        lambda *args, **kwargs: next(calls),
    )
    adapter = ScaAdapter()

    findings = adapter._run_pip_audit(tmp_path)

    assert any("CVE-2018-18074" in finding.title for finding in findings)
    assert adapter.run_statuses["pip-audit"] == "partial"
    assert "without transitive resolution" in adapter.failure_details["pip-audit"]


def test_sca_adapter_rejects_malformed_success_output(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.shutil.which",
        lambda binary: f"/usr/bin/{binary}",
    )

    class Malformed:
        returncode = 0
        stdout = "not-json"
        stderr = ""

    monkeypatch.setattr(
        "repoauditor.detect.deterministic.sca_adapter.subprocess.run",
        lambda *args, **kwargs: Malformed(),
    )
    adapter = ScaAdapter()

    assert adapter._run_pip_audit(tmp_path) == []
    assert adapter.run_statuses["pip-audit"] == "failed"
    assert "malformed" in adapter.failure_details["pip-audit"]

    assert adapter._run_osv_scanner(tmp_path) == []
    assert adapter.run_statuses["osv-scanner"] == "failed"
    assert "malformed" in adapter.failure_details["osv-scanner"]


@pytest.mark.integration
def test_sca_adapter_run_returns_a_list_without_raising(tmp_path):
    assert isinstance(ScaAdapter().run(tmp_path), list)


# --------------------------------------------------------------------------- #
# Secrets (gitleaks) — the raw credential must never reach a finding
# --------------------------------------------------------------------------- #
def test_redact_masks_the_secret_out_of_its_match():
    assert _redact('API_TOKEN = "sk_live_ABCDEF"', "sk_live_ABCDEF") == 'API_TOKEN = "****"'
    # If the secret isn't literally inside the match, drop to a bare mask (never leak it).
    assert _redact("token here", "sk_live_ABCDEF") == "****"


def test_secrets_adapter_parses_gitleaks_json_with_the_secret_redacted():
    raw = json.dumps([{
        "RuleID": "stripe-access-token", "Description": "Stripe access token",
        "File": "app.py", "StartLine": 16, "EndLine": 16,
        "Match": 'API_TOKEN = "sk_live_SUPERSECRET0000"',
        "Secret": "sk_live_SUPERSECRET0000",
    }])
    cands = SecretsAdapter().parse(raw)
    assert len(cands) == 1
    c = cands[0]
    assert c.source_tool == "secrets" and c.severity is Severity.HIGH
    assert c.file == "app.py" and c.line_start == 16
    # The redacted marker is present and the raw secret is nowhere in what we persist.
    assert "****" in c.citation_snippet
    assert "sk_live_SUPERSECRET0000" not in c.citation_snippet
    assert "sk_live_SUPERSECRET0000" not in (c.rationale or "")


@pytest.mark.parametrize(
    ("returncode", "report", "failure"),
    [
        (2, "[]", "exit code 2"),
        (0, "not-json", "malformed or unsupported JSON"),
    ],
)
def test_secrets_adapter_rejects_failed_or_malformed_runs(
    tmp_path, monkeypatch, returncode, report, failure
):
    monkeypatch.setattr(
        "repoauditor.detect.deterministic.secrets_adapter.shutil.which",
        lambda _binary: "/usr/bin/gitleaks",
    )

    class Completed:
        stderr = ""

        def __init__(self):
            self.returncode = returncode

    def run(command, **kwargs):
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text(report)
        return Completed()

    monkeypatch.setattr(
        "repoauditor.detect.deterministic.secrets_adapter.subprocess.run", run
    )
    adapter = SecretsAdapter()

    assert adapter.run(tmp_path) == []
    assert adapter.run_status == "failed"
    assert failure in (adapter.failure_detail or "")


@pytest.mark.integration
def test_secrets_adapter_run_finds_and_redacts_a_real_planted_secret():
    """End-to-end with the installed gitleaks binary on a fixture with a planted secret."""
    snapshot = FIXTURES / "example_vuln_repo" / "snapshot"
    cands = SecretsAdapter().run(snapshot)
    assert cands, "gitleaks should flag the planted sk_live_ token"
    leak = cands[0]
    assert leak.source_tool == "secrets"
    assert leak.file.endswith("app.py")
    # The value the fixture planted must not survive into the finding.
    assert "sk_live_51H8xExampleHardcodedSecretDoNotUse0000" not in leak.citation_snippet


# --------------------------------------------------------------------------- #
# Ensemble wiring: tool findings land in the store alongside lens findings
# --------------------------------------------------------------------------- #
def _ingest_and_map(tmp_config, scripted_llm, repo_id="example_vuln_repo"):
    result = ingest_repo(str(FIXTURES / repo_id / "snapshot"), tmp_config, repo_id=repo_id)
    recover_architecture(result.snapshot_path, result.repo_id, result.commit,
                         tmp_config, scripted_llm)
    return result.repo_id


@pytest.mark.integration
def test_ensemble_persists_tool_findings_alongside_lens_findings(tmp_config, scripted_llm):
    db.init_db(tmp_config)
    repo_id = _ingest_and_map(tmp_config, scripted_llm)
    result = run_ensemble(repo_id, tmp_config, llm=scripted_llm)

    assert result.sarif_path is not None
    assert result.sarif_path.is_file()
    artifact_rel = result.sarif_path.relative_to(
        tmp_config.resolve(tmp_config.paths.data_dir)
    )
    assert artifact_rel.parts[:2] == ("artifacts", repo_id)
    assert artifact_rel.parts[-2:] == ("detect", "semgrep.sarif")
    assert result.semgrep_status in {"complete", "empty", "unavailable", "failed", "malformed"}

    findings = db.list_findings(repo_id, tmp_config)
    lens = [f for f in findings if f.source_lens]
    tools = [f for f in findings if f.source_tool]
    assert lens, "LLM lenses should still produce findings"
    # gitleaks (installed) contributes a secret finding tagged source_tool='secrets'.
    assert any(f.source_tool == "secrets" for f in tools)
    # Every tool finding traces back to a trust boundary (primary-boundary fallback).
    assert all(f.trust_boundary_id is not None for f in tools)


def test_ensemble_can_run_lens_only_when_tools_disabled(tmp_config, scripted_llm):
    db.init_db(tmp_config)
    cfg = tmp_config.model_copy(
        update={"detect": tmp_config.detect.model_copy(
            update={"run_deterministic_tools": False})})
    repo_id = _ingest_and_map(cfg, scripted_llm)
    run_ensemble(repo_id, cfg, llm=scripted_llm)

    findings = db.list_findings(repo_id, cfg)
    assert findings and all(f.source_tool is None for f in findings)  # lens-only


def test_completed_detection_regions_are_reused_without_model_calls(
    tmp_config, scripted_llm, scripted_backend
):
    db.init_db(tmp_config)
    cfg = tmp_config.model_copy(
        update={"detect": tmp_config.detect.model_copy(
            update={"run_deterministic_tools": False})})
    repo_id = _ingest_and_map(cfg, scripted_llm)

    first = run_ensemble(repo_id, cfg, llm=scripted_llm)
    calls_after_first = len(scripted_backend.calls)
    second = run_ensemble(repo_id, cfg, llm=scripted_llm)

    assert len(scripted_backend.calls) == calls_after_first
    assert first.completed_region_calls > 0
    assert second.completed_region_calls == 0
    assert second.skipped_completed_region_calls == first.completed_region_calls
    commit = next(
        repo.commit_hash for repo in db.list_ingested_repos(cfg)
        if repo.repo_id == repo_id
    )
    regions = db.list_detection_regions(
        repo_id, commit, cfg
    )
    assert regions and all(region.status.value == "completed" for region in regions)


def test_detection_run_retains_cross_file_context_provenance(
    tmp_config, scripted_llm, monkeypatch
):
    db.init_db(tmp_config)
    cfg = tmp_config.model_copy(
        update={"detect": tmp_config.detect.model_copy(
            update={"run_deterministic_tools": False})})
    repo_id = _ingest_and_map(cfg, scripted_llm)

    def fixed_context(_index, primary_file, _file_text, *, limit=3):
        assert limit == 3
        return "", [{
            "basis": "call-name-match",
            "file": f"related/{Path(primary_file).name}",
            "line_start": 7,
            "symbol": "dispatch",
        }]

    monkeypatch.setattr(
        ensemble_module, "_retrieval_context_with_provenance", fixed_context
    )

    result = run_ensemble(repo_id, cfg, llm=scripted_llm)

    assert result.context_expansions
    assert len(result.context_expansions) == len(result.selected_regions)
    for expansion in result.context_expansions:
        assert expansion["primary_file"] in {
            selected["file"] for selected in result.selected_regions
        }
        assert expansion["related"][0]["file"].startswith("related/")


def test_fake_adapter_candidate_persists_through_ensemble_fast_lane(
    tmp_config, scripted_llm, monkeypatch
):
    """Protect the adapter-to-store contract without launching scanner binaries."""
    db.init_db(tmp_config)
    repo_id = _ingest_and_map(tmp_config, scripted_llm)

    def fake_adapters(_snapshot, _config, sarif_path):
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text('{"version":"2.1.0","runs":[]}')
        candidate = CandidateFinding(
            title="Fixed fake command injection",
            file="app.py",
            line_start=32,
            line_end=32,
            citation_snippet="return requests.get(url).text",
            source_tool="sast",
            producer="semgrep",
            confidence=0.9,
            severity=Severity.HIGH,
            trust_boundary_ref="public HTTP edge",
            rationale="Fixed adapter fixture.",
        )
        return (
            [candidate],
            sarif_path,
            "complete",
            {
                "semgrep": "complete",
                "pip-audit": "empty",
                "osv-scanner": "empty",
                "gitleaks": "empty",
            },
            {},
        )

    monkeypatch.setattr(
        "repoauditor.detect.ensemble._run_deterministic_adapters", fake_adapters
    )
    result = run_ensemble(repo_id, tmp_config, llm=scripted_llm)

    persisted = [
        finding for finding in db.list_findings(repo_id, tmp_config)
        if finding.title == "Fixed fake command injection"
    ]
    assert len(persisted) == 1
    assert persisted[0].source_tool == "sast"
    assert persisted[0].trust_boundary_id is not None
    assert result.source_counts["semgrep"] == 1
    assert result.scanner_statuses["semgrep"] == "complete"
    assert result.scanner_statuses["pip-audit"] == "empty"
    assert result.scanner_failures == {}
