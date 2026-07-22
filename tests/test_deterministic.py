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

from repoauditor.detect import run_ensemble
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


def test_sast_adapter_run_returns_a_list_without_raising(tmp_path):
    # semgrep isn't installed here; run() must degrade to [] rather than raise.
    assert SastAdapter().run(tmp_path) == []


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
    monkeypatch.setattr("repoauditor.detect.deterministic.sast_adapter.subprocess.run",
                        lambda *args, **kwargs: Completed())

    findings = SastAdapter(sarif_output_path=artifact).run(snapshot)

    assert len(findings) == 1
    assert artifact.read_text(encoding="utf-8") == _SARIF
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert not (snapshot / "semgrep.sarif").exists()


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
    assert "django" in c.citation_snippet and "GHSA-abcd" in c.citation_snippet


def test_sca_adapter_run_returns_a_list_without_raising(tmp_path):
    assert ScaAdapter().run(tmp_path) == []   # neither pip-audit nor osv-scanner installed


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
