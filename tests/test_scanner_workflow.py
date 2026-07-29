"""Static controls for the required scanner deployment workflow."""

from pathlib import Path


WORKFLOW = Path(".github/workflows/tests.yml")


def _gate() -> str:
    text = WORKFLOW.read_text()
    return text.split("\n  scanner-deployment:\n", 1)[1].split(
        "\n  integration:\n", 1
    )[0]


def test_required_scanner_gate_runs_on_pull_requests_and_retains_evidence():
    text = WORKFLOW.read_text()
    gate = _gate()

    assert "pull_request:" in text
    assert "scanner-deployment:" in text
    assert "name: scanner deployment / required" in gate
    assert "uv run repoauditor scanner-canaries" in gate
    assert "--output scanner-canaries.json" in gate
    assert "if: always()" in gate
    assert "scanner-versions.txt" in gate
    assert "retention-days: 30" in gate


def test_required_scanner_gate_uses_exact_scanner_versions():
    gate = _gate()

    assert "semgrep==1.170.1" in gate
    assert "pip-audit==2.10.1" in gate
    assert "gitleaks/v8@v8.30.1" in gate
    assert "osv-scanner@v2.3.8" in gate
