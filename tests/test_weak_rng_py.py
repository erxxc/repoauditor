"""weak_rng_py: the Python `random` detector plugin (additive, beside the digest-bound
Java weak_rng plugin). Pins detection on a synthetic snapshot, the skip rules (tests,
comments, secrets/SystemRandom), the execution contract, registry discovery, and a
passing canary with the plugin's own provenance certification."""

from __future__ import annotations

from pathlib import Path
import json

from repoauditor.detect.deterministic import registry
from repoauditor.detect.deterministic.plugins import weak_rng_py


def _snapshot(tmp_path: Path) -> Path:
    root = tmp_path / "snap"
    (root / "app").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "app" / "tokens.py").write_text(
        "import random\n"
        "import secrets\n"
        "\n"
        "\n"
        "def reset_code():\n"
        "    return random.getrandbits(64)\n"          # py-random-getrandbits
        "\n"
        "\n"
        "def session_id():\n"
        "    # random.random() would be weak\n"        # comment: skipped
        "    return ''.join(random.choice('abc') for _ in range(8))\n"  # py-random-module
        "\n"
        "\n"
        "def safe():\n"
        "    return secrets.token_hex(16)\n"
        "\n"
        "\n"
        "rng = random.SystemRandom()\n"                 # excluded
        "seeded = random.Random(42)\n",                 # py-random-ctor
        encoding="utf-8",
    )
    (root / "tests" / "test_tokens.py").write_text(
        "import random\nvalue = random.getrandbits(8)\n", encoding="utf-8")
    return root


def test_detects_python_idioms_and_skips_tests_comments_and_secure_apis(tmp_path):
    root = _snapshot(tmp_path)
    adapter = weak_rng_py.create_adapter(1)
    findings = adapter.run(root)
    by_producer = {f.producer: f for f in findings}
    assert set(by_producer) == {"py-random-getrandbits", "py-random-module", "py-random-ctor"}
    assert all(f.source_tool == "weak_rng_py" and f.severity.value == "medium" for f in findings)
    assert all(f.file == "app/tokens.py" for f in findings)
    assert by_producer["py-random-getrandbits"].identity_key.startswith("weak-rng-py:app/tokens.py:")
    assert "reset_code" in by_producer["py-random-getrandbits"].identity_key
    execution = adapter.execution()
    assert execution.status == "complete" and execution.finding_count == 3
    assert execution.target_count == 1 and execution.target_count_basis == "scanner-reported-files"
    assert execution.version == "weak_rng_py@v1" and execution.configuration_resolution == "embedded-default"


def test_not_applicable_without_python_and_empty_when_clean(tmp_path):
    java = tmp_path / "j"
    java.mkdir()
    (java / "A.java").write_text("class A {}\n", encoding="utf-8")
    adapter = weak_rng_py.create_adapter(1)
    assert adapter.run(java) == [] and adapter.execution().status == "not-applicable"
    clean = tmp_path / "c"
    clean.mkdir()
    (clean / "t.py").write_text("import secrets\nx = secrets.token_hex()\n", encoding="utf-8")
    adapter = weak_rng_py.create_adapter(1)
    assert adapter.run(clean) == [] and adapter.execution().status == "empty"


def test_registered_through_the_plugin_seam():
    plugins = {p.id: p for p in registry.discover_scanner_plugins()}
    assert "weak_rng_py" in plugins
    assert plugins["weak_rng_py"].module == "repoauditor.detect.deterministic.plugins.weak_rng_py"
    adapters = registry.create_scanner_plugin_adapters(1)
    assert "weak_rng_py" in {a.tool_name for a in adapters}
    assert "weak_rng_py" in registry.scanner_plugin_canary_runners()


def test_canary_passes_with_own_provenance(tmp_path):
    result = weak_rng_py.run_canary(tmp_path, 1)
    assert result.scanner == "weak_rng_py"
    assert result.passed and result.provenance_passed
    assert result.positive.execution.status == "complete"
    assert result.clean.execution.status == "empty"


def test_snapshot_binding_fails_closed(tmp_path):
    root = _snapshot(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    from repoauditor.detect.retrieval.index import RetrievalIndex

    wrong_index = RetrievalIndex().build(other)
    adapter = weak_rng_py.create_adapter(1)
    try:
        adapter.run(root, wrong_index)
    except ValueError as error:
        assert "not bound" in str(error)
    else:
        raise AssertionError("mismatched RetrievalIndex was accepted")


def test_substring_only_alias_shadowing_and_string_boundaries_are_explicit(tmp_path):
    root = tmp_path / "limitations"
    root.mkdir()
    (root / "cases.py").write_text(
        "from random import getrandbits as bits\n"
        "alias_miss = bits(64)\n"
        "class Shadow:\n"
        "    def getrandbits(self, size): return size\n"
        "random = Shadow()\n"
        "shadow_match = random.getrandbits(64)\n"
        "string_match = 'random.randint(1, 9)'\n",
        encoding="utf-8",
    )
    findings = weak_rng_py.create_adapter(1).run(root)
    lines = {finding.line_start for finding in findings}
    assert 2 not in lines  # aliased import is outside substring-only coverage
    assert {6, 7} <= lines  # shadowed identifiers and strings are known candidates


def test_qualification_result_preserves_bounded_claim() -> None:
    root = Path(__file__).resolve().parents[1]
    result = json.loads((
        root / "docs/optimizations/opt-038-implementation-qualification-result-2026-09-10.json"
    ).read_text(encoding="utf-8"))
    assert result["status"] == "completed-bounded-qualification"
    assert result["qualified_contract"]["substring_only"] is True
    assert result["qualified_contract"]["initial_severity"] == "medium"
    assert result["qualified_contract"]["automatic_actionability_or_severity_upgrade"] is False
    assert result["activity"]["lattice_lab_imports_or_executions"] == 0
    assert result["lifecycle"]["opt_038"] == "open-pending-separately-authorized-closure"
