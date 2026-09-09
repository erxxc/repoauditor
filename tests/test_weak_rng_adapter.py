"""OPT-036 weak-RNG detector: locates predictable-generator idioms over the retrieval
index, with the corrected CandidateFinding contract, and does not false-positive on
SecureRandom / secure variants / test sources."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_language_pack")  # Java AST for enclosing-symbol identity

from repoauditor.detect.deterministic.weak_rng_adapter import WeakRngAdapter, detect_in_source
from repoauditor.detect.retrieval.index import RetrievalIndex
from repoauditor.store.models import Severity

_PROD = textwrap.dedent(
    """\
    package com.example.auth;

    import java.util.Random;
    import org.apache.commons.lang3.RandomStringUtils;

    public class TokenService {
        public String issueToken() {
            Random r = new Random();
            return RandomStringUtils.randomAlphanumeric(32);
        }

        public double jitter() {
            return Math.random();
        }

        // new Random() written in a comment must be ignored
        public String safe() {
            java.security.SecureRandom sr = new SecureRandom();
            return RandomStringUtils.secure().nextAlphanumeric(32);
        }
    }
    """
)

_TEST_SRC = textwrap.dedent(
    """\
    public class TokenServiceTest {
        public void t() { Random r = new Random(); }
    }
    """
)


def _index(tmp_path: Path) -> RetrievalIndex:
    prod = tmp_path / "src" / "main" / "java" / "TokenService.java"
    test = tmp_path / "src" / "test" / "java" / "TokenServiceTest.java"
    for path, body in ((prod, _PROD), (test, _TEST_SRC)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return RetrievalIndex().build(tmp_path)


def test_detects_the_three_java_idioms(tmp_path):
    findings = detect_in_source(_index(tmp_path))
    producers = {f.producer for f in findings}
    assert producers == {"java-util-random-ctor", "math-random", "apache-randomstringutils"}
    assert len(findings) == 3                       # one per idiom; comment + test excluded
    assert all(f.source_tool == "weak_rng" for f in findings)
    assert all(f.severity is Severity.MEDIUM for f in findings)   # conservative initial
    assert all(f.file.endswith("TokenService.java") for f in findings)


def test_no_false_positives_on_secure_or_tests(tmp_path):
    findings = detect_in_source(_index(tmp_path))
    joined = " ".join(f.citation_snippet for f in findings)
    assert "SecureRandom" not in joined
    assert "RandomStringUtils.secure" not in joined
    assert not any("test" in f.file.lower() for f in findings)     # test dir skipped
    assert not any(f.citation_snippet.strip().startswith("//") for f in findings)  # comment skipped


def test_finding_locations_and_identity(tmp_path):
    findings = detect_in_source(_index(tmp_path))
    ctor = next(f for f in findings if f.producer == "java-util-random-ctor")
    assert "new Random(" in ctor.citation_snippet
    assert ctor.line_start == ctor.line_end
    # exact line: the instantiation, not the comment
    assert _PROD.splitlines()[ctor.line_start - 1].strip() == "Random r = new Random();"
    # identity carries the enclosing method (tree-sitter), so re-runs collapse the issue
    assert "issueToken" in ctor.identity_key and ctor.identity_key.startswith("weak-rng:")


# --- OPT-022 execution contract
def test_execution_complete_when_java_and_idioms_present(tmp_path):
    adapter = WeakRngAdapter()
    prod = tmp_path / "src" / "main" / "java" / "TokenService.java"
    prod.parent.mkdir(parents=True, exist_ok=True)
    prod.write_text(_PROD)
    findings = adapter.run(tmp_path)
    ex = adapter.execution()
    assert findings and adapter.run_status == "complete"
    assert ex.status == "complete" and ex.applicable is True and ex.output_valid is True
    assert ex.finding_count == len(findings) and ex.target_count >= 1
    assert ex.target_count_basis == "scanner-reported-files"
    assert ex.version and ex.invocation  # provenance for the canary


def test_execution_empty_when_java_but_no_idioms(tmp_path):
    prod = tmp_path / "Safe.java"
    prod.write_text("public class Safe { java.security.SecureRandom r = new SecureRandom(); }\n")
    adapter = WeakRngAdapter()
    assert adapter.run(tmp_path) == []
    ex = adapter.execution()
    assert ex.status == "empty" and ex.finding_count == 0 and ex.target_count == 1


def test_execution_not_applicable_without_java(tmp_path):
    (tmp_path / "app.py").write_text("import random\nrandom.random()\n")  # not Java
    adapter = WeakRngAdapter()
    assert adapter.run(tmp_path) == []
    ex = adapter.execution()
    assert ex.status == "not-applicable" and ex.applicable is False
    assert ex.target_count == 0 and ex.applicability_detail


def test_rejects_index_bound_to_another_snapshot(tmp_path):
    submitted = tmp_path / "submitted"
    other = tmp_path / "other"
    submitted.mkdir()
    other.mkdir()
    (submitted / "Token.java").write_text("class Token { Random r = new Random(); }\n")
    (other / "Other.java").write_text("class Other {}\n")

    with pytest.raises(ValueError, match="not bound"):
        WeakRngAdapter().run(submitted, RetrievalIndex().build(other))
