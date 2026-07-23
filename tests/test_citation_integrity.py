"""Semantic citation-integrity checks at the LLM detection boundary."""

from __future__ import annotations

from pathlib import Path

from repoauditor.detect.ensemble import LensCandidate, _canonicalize_citation
from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.matching import find_matches
from repoauditor.store import db
from repoauditor.store.models import Finding

UAT_SNAPSHOT = Path(__file__).parent / "fixtures" / "uat_lightweight_app" / "snapshot"


def _candidate(**updates) -> LensCandidate:
    values = {
        "title": "Broken object authorization",
        "file": "invoices.py",
        "line_start": 30,
        "line_end": 40,
        "citation_snippet": 'row = db.query_one("SELECT * FROM orders WHERE id = ?", (order_id,))',
        "severity": "high",
        "confidence": 0.9,
        "rationale": "Order lookup lacks an ownership check.",
    }
    values.update(updates)
    return LensCandidate(**values)


def test_unique_retrieval_citation_is_relocated_to_canonical_file(tmp_config, tmp_path):
    db.init_db(tmp_config)
    (tmp_path / "orders.py").write_text(
        "def get_order(order_id):\n"
        '    row = db.query_one("SELECT * FROM orders WHERE id = ?", (order_id,))\n'
        "    return row\n"
    )
    (tmp_path / "invoices.py").write_text(
        "def get_invoice(invoice_id):\n"
        "    return guarded_lookup(invoice_id)\n"
    )
    index = RetrievalIndex().build(tmp_path)

    result = _canonicalize_citation(
        _candidate(), index, "invoices.py", "owasp", tmp_config
    )

    assert result is not None
    assert (result.file, result.line_start, result.line_end) == ("orders.py", 2, 2)
    assert "invoices.py:30-40 -> orders.py:2-2" in (result.rationale or "")
    assert db.list_validation_failures(tmp_config) == []


def test_observed_nonverbatim_invoice_order_misattribution_is_rejected(tmp_config):
    db.init_db(tmp_config)
    citation = (
        '@orders_bp.route("/orders/<int:order_id>")\n'
        "def get_order(order_id: int):\n"
        "    current_customer_id()  # ensure the caller is authenticated\n"
        "    row = db.query_one(\n"
        '        "SELECT id, customer_id, total, placed_at FROM orders WHERE id = ?", (o'
    )
    candidate = _candidate(
        file="storefront/invoices.py",
        line_start=30,
        line_end=42,
        citation_snippet=citation,
    )

    result = _canonicalize_citation(
        candidate,
        RetrievalIndex().build(UAT_SNAPSHOT),
        "storefront/invoices.py",
        "owasp",
        tmp_config,
    )

    assert result is None
    failures = db.list_validation_failures(tmp_config)
    assert len(failures) == 1
    assert "does not occur" in failures[0].validation_error


def test_relocated_candidate_groups_with_existing_underlying_issue(tmp_config, tmp_path):
    db.init_db(tmp_config)
    citation = 'row = db.query_one("SELECT * FROM orders WHERE id = ?", (order_id,))'
    (tmp_path / "orders.py").write_text(
        "def get_order(order_id):\n"
        f"    {citation}\n"
        "    return row\n"
    )
    (tmp_path / "invoices.py").write_text("def get_invoice():\n    return guarded()\n")
    relocated = _canonicalize_citation(
        _candidate(citation_snippet=citation),
        RetrievalIndex().build(tmp_path),
        "invoices.py",
        "owasp",
        tmp_config,
    )
    assert relocated is not None
    findings = [
        Finding(
            repo_id="r", title="IDOR", file="orders.py", line_start=2, line_end=2,
            citation_snippet=citation, source_lens="owasp", confidence=0.8,
            severity="high",
        ),
        Finding(
            repo_id="r", title=relocated.title, file=relocated.file,
            line_start=relocated.line_start, line_end=relocated.line_end,
            citation_snippet=relocated.citation_snippet, source_lens="owasp",
            confidence=relocated.confidence, severity=relocated.severity,
        ),
    ]

    assert len(find_matches(findings).groups) == 1


def test_nonexistent_citation_is_logged_and_not_persistable(tmp_config, tmp_path):
    db.init_db(tmp_config)
    (tmp_path / "orders.py").write_text("def safe():\n    return 1\n")

    result = _canonicalize_citation(
        _candidate(citation_snippet="not present anywhere"),
        RetrievalIndex().build(tmp_path),
        "orders.py",
        "owasp",
        tmp_config,
    )

    assert result is None
    failures = db.list_validation_failures(tmp_config)
    assert len(failures) == 1
    assert failures[0].module == "detect.citation"
    assert "does not occur" in failures[0].validation_error


def test_ambiguous_cross_file_citation_is_logged_and_rejected(tmp_config, tmp_path):
    db.init_db(tmp_config)
    duplicate = "dangerous(user_input)"
    (tmp_path / "a.py").write_text(f"def a():\n    {duplicate}\n")
    (tmp_path / "b.py").write_text(f"def b():\n    {duplicate}\n")
    (tmp_path / "declared.py").write_text("def clean():\n    return 1\n")

    result = _canonicalize_citation(
        _candidate(
            file="declared.py", line_start=2, line_end=2,
            citation_snippet=duplicate,
        ),
        RetrievalIndex().build(tmp_path),
        "declared.py",
        "owasp",
        tmp_config,
    )

    assert result is None
    failures = db.list_validation_failures(tmp_config)
    assert len(failures) == 1
    assert "ambiguous across 2 locations" in failures[0].validation_error
