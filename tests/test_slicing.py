"""Python slicing adds bounded evidence without claiming path feasibility."""

from pathlib import Path

from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.falsify.slicing import SLICE_VERSION, build_python_slice
from repoauditor.store.models import Finding

UAT = Path(__file__).parent / "fixtures" / "uat_lightweight_app" / "snapshot"


def _finding(title: str, file: str, line: int, citation: str) -> Finding:
    return Finding(
        repo_id="r",
        title=title,
        file=file,
        line_start=line,
        line_end=line,
        citation_snippet=citation,
        source_tool="semgrep",
        confidence=0.8,
        severity="high",
    )


def test_sql_slice_connects_request_assignments_to_query_sink():
    evidence = build_python_slice(
        RetrievalIndex().build(UAT),
        _finding(
            "SQL injection [CWE-89]",
            "storefront/catalog.py",
            39,
            "rows = db.query(sql)",
        ),
    )

    assert evidence is not None
    assert evidence.mechanism == "sql_injection"
    assert evidence.status == "local"
    assert evidence.function == "search_products"
    assert evidence.sink and "db.query(sql)" in evidence.sink.source
    assert any('request.args.get("q"' in item.source for item in evidence.source_evidence)
    assert any(
        "register_blueprint(catalog_bp)" in item.source
        for item in evidence.registration_evidence
    )
    assert "reachability" in evidence.render()


def test_ssrf_slice_connects_request_target_to_http_sink():
    evidence = build_python_slice(
        RetrievalIndex().build(UAT),
        _finding(
            "Server-side request forgery (SSRF) [CWE-918]",
            "storefront/integrations.py",
            29,
            "resp = requests.get(target, timeout=5)",
        ),
    )

    assert evidence is not None and evidence.status == "local"
    assert evidence.sink and "requests.get(target" in evidence.sink.source
    assert any('request.args.get("url"' in item.source for item in evidence.source_evidence)
    assert any(
        "require_admin()" in item.source
        for item in evidence.authorization_candidates
    )
    assert any(
        "register_blueprint(integrations_bp)" in item.source
        for item in evidence.registration_evidence
    )


def test_dynamic_or_unresolved_dependency_is_explicitly_incomplete(tmp_path):
    (tmp_path / "svc.py").write_text(
        "import os\n\n"
        "def run():\n"
        "    os.system(command_from_plugin)\n"
    )
    evidence = build_python_slice(
        RetrievalIndex().build(tmp_path),
        _finding(
            "Command injection [CWE-78]",
            "svc.py",
            4,
            "os.system(command_from_plugin)",
        ),
    )

    assert evidence is not None
    assert evidence.status == "incomplete"
    assert any("command_from_plugin" in item for item in evidence.limitations)
    assert SLICE_VERSION in evidence.render()


def test_command_slice_surfaces_control_candidate_without_calling_it_effective(tmp_path):
    (tmp_path / "svc.py").write_text(
        "import os\n\n"
        "def run(user_input):\n"
        "    command = sanitize_command(user_input)\n"
        "    os.system(command)\n"
    )
    evidence = build_python_slice(
        RetrievalIndex().build(tmp_path),
        _finding(
            "Command injection [CWE-78]",
            "svc.py",
            5,
            "os.system(command)",
        ),
    )

    assert evidence is not None
    assert any("sanitize_command" in item.source for item in evidence.sanitizer_candidates)
    assert "sanitizer effectiveness" in evidence.render()


def test_slice_separates_authorization_candidates_from_authentication(tmp_path):
    (tmp_path / "svc.py").write_text(
        "import os\n\n"
        "@app.route('/run/<job_id>')\n"
        "@owns_resource('job')\n"
        "def run(job_id, command):\n"
        "    current_customer_id()\n"
        "    os.system(command)\n"
    )
    evidence = build_python_slice(
        RetrievalIndex().build(tmp_path),
        _finding(
            "Command injection [CWE-78]",
            "svc.py",
            7,
            "os.system(command)",
        ),
    )

    assert evidence is not None
    assert [item.source for item in evidence.authorization_candidates] == [
        "@owns_resource('job')"
    ]
    assert all(
        "current_customer_id" not in item.source
        for item in evidence.authorization_candidates
    )
    assert "authorization-candidate" in evidence.render()


def test_unsupported_mechanism_does_not_emit_a_slice():
    evidence = build_python_slice(
        RetrievalIndex().build(UAT),
        _finding(
            "Broken object authorization [CWE-862]",
            "storefront/orders.py",
            24,
            "def get_order(order_id: int):",
        ),
    )

    assert evidence is None
