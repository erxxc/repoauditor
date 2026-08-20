"""Outcome-blind metadata-only Java/Ruby augmentation selection for OPT-010."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-selection-receipt-2026-08-20.json"
RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-selection-result-2026-08-20.json"
FOCUSED_TEST = ROOT / "tests/test_opt_010_java_ruby_source_augmentation_selection.py"
STORE = ROOT / "data/repoauditor.db"
STORE_SHA256 = "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a"
MAX_READS = 40
MAX_NEW_BYTES = 5 * 1024**2
MAX_SECONDS = 30 * 60
ALLOWED_LICENSES = {
    "AGPL-3.0",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "EPL-2.0",
    "GPL-2.0",
    "GPL-3.0",
    "LGPL-2.1",
    "LGPL-3.0",
    "MIT",
    "MPL-2.0",
}
DEPLOYMENT_MARKERS = (
    "self-hosted",
    "self hosted",
    "docker",
    "docker compose",
    "installation",
    "installing",
    "deployment",
    "deploy",
)
PRODUCT_MARKERS = (
    "application",
    "dashboard",
    "management",
    "platform",
    "server",
    "service",
    "system",
    "web app",
)
NON_PRODUCT_MARKERS = (
    "awesome list",
    "project template",
    "starter template",
    "software development kit",
)
EXPLICIT_PRIOR_FAMILIES = {
    "actualbudget/actual",
    "documenso/documenso",
    "go-vikunja/vikunja",
    "goauthentik/authentik",
    "miniflux/v2",
    "usememos/memos",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stable_identity(repository: str, commit: str) -> str:
    material = (
        "opt-010-java-ruby-augmentation-v1" + repository.lower() + commit
    ).encode()
    return hashlib.sha256(material).hexdigest()


def readme_is_deployable_product(text: str) -> bool:
    lowered = text.lower()
    return (
        any(marker in lowered for marker in DEPLOYMENT_MARKERS)
        and any(marker in lowered for marker in PRODUCT_MARKERS)
        and not any(marker in lowered for marker in NON_PRODUCT_MARKERS)
    )


class ReadMeter:
    def __init__(self, maximum: int = MAX_READS) -> None:
        self.maximum = maximum
        self.reads = 0
        self.hosts: set[str] = set()

    def get(self, url: str) -> dict[str, Any]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.hostname != "api.github.com":
            raise RuntimeError("nonallowed metadata host")
        if self.reads >= self.maximum:
            raise RuntimeError("metadata read ceiling reached")
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "RepoAuditor-OPT-010-metadata-selection",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        self.reads += 1
        self.hosts.add(parsed.hostname)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read()
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"GitHub metadata read failed: {type(exc).__name__}") from exc
        try:
            parsed_payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError("GitHub metadata response was not JSON") from exc
        if not isinstance(parsed_payload, dict):
            raise RuntimeError("GitHub metadata response shape drifted")
        return parsed_payload


def _api_url(path: str, query: dict[str, Any] | None = None) -> str:
    encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
    url = f"https://api.github.com/{encoded_path}"
    if query:
        url += "?" + urllib.parse.urlencode(query)
    return url


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def search_metadata_eligible(
    item: dict[str, Any], *, language: str, excluded_repositories: set[str], excluded_owners: set[str]
) -> bool:
    repository = str(item.get("full_name", "")).lower()
    owner = repository.split("/", 1)[0] if "/" in repository else ""
    license_record = item.get("license") or {}
    topics = {str(value).lower() for value in item.get("topics", [])}
    description = str(item.get("description") or "").lower()
    try:
        created = _timestamp(str(item["created_at"]))
        pushed = _timestamp(str(item["pushed_at"]))
    except (KeyError, ValueError):
        return False
    return (
        bool(repository and owner)
        and repository not in excluded_repositories
        and owner not in excluded_owners
        and item.get("fork") is False
        and item.get("archived") is False
        and item.get("is_template") is not True
        and item.get("private") is False
        and item.get("language") == language
        and created <= datetime(2024, 8, 20, 23, 59, 59, tzinfo=UTC)
        and pushed >= datetime(2025, 8, 20, tzinfo=UTC)
        and int(item.get("stargazers_count", 0)) >= 100
        and "self-hosted" in topics
        and license_record.get("spdx_id") in ALLOWED_LICENSES
        and not any(marker in description for marker in NON_PRODUCT_MARKERS)
        and bool(item.get("default_branch"))
    )


def _resolve_candidate(item: dict[str, Any], language: str, meter: ReadMeter) -> dict[str, Any] | None:
    repository = str(item["full_name"])
    encoded_repo = "/".join(urllib.parse.quote(part, safe="") for part in repository.split("/"))
    readme = meter.get(f"https://api.github.com/repos/{encoded_repo}/readme")
    content = readme.get("content")
    if not isinstance(content, str) or readme.get("encoding") != "base64":
        return None
    try:
        text = base64.b64decode(content, validate=False).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return None
    if not readme_is_deployable_product(text):
        return None
    branch = str(item["default_branch"])
    commit = meter.get(
        f"https://api.github.com/repos/{encoded_repo}/commits/{urllib.parse.quote(branch, safe='')}"
    )
    exact_commit = commit.get("sha")
    readme_sha = readme.get("sha")
    readme_path = readme.get("path")
    license_id = (item.get("license") or {}).get("spdx_id")
    if (
        not isinstance(exact_commit, str)
        or len(exact_commit) != 40
        or not isinstance(readme_sha, str)
        or len(readme_sha) != 40
        or not isinstance(readme_path, str)
        or license_id not in ALLOWED_LICENSES
    ):
        return None
    return {
        "repository": repository,
        "repository_url": str(item["html_url"]),
        "default_branch": branch,
        "exact_commit": exact_commit,
        "stable_identity_sha256": stable_identity(repository, exact_commit),
        "primary_language": language,
        "license": license_id,
        "README_path": readme_path,
        "README_sha": readme_sha,
        "selection_basis": (
            "Outcome-blind public metadata identifies an independently deployable maintained "
            f"self-hosted {language} product with recognized license and exact HEAD provenance."
        ),
    }


def _new_bytes() -> int:
    return sum(path.stat().st_size for path in (Path(__file__), FOCUSED_TEST, RESULT) if path.is_file())


def _write_result(payload: dict[str, Any]) -> None:
    for _ in range(5):
        RESULT.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        size = _new_bytes()
        if payload["resource_accounting"]["new_data_bytes"] == size:
            break
        payload["resource_accounting"]["new_data_bytes"] = size
    RESULT.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _preflight() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if RESULT.exists():
        raise RuntimeError("source-selection output already exists")
    for record in receipt["frozen_inputs"].values():
        if isinstance(record, dict) and sha256(ROOT / record["path"]) != record["sha256"]:
            raise RuntimeError("frozen input digest drifted")
    if sha256(STORE) != STORE_SHA256:
        raise RuntimeError("production store digest drifted")
    branch = subprocess_run(["git", "branch", "--show-current"])
    head = subprocess_run(["git", "rev-parse", "HEAD"])
    staged = subprocess.call(["git", "diff", "--cached", "--quiet"], cwd=ROOT)
    workspace = receipt["workspace_preflight"]
    if branch != workspace["branch"] or head != workspace["committed_main"] or staged != 0:
        raise RuntimeError("workspace branch, HEAD, or index drifted")
    prior = json.loads(
        (ROOT / receipt["frozen_inputs"]["original_source_selection_result"]["path"]).read_text()
    )
    selected = prior["selected_identities"]
    reserve = receipt["frozen_java_reserve_nomination"]
    frozen = next(item for item in selected if item["order"] == reserve["source_selection_order"])
    for field in (
        "repository",
        "repository_url",
        "default_branch",
        "exact_commit",
        "stable_identity_sha256",
        "primary_language",
        "license",
        "README_path",
        "README_sha",
    ):
        if frozen[field] != reserve[field]:
            raise RuntimeError("frozen Java reserve binding drifted")
    return receipt, selected


def subprocess_run(command: list[str]) -> str:
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)
    return completed.stdout.strip()


def run() -> dict[str, Any]:
    started = time.monotonic()
    receipt, prior_selected = _preflight()
    excluded_repositories = {item["repository"].lower() for item in prior_selected} | EXPLICIT_PRIOR_FAMILIES
    excluded_owners = {item["repository"].split("/", 1)[0].lower() for item in prior_selected}
    meter = ReadMeter()
    pools: dict[str, list[dict[str, Any]]] = {"Java": [], "Ruby": []}
    inspected = Counter()
    search_eligible = Counter()
    resolved_eligible = Counter()
    for query in receipt["metadata_discovery_contract"]["queries"]:
        language = query["language"]
        response = meter.get(
            _api_url(
                "search/repositories",
                {
                    "q": query["q"],
                    "sort": query["sort"],
                    "order": query["order"],
                    "per_page": query["candidate_limit"],
                },
            )
        )
        items = response.get("items")
        if not isinstance(items, list) or len(items) > query["candidate_limit"]:
            raise RuntimeError("GitHub search result shape or limit drifted")
        inspected[language] += len(items)
        prefiltered = [
            item
            for item in items
            if isinstance(item, dict)
            and search_metadata_eligible(
                item,
                language=language,
                excluded_repositories=excluded_repositories,
                excluded_owners=excluded_owners,
            )
        ]
        search_eligible[language] += len(prefiltered)
        for item in sorted(prefiltered, key=lambda value: str(value["full_name"]).lower()):
            if meter.reads + 2 > MAX_READS:
                break
            resolved = _resolve_candidate(item, language, meter)
            if resolved is not None:
                pools[language].append(resolved)
                resolved_eligible[language] += 1

    pools["Java"].sort(key=lambda item: item["stable_identity_sha256"])
    pools["Ruby"].sort(key=lambda item: item["stable_identity_sha256"])
    enough = len(pools["Java"]) >= 1 and len(pools["Ruby"]) >= 2
    fixed = dict(receipt["frozen_java_reserve_nomination"])
    fixed.pop("selection_basis")
    fixed.pop("acquisition_authorized")
    fixed.pop("source_selection_order")
    fixed.pop("role_before")
    fixed["role"] = fixed.pop("role_in_this_result")
    if enough:
        new = [pools["Java"][0], *pools["Ruby"][:2]]
        for item in new:
            item["role"] = "augmentation-primary-pending-owner-review"
        java = sorted([fixed, new[0]], key=lambda item: item["stable_identity_sha256"])
        ruby = sorted(new[1:], key=lambda item: item["stable_identity_sha256"])
        selected = java + ruby
        if len({item["repository"].split("/", 1)[0].lower() for item in selected}) != 4:
            raise RuntimeError("selected owner independence drifted")
    else:
        selected = []
    status = (
        "complete-four-identities-awaiting-owner-review"
        if enough
        else "stopped-aggregate-java-ruby-source-shortfall"
    )
    store_after = sha256(STORE)
    result: dict[str, Any] = {
        "schema_version": 1,
        "optimization": "OPT-010",
        "status": status,
        "metadata_discovery": {
            "queries": 2,
            "candidate_metadata_identities_inspected": sum(inspected.values()),
            "inspected_by_language": dict(inspected),
            "search_metadata_eligible_by_language": dict(search_eligible),
            "fully_resolved_eligible_by_language": dict(resolved_eligible),
            "network_reads": meter.reads,
            "metadata_documents": meter.reads,
            "hosts_used": sorted(meter.hosts),
            "readme_source_persisted": 0,
            "license_source_persisted": 0,
            "source_files_opened": 0,
        },
        "selection": {
            "required_identities": 4,
            "selected_identities": len(selected),
            "Java": sum(item["primary_language"] == "Java" for item in selected),
            "Ruby": sum(item["primary_language"] == "Ruby" for item in selected),
            "distinct_owners": len({item["repository"].split("/", 1)[0].lower() for item in selected}),
            "complete": enough,
            "partial_list_persisted_or_disclosed": False,
            "shortfall_by_language": {
                "Java": max(0, 1 - len(pools["Java"])),
                "Ruby": max(0, 2 - len(pools["Ruby"])),
            },
        },
        "selected_identities": selected,
        "decision": {
            "result_state": "complete-awaiting-project-owner-source-review" if enough else "stopped-aggregate-shortfall",
            "source_selection_complete": enough,
            "source_acquisition_authorized": False,
            "scanner_execution_authorized": False,
            "packet_construction_authorized": False,
            "opt010_status_changed": False,
        },
        "resource_accounting": {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "new_data_bytes": 0,
            "candidate_metadata_identities_inspected": sum(inspected.values()),
            "metadata_documents_and_network_reads": meter.reads,
            "network_uploads": 0,
            "provider_calls": 0,
            "provider_reported_tokens": 0,
            "provider_cost_usd": 0.0,
            "repository_materializations": 0,
            "repository_code_executions": 0,
            "scanner_processes": 0,
            "agentic_falsification_runs": 0,
            "production_store_database_reads": 0,
            "production_store_mutations": 0,
            "assessments_written": 0,
            "labels_written": 0,
            "model_training_runs": 0,
            "rescoring_runs": 0,
            "human_finding_reviews": 0,
            "branch_or_index_operations": 0,
            "source_commits": 0,
            "merge_commits": 0,
            "remote_pushes": 0,
            "lifecycle_changes": 0,
        },
        "store": {
            "expected_sha256": STORE_SHA256,
            "after_sha256": store_after,
            "byte_identical": store_after == STORE_SHA256,
        },
        "workspace": {
            "branch": subprocess_run(["git", "branch", "--show-current"]),
            "head": subprocess_run(["git", "rev-parse", "HEAD"]),
            "index_or_branch_changed": False,
        },
    }
    _write_result(result)
    if time.monotonic() - started > MAX_SECONDS:
        raise RuntimeError("elapsed-time ceiling exceeded")
    if result["resource_accounting"]["new_data_bytes"] > MAX_NEW_BYTES:
        raise RuntimeError("new-data ceiling exceeded")
    if meter.reads > MAX_READS:
        raise RuntimeError("metadata read ceiling exceeded")
    if not result["store"]["byte_identical"]:
        raise RuntimeError("production store changed")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run:
        parser.error("--run is required")
    print(json.dumps(run(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
