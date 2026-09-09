"""Security and behavior contract for the package-local scanner extension seam."""

from __future__ import annotations

import json

import pytest

from repoauditor.detect.deterministic import registry


def test_registry_discovers_weak_rng_with_stable_contract():
    plugins = registry.discover_scanner_plugins()

    assert [plugin.id for plugin in plugins] == ["weak_rng"]
    assert plugins[0].module == (
        "repoauditor.detect.deterministic.plugins.weak_rng"
    )
    assert plugins[0].target_count_bases == ("scanner-reported-files",)
    assert len(plugins[0].manifest_sha256) == 64
    adapters = registry.create_scanner_plugin_adapters(1)
    assert [adapter.tool_name for adapter in adapters] == ["weak_rng"]
    assert set(registry.scanner_plugin_canary_runners()) == {"weak_rng"}


@pytest.mark.parametrize(
    ("name", "update", "message"),
    [
        ("escape", {"module": "third_party.plugin"}, "outside package seam"),
        ("bad-id", {"id": "../bad"}, "invalid or duplicate"),
        ("bad-basis", {"target_count_bases": ["absolute-path"]}, "target-count"),
        ("extra", {"unexpected": True}, "manifest schema"),
    ],
)
def test_registry_fails_closed_on_invalid_manifests(
    tmp_path, monkeypatch, name, update, message
):
    payload = {
        "schema_version": 1,
        "id": name,
        "module": f"repoauditor.detect.deterministic.plugins.{name}",
        "adapter_factory": "create_adapter",
        "canary_runner": "run_canary",
        "target_count_bases": ["scanner-reported-files"],
    }
    payload.update(update)
    (tmp_path / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(registry, "_plugin_root", lambda: tmp_path)

    with pytest.raises(RuntimeError, match=message):
        registry.discover_scanner_plugins()


def test_registry_rejects_manifest_without_package_local_implementation(
    tmp_path, monkeypatch
):
    payload = {
        "schema_version": 1,
        "id": "missing",
        "module": "repoauditor.detect.deterministic.plugins.missing",
        "adapter_factory": "create_adapter",
        "canary_runner": "run_canary",
        "target_count_bases": ["scanner-reported-files"],
    }
    (tmp_path / "missing.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(registry, "_plugin_root", lambda: tmp_path)
    plugin = registry.discover_scanner_plugins()[0]

    with pytest.raises(RuntimeError, match="missing or unsafe"):
        registry._load_symbol(plugin, "adapter_factory")
