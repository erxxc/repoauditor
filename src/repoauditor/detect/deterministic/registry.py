"""Validated package-local extension seam for deterministic scanners.

Only manifests shipped beneath ``deterministic/plugins`` are discovered. This is not a
Python entry-point or ``sys.path`` plugin system: third-party and arbitrary filesystem
loading are deliberately outside the trust boundary.
"""

from __future__ import annotations

import importlib
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Callable


_PLUGIN_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_MODULE_PREFIX = "repoauditor.detect.deterministic.plugins."
_MANIFEST_KEYS = {
    "schema_version",
    "id",
    "module",
    "adapter_factory",
    "canary_runner",
    "target_count_bases",
}
_ALLOWED_TARGET_COUNT_BASES = {
    "scanner-reported-files",
    "submitted-manifests",
    "submitted-root",
}


@dataclass(frozen=True)
class ScannerPlugin:
    id: str
    module: str
    adapter_factory: str
    canary_runner: str
    target_count_bases: tuple[str, ...]
    manifest_path: Path
    manifest_sha256: str


def _plugin_root() -> Path:
    return Path(__file__).with_name("plugins")


def discover_scanner_plugins() -> tuple[ScannerPlugin, ...]:
    """Return validated built-in plugin manifests in stable identity order."""
    root = _plugin_root().resolve()
    discovered: list[ScannerPlugin] = []
    seen: set[str] = set()
    for path in sorted(root.glob("*.json"), key=lambda item: item.name):
        if path.is_symlink() or path.resolve().parent != root:
            raise RuntimeError(f"scanner plugin manifest escapes package root: {path.name}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if set(payload) != _MANIFEST_KEYS or payload["schema_version"] != 1:
            raise RuntimeError(f"invalid scanner plugin manifest schema: {path.name}")
        plugin_id = payload["id"]
        if (
            not isinstance(plugin_id, str)
            or not _PLUGIN_ID.fullmatch(plugin_id)
            or path.stem != plugin_id
            or plugin_id in seen
        ):
            raise RuntimeError(f"invalid or duplicate scanner plugin id: {path.name}")
        module = payload["module"]
        expected_module = f"{_MODULE_PREFIX}{plugin_id}"
        if module != expected_module:
            raise RuntimeError(f"scanner plugin module is outside package seam: {path.name}")
        symbols = (payload["adapter_factory"], payload["canary_runner"])
        if not all(isinstance(item, str) and item.isidentifier() for item in symbols):
            raise RuntimeError(f"invalid scanner plugin symbol: {path.name}")
        bases = payload["target_count_bases"]
        if (
            not isinstance(bases, list)
            or not bases
            or len(bases) != len(set(bases))
            or not set(bases) <= _ALLOWED_TARGET_COUNT_BASES
        ):
            raise RuntimeError(f"invalid scanner target-count bases: {path.name}")
        seen.add(plugin_id)
        discovered.append(ScannerPlugin(
            id=plugin_id,
            module=module,
            adapter_factory=payload["adapter_factory"],
            canary_runner=payload["canary_runner"],
            target_count_bases=tuple(bases),
            manifest_path=path,
            manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        ))
    return tuple(sorted(discovered, key=lambda item: item.id))


def scanner_plugin_target_count_bases() -> MappingProxyType:
    return MappingProxyType({
        item.id: item.target_count_bases for item in discover_scanner_plugins()
    })


def _load_symbol(plugin: ScannerPlugin, attribute: str) -> Callable:
    implementation = plugin.manifest_path.with_suffix(".py")
    if (
        not implementation.is_file()
        or implementation.is_symlink()
        or implementation.resolve().parent != _plugin_root().resolve()
    ):
        raise RuntimeError(f"scanner plugin implementation is missing or unsafe: {plugin.id}")
    module = importlib.import_module(plugin.module)
    symbol_name = getattr(plugin, attribute)
    symbol = getattr(module, symbol_name, None)
    if not callable(symbol) or getattr(symbol, "__module__", None) != plugin.module:
        raise RuntimeError(f"invalid {attribute} for scanner plugin {plugin.id}")
    return symbol


def create_scanner_plugin_adapters(timeout_seconds: int) -> tuple[object, ...]:
    adapters = []
    for plugin in discover_scanner_plugins():
        adapter = _load_symbol(plugin, "adapter_factory")(timeout_seconds)
        if getattr(adapter, "tool_name", None) != plugin.id:
            raise RuntimeError(f"scanner plugin adapter identity mismatch: {plugin.id}")
        adapters.append(adapter)
    return tuple(adapters)


def scanner_plugin_canary_runners() -> MappingProxyType:
    return MappingProxyType({
        plugin.id: _load_symbol(plugin, "canary_runner")
        for plugin in discover_scanner_plugins()
    })
