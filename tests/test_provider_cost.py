"""OPT-006 dated provider/model dollar-cost projection."""

import json
from decimal import Decimal
from pathlib import Path

from repoauditor.analyze.provider_cost import (
    PRICING_SNAPSHOT_DATE,
    PRICING_SOURCE,
    calculate_provider_cost,
)
from repoauditor.store.models import ModelUsage


def _usage(**updates):
    values = {
        "id": 1,
        "stage": "detect",
        "module": "lens",
        "prompt_version": "v1",
        "provider": "anthropic",
        "model": "claude-opus-4-8",
        "usage_available": True,
        "input_tokens": 100_000,
        "output_tokens": 10_000,
        "cache_read_tokens": 20_000,
        "cache_write_tokens": 0,
        "latency_ms": 100,
    }
    values.update(updates)
    return ModelUsage(**values)


def test_prices_exact_supported_model_usage():
    result = calculate_provider_cost([_usage()])

    assert result.status == "priced"
    assert result.usd == Decimal("0.760000")
    assert result.calls == result.priced_calls == 1
    assert result.source_checked_at == "2026-08-01"


def test_unknown_usage_or_model_makes_whole_total_unavailable():
    missing = calculate_provider_cost([_usage(usage_available=False)])
    unknown_model = calculate_provider_cost([_usage(model="unpriced-model")])

    assert missing.status == "unavailable" and missing.usd is None
    assert "no provider token metadata" in missing.detail
    assert unknown_model.status == "unavailable" and unknown_model.usd is None
    assert "no dated price" in unknown_model.detail


def test_cache_write_without_ttl_is_not_guessed():
    result = calculate_provider_cost([_usage(cache_write_tokens=10)])

    assert result.status == "unavailable" and result.usd is None
    assert "5m/1h TTL" in result.detail


def test_empty_usage_is_not_recorded():
    result = calculate_provider_cost([])

    assert result.status == "not-recorded" and result.usd is None


def test_frozen_pricing_protocol_matches_runtime_source():
    root = Path(__file__).resolve().parents[1]
    protocol = json.loads((
        root / "docs/optimizations/opt-006-provider-pricing-2026-08-01.json"
    ).read_text())

    assert protocol["source"] == PRICING_SOURCE
    assert protocol["checked_at"] == PRICING_SNAPSHOT_DATE
    price = protocol["prices"][0]
    assert price["provider"] == "anthropic"
    assert price["model"] == "claude-opus-4-8"
    assert price["input"] == 5.0 and price["output"] == 25.0
    assert price["cache_read"] == 0.5
