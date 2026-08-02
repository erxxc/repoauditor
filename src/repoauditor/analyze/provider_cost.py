"""Fail-closed dollar costing of authoritative provider-reported token usage."""

from __future__ import annotations

from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field

from ..store.models import ModelUsage

PRICING_SOURCE = "https://platform.claude.com/docs/en/about-claude/pricing"
PRICING_SNAPSHOT_DATE = "2026-08-01"
_MILLION = Decimal(1_000_000)


class TokenPrice(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    model: str
    input_per_million_usd: Decimal = Field(ge=0)
    output_per_million_usd: Decimal = Field(ge=0)
    cache_read_per_million_usd: Decimal = Field(ge=0)
    source: str
    source_checked_at: str


class ProviderCost(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str
    usd: Decimal | None
    calls: int
    priced_calls: int
    source: str
    source_checked_at: str
    detail: str


_PRICES = {
    ("anthropic", "claude-opus-4-8"): TokenPrice(
        provider="anthropic",
        model="claude-opus-4-8",
        input_per_million_usd=Decimal("5"),
        output_per_million_usd=Decimal("25"),
        cache_read_per_million_usd=Decimal("0.5"),
        source=PRICING_SOURCE,
        source_checked_at=PRICING_SNAPSHOT_DATE,
    ),
}


def calculate_provider_cost(rows: list[ModelUsage]) -> ProviderCost:
    """Price exact recorded usage; never estimate absent usage or unsupported modifiers."""
    if not rows:
        return ProviderCost(
            status="not-recorded", usd=None, calls=0, priced_calls=0,
            source=PRICING_SOURCE, source_checked_at=PRICING_SNAPSHOT_DATE,
            detail="no provider calls were recorded",
        )
    total = Decimal(0)
    priced = 0
    blockers: list[str] = []
    for row in rows:
        price = _PRICES.get((row.provider, row.model))
        if not row.usage_available:
            blockers.append(f"call #{row.id or '?'} has no provider token metadata")
            continue
        if price is None:
            blockers.append(f"no dated price for {row.provider}/{row.model}")
            continue
        if row.cache_write_tokens:
            blockers.append(
                f"call #{row.id or '?'} has cache-write tokens without a recorded 5m/1h TTL"
            )
            continue
        total += (
            Decimal(row.input_tokens or 0) * price.input_per_million_usd
            + Decimal(row.output_tokens or 0) * price.output_per_million_usd
            + Decimal(row.cache_read_tokens or 0) * price.cache_read_per_million_usd
        ) / _MILLION
        priced += 1
    if blockers:
        return ProviderCost(
            status="unavailable", usd=None, calls=len(rows), priced_calls=priced,
            source=PRICING_SOURCE, source_checked_at=PRICING_SNAPSHOT_DATE,
            detail="; ".join(sorted(set(blockers))),
        )
    return ProviderCost(
        status="priced", usd=total.quantize(Decimal("0.000001")), calls=len(rows),
        priced_calls=priced, source=PRICING_SOURCE,
        source_checked_at=PRICING_SNAPSHOT_DATE,
        detail="standard global Claude API token rates; excludes taxes and negotiated discounts",
    )


def render_provider_cost(cost: ProviderCost) -> str:
    if cost.usd is None:
        return f"unavailable ({cost.detail})"
    return (
        f"${cost.usd:.6f} USD ({cost.calls} call(s); prices checked "
        f"{cost.source_checked_at}; taxes/discounts excluded)"
    )
