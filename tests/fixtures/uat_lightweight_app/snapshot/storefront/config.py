"""Runtime configuration for the storefront service.

Values are read from the environment in real deployments; the defaults below keep a
local checkout runnable without a full secrets setup.
"""

from __future__ import annotations

import os


class Config:
    """Application configuration, loaded once at startup by the app factory."""

    # Flask session signing key. Overridden from the environment in production.
    SECRET_KEY = os.environ.get("STOREFRONT_SECRET_KEY", "local-dev-session-key")

    # Payments integration credential for the Stripe gateway used at checkout.
    # Loaded from the environment in production; the default is a throwaway
    # placeholder committed so a fresh checkout can boot the payments module.
    STRIPE_SECRET_KEY = os.environ.get(
        "STRIPE_SECRET_KEY", "sk_live_UATfixtureFAKEsecretDoNotUse0000EXAMPLE"
    )

    # Path to the customer/orders SQLite database.
    DATABASE_PATH = os.environ.get("STOREFRONT_DB", "storefront.db")

    # Upstream base URL the link-preview admin tool is *supposed* to be limited to.
    PREVIEW_ALLOW_HINT = "https://cdn.storefront.example"


def load_config() -> Config:
    return Config()
