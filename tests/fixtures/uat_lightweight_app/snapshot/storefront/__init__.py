"""Storefront service — application factory.

A small customer-facing storefront: a public product catalog, signed-in order and
invoice history, an admin link-preview tool, and account settings. Blueprints are
registered here; the app factory has no side effects (no sockets, no DB writes), so
importing it is safe for static tooling.
"""

from __future__ import annotations

from flask import Flask

from .config import Config
from .account import account_bp
from .catalog import catalog_bp
from .integrations import integrations_bp
from .invoices import invoices_bp
from .orders import orders_bp


def create_app() -> Flask:
    """Build and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = Config.SECRET_KEY

    # Public + authenticated storefront surface.
    app.register_blueprint(catalog_bp)
    app.register_blueprint(orders_bp)
    app.register_blueprint(invoices_bp)
    app.register_blueprint(integrations_bp)
    app.register_blueprint(account_bp)

    # NOTE: `legacy_bp` (storefront/legacy.py) is deliberately not registered — the
    # legacy bulk-import endpoint was retired and is kept only for reference.

    return app
