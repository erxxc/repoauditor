"""Public product catalog.

Unauthenticated storefront routes for browsing and searching products. These sit at the
internet-facing edge — no session is required to reach them.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from . import db

catalog_bp = Blueprint("catalog", __name__)


@catalog_bp.route("/products")
def list_products():
    """List the catalog, most recent first."""
    rows = db.query("SELECT id, name, category, price FROM products ORDER BY id DESC LIMIT 100")
    return jsonify([dict(r) for r in rows])


@catalog_bp.route("/products/search")
def search_products():
    """Full-text-ish product search by name, with an optional category filter.

    Reachable anonymously from the public edge; both parameters come straight off the
    query string and are woven into the SQL that runs against the customer database.
    """
    term = request.args.get("q", "")
    category = request.args.get("category", "")

    sql = "SELECT id, name, category, price FROM products WHERE name LIKE '%" + term + "%'"
    if category:
        sql += " AND category = '" + category + "'"
    sql += " ORDER BY name"

    rows = db.query(sql)
    return jsonify([dict(r) for r in rows])
