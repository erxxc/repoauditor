"""Customer order history.

Signed-in routes for viewing a customer's orders. Authentication is required (a session
must exist), but each handler is responsible for its own object-level authorization.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, abort

from . import db
from .security import current_customer_id
from .models import Order

orders_bp = Blueprint("orders", __name__)


@orders_bp.route("/orders")
def list_my_orders():
    """List the signed-in customer's own orders."""
    customer_id = current_customer_id()
    rows = db.query(
        "SELECT id, customer_id, total, placed_at FROM orders WHERE customer_id = ? "
        "ORDER BY placed_at DESC",
        (customer_id,),
    )
    return jsonify([dict(r) for r in rows])


@orders_bp.route("/orders/<int:order_id>")
def get_order(order_id: int):
    """Return a single order by id.

    Requires a signed-in session and looks the order up by its primary key. The lookup
    is parameterized, so it is not an injection surface.
    """
    current_customer_id()  # ensure the caller is authenticated
    row = db.query_one(
        "SELECT id, customer_id, total, placed_at FROM orders WHERE id = ?", (order_id,)
    )
    if row is None:
        abort(404)
    return jsonify(vars(Order.from_row(row)))
