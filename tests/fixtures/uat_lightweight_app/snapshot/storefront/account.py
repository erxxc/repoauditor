"""Account settings.

Signed-in routes for a customer's own account preferences. These endpoints only ever
read and write the caller's own session/profile state.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request, session

from .security import current_customer_id

account_bp = Blueprint("account", __name__)


@account_bp.route("/account/return-target", methods=["POST"])
def set_return_target():
    """Remember where to send the customer after the next re-authentication.

    The single-page frontend posts a ``next`` path here before starting a step-up auth
    flow, then reads ``return_target`` back afterwards to resume navigation. The value is
    stored on the session and echoed back; the backend itself never issues a redirect to
    it. Whether it is safe depends entirely on how the frontend consumes it.
    """
    current_customer_id()
    nxt = request.form.get("next", "/account")
    session["return_target"] = nxt
    return jsonify({"return_target": nxt})


@account_bp.route("/account/profile")
def profile():
    """Return the signed-in customer's own profile."""
    from . import db

    customer_id = current_customer_id()
    row = db.query_one(
        "SELECT id, email, full_name FROM customers WHERE id = ?", (customer_id,)
    )
    return jsonify(dict(row) if row else {})
