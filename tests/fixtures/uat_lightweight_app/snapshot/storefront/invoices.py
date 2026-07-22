"""Customer invoice access.

Structurally identical to the order-by-id route, but every invoice handler is guarded by
the shared ``owns_resource`` ownership gate so a customer can only ever read their own
invoices.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, abort

from . import db
from .security import owns_resource
from .models import Invoice

invoices_bp = Blueprint("invoices", __name__)


@invoices_bp.route("/invoices/<int:invoice_id>")
@owns_resource("invoice")
def get_invoice(invoice_id: int):
    """Return a single invoice by id.

    The ``owns_resource("invoice")`` decorator has already verified the invoice belongs
    to the signed-in customer before this body runs, so the by-id lookup is safe.
    """
    row = db.query_one(
        "SELECT id, customer_id, order_id, pdf_path FROM invoices WHERE id = ?", (invoice_id,)
    )
    if row is None:
        abort(404)
    return jsonify(vars(Invoice.from_row(row)))
