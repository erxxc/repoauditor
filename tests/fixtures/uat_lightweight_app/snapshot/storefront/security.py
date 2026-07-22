"""Authentication and authorization helpers.

Session-cookie auth: a signed-in customer's id lives in ``session["customer_id"]``.
The ``owns_resource`` decorator is the shared ownership gate used by routes that expose
a customer-scoped record by id — it loads the record and rejects the request unless it
belongs to the caller. Routes that forget to apply it (or an equivalent inline check)
are the classic broken-object-level-authorization bug.
"""

from __future__ import annotations

import functools
from typing import Callable

from flask import abort, session

from . import db


def current_customer_id() -> int:
    """Return the signed-in customer's id, or 401 if there is no session."""
    customer_id = session.get("customer_id")
    if customer_id is None:
        abort(401)
    return int(customer_id)


def require_admin() -> None:
    """Abort with 403 unless the signed-in customer has the admin flag set."""
    customer_id = current_customer_id()
    row = db.query_one("SELECT is_admin FROM customers WHERE id = ?", (customer_id,))
    if row is None or not row["is_admin"]:
        abort(403)


# Fully static ownership lookups per resource kind, plus the id-column route argument.
# The SQL is a constant literal per kind (no interpolation) and the id is bound as a
# parameter, so this gate is not itself an injection surface.
_OWNERSHIP_SQL = {
    "order": ("SELECT customer_id FROM orders WHERE id = ?", "order_id"),
    "invoice": ("SELECT customer_id FROM invoices WHERE id = ?", "invoice_id"),
}


def owns_resource(kind: str) -> Callable:
    """Decorator enforcing that the caller owns the addressed resource.

    Loads the row named by the route's id argument and compares its ``customer_id`` to
    the signed-in customer, returning 404 if it is missing and 403 if it belongs to
    someone else. This is the mitigating control the ``orders`` blueprint fails to use.
    """
    sql, arg = _OWNERSHIP_SQL[kind]

    def decorator(view: Callable) -> Callable:
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            resource_id = kwargs[arg]
            row = db.query_one(sql, (resource_id,))
            if row is None:
                abort(404)
            if row["customer_id"] != current_customer_id():
                abort(403)
            return view(*args, **kwargs)

        return wrapper

    return decorator
