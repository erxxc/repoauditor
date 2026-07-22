"""SQLite access layer for the storefront service.

This module owns the connection to the production customer database, which holds
customer PII (email, full name, shipping address, card metadata) alongside the
orders and invoices that reference it. Everything the storefront serves to a signed-in
customer ultimately resolves through this store.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from flask import g

from .config import Config

# DDL for the customer datastore. The `customers` table is the system of record for
# personal data; `orders` and `invoices` foreign-key back to a customer.
SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    full_name     TEXT NOT NULL,
    shipping_address TEXT,
    card_last4    TEXT,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS products (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL,
    category TEXT NOT NULL,
    price    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id          INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    total       REAL NOT NULL,
    placed_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invoices (
    id          INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    order_id    INTEGER NOT NULL REFERENCES orders(id),
    pdf_path    TEXT
);
"""


def get_connection() -> sqlite3.Connection:
    """Return the request-scoped connection to the customer database."""
    conn = getattr(g, "_storefront_db", None)
    if conn is None:
        conn = sqlite3.connect(Config.DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        g._storefront_db = conn
    return conn


def init_schema() -> None:
    """Create the customer datastore schema if it does not yet exist."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def query(sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    """Run a read query and return all rows."""
    cur = get_connection().execute(sql, params)
    return cur.fetchall()


def query_one(sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    cur = get_connection().execute(sql, params)
    return cur.fetchone()
