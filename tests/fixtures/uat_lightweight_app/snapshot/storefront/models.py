"""Lightweight row -> object mappers for the storefront domain.

Plain dataclasses over ``sqlite3.Row`` so route handlers can return typed objects
without pulling in a full ORM.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass


@dataclass
class Customer:
    id: int
    email: str
    full_name: str
    shipping_address: str | None
    card_last4: str | None
    is_admin: bool

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Customer":
        return cls(
            id=row["id"],
            email=row["email"],
            full_name=row["full_name"],
            shipping_address=row["shipping_address"],
            card_last4=row["card_last4"],
            is_admin=bool(row["is_admin"]),
        )


@dataclass
class Product:
    id: int
    name: str
    category: str
    price: float

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Product":
        return cls(id=row["id"], name=row["name"], category=row["category"], price=row["price"])


@dataclass
class Order:
    id: int
    customer_id: int
    total: float
    placed_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Order":
        return cls(
            id=row["id"],
            customer_id=row["customer_id"],
            total=row["total"],
            placed_at=row["placed_at"],
        )


@dataclass
class Invoice:
    id: int
    customer_id: int
    order_id: int
    pdf_path: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Invoice":
        return cls(
            id=row["id"],
            customer_id=row["customer_id"],
            order_id=row["order_id"],
            pdf_path=row["pdf_path"],
        )
