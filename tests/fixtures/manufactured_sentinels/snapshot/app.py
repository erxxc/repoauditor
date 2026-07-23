from urllib.parse import urlparse

import requests
from flask import request


def unsafe_search(db):
    term = request.args.get("q")
    sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    return db.execute(sql).fetchall()


def safe_search(db):
    term = request.args.get("q")
    return db.execute(
        "SELECT * FROM products WHERE name LIKE ?",
        (f"%{term}%",),
    ).fetchall()


def unsafe_preview():
    target = request.args.get("url")
    return requests.get(target, timeout=2).text


def safe_preview():
    target = request.args.get("url")
    parsed = urlparse(target)
    if parsed.scheme != "https" or parsed.hostname not in {"docs.example.test"}:
        raise ValueError("unapproved preview host")
    return requests.get(target, timeout=2).text
