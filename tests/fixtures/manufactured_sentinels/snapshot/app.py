import requests
from flask import request

_ALLOWED_PREVIEWS = {
    "help": "https://docs.example.test/help",
}


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
    page = request.args.get("page")
    target = _ALLOWED_PREVIEWS.get(page)
    if target is None:
        raise ValueError("unknown preview page")
    return requests.get(target, timeout=2, allow_redirects=False).text
