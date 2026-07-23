import requests
from flask import Flask, current_app, request

app = Flask(__name__)

_ALLOWED_PREVIEWS = {
    "help": "https://docs.example.test/help",
}


@app.get("/products/unsafe-search")
def unsafe_search():
    db = current_app.extensions["db"]
    term = request.args.get("q")
    sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    return db.execute(sql).fetchall()


@app.get("/products/safe-search")
def safe_search():
    db = current_app.extensions["db"]
    term = request.args.get("q")
    return db.execute(
        "SELECT * FROM products WHERE name LIKE ?",
        (f"%{term}%",),
    ).fetchall()


@app.get("/preview/unsafe")
def unsafe_preview():
    target = request.args.get("url")
    return requests.get(target, timeout=2).text


@app.get("/preview/safe")
def safe_preview():
    page = request.args.get("page")
    target = _ALLOWED_PREVIEWS.get(page)
    if target is None:
        raise ValueError("unknown preview page")
    return requests.get(target, timeout=2, allow_redirects=False).text
