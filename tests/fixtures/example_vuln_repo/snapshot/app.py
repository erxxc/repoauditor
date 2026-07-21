"""Intentionally vulnerable fixture app — ground truth for the golden harness.

Do NOT fix these vulnerabilities: they are the known-bad corpus the eval harness
measures precision/recall against. Each corresponds to an entry in the sibling
`expected_findings.json`.
"""

import sqlite3

import requests
from flask import Flask, request

app = Flask(__name__)

# Vuln 1: hardcoded secret (line ~17).
API_TOKEN = "sk_live_51H8xExampleHardcodedSecretDoNotUse0000"


@app.route("/user")
def get_user():
    # Vuln 2: SQL injection — user input concatenated into the query (line ~24).
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT * FROM users WHERE id = " + user_id).fetchall()
    return {"rows": rows}


@app.route("/fetch")
def fetch():
    # Vuln 3: SSRF — user-controlled URL fetched server-side (line ~33).
    url = request.args.get("url")
    return requests.get(url).text
