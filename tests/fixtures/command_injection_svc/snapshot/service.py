"""Intentionally vulnerable fixture service — ground truth for the golden harness.

Do NOT fix these vulnerabilities: they are the known-bad corpus the eval harness
measures precision/recall against. Each corresponds to an entry in the sibling
`expected_findings.json`.
"""

import os

from flask import Flask, request

app = Flask(__name__)

# Vuln 1: hardcoded database credential.
DB_PASSWORD = "hunter2-prod-db-password"


@app.route("/ping")
def ping():
    # Vuln 2: command injection — user input concatenated into a shell command.
    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()
