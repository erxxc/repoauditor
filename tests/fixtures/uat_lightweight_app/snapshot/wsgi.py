"""WSGI entry point for the storefront service.

This module exposes ``app`` for a WSGI server, but it will NOT start a server on its
own. The storefront is a static analysis fixture and is intentionally insecure; it must
never be exposed to real data or a reachable network. Merely importing this module is
side-effect free (it builds the Flask app object and nothing else — no sockets, no DB
writes).

If you deliberately want a LOCAL-ONLY instance for manual inspection, set
``STOREFRONT_ALLOW_RUN=1``; it will then bind to loopback only, with the debugger off.
"""

from __future__ import annotations

import os
import sys

from storefront import create_app

app = create_app()


def _refuse_to_serve() -> None:
    sys.stderr.write(
        "storefront is an intentionally-insecure analysis fixture and does not self-serve.\n"
        "Do not expose it to real data or a reachable network. For a local-only instance,\n"
        "re-run with STOREFRONT_ALLOW_RUN=1 (binds 127.0.0.1 only, debugger disabled).\n"
    )


if __name__ == "__main__":
    if os.environ.get("STOREFRONT_ALLOW_RUN") != "1":
        _refuse_to_serve()
        raise SystemExit(1)
    # Loopback only; debugger disabled. A fixture must never bind a public interface
    # or enable the Werkzeug interactive console.
    app.run(host="127.0.0.1", port=8000, debug=False)
