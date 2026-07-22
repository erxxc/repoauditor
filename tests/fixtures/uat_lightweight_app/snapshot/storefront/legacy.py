"""Legacy bulk-import endpoint — retired, kept for reference only.

This blueprint is intentionally NOT registered by the application factory
(``storefront/__init__.py``), so none of its routes are wired into the running app. It
also self-guards behind ``ENABLE_LEGACY_IMPORT``, which is permanently off. The old
shell-based importer below is therefore dead code: it cannot be reached from any entry
point. It is preserved so the migration to the current catalog importer stays documented.
"""

from __future__ import annotations

import os

from flask import Blueprint, abort, request

legacy_bp = Blueprint("legacy", __name__)

# Permanently disabled. The shell importer was replaced by the streaming catalog loader;
# this flag is never turned back on.
ENABLE_LEGACY_IMPORT = False


@legacy_bp.route("/legacy/import", methods=["POST"])
def legacy_import():
    """Historical bulk importer that shelled out to a fetch-and-load pipeline.

    Unreachable: the blueprint is never registered, and this handler additionally returns
    404 unless ``ENABLE_LEGACY_IMPORT`` is true, which it never is.
    """
    if not ENABLE_LEGACY_IMPORT:
        abort(404)

    source = request.form["source"]
    os.system("curl -s " + source + " | psql storefront -c 'COPY products FROM STDIN'")
    return "import started"
