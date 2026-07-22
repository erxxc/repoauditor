"""Admin integrations tooling.

Admin-only helpers for the merchandising team. The link-preview tool fetches a URL so
the admin UI can show a thumbnail/preview of an off-site product link before it is
added to the catalog.
"""

from __future__ import annotations

import requests
from flask import Blueprint, jsonify, request

from .security import require_admin

integrations_bp = Blueprint("integrations", __name__)


@integrations_bp.route("/admin/link-preview")
def link_preview():
    """Fetch a URL server-side and return a small preview of the response.

    Admin-gated, but the destination comes straight from the caller and is fetched by
    the server itself, which is reachable from inside the deployment network.
    """
    require_admin()
    target = request.args.get("url", "")

    resp = requests.get(target, timeout=5)
    return jsonify(
        {
            "url": target,
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type"),
            "preview": resp.text[:2000],
        }
    )
