"""Cross-site writes to the API, refused by what the browser says of them.

The session and namespace cookies are ``SameSite=Lax``, so a cross-site POST
carries neither; but a page on a sibling subdomain is same-site, and the metadata
upload is a form any page can post. A browser names where each request comes from
in ``Sec-Fetch-Site``: a request under ``/api/`` that may change something (any
method but GET, HEAD and OPTIONS) is refused unless it comes from this origin
(``same-origin``) or from no page at all (``none``). The CSP reports are the
browser's own and stay open. A request without the header is let through: it
comes from no browser, or from one older than Fetch Metadata, which cannot run
the ceremonies (they need WebAuthn's JSON methods).
"""
from __future__ import annotations

from typing import Any

from flask import Flask, jsonify, request

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_ALLOWED_SITES = frozenset({"same-origin", "none"})
_OPEN_PATHS = frozenset({"/api/csp-report"})
REFUSED = "Requests from another site may not change anything here."


def _refuse_cross_site_write() -> Any:
    if request.method in _SAFE_METHODS or not request.path.startswith("/api/") or request.path in _OPEN_PATHS:
        return None
    site = request.headers.get("Sec-Fetch-Site")
    if site is None or site.strip().lower() in _ALLOWED_SITES:
        return None
    return jsonify({"error": REFUSED}), 403


def init_app(app: Flask) -> None:
    """Refuse a cross-site write before any route reads it."""

    app.before_request(_refuse_cross_site_write)
