"""The site's pages: the new UI's Next.js static export in ``web/out`` (docs/UI_MIGRATION.md).

- ``/`` answers ``index.html``; ``/design`` answers ``design.html`` (the export
  writes one HTML file per page).
- ``/_next/static/...`` holds content-hashed files: cached for a year,
  immutable, with the build-time ``.gz`` copy when there is one.
- Everything else, the HTML above all, is revalidated (``no-cache``), so a
  deploy is seen at once.
- An unknown path answers 404 with the export's own ``404.html``; with no
  export at all, Werkzeug's plain 404. A path under ``/api/`` that no route
  holds answers the plain 404, as an API should.
- ``/beta`` and every ``/beta/...`` path, where the new UI was reviewed before
  the cutover (Phase 30), answer a permanent redirect (308) to the same path at
  ``/`` with its query; the browser keeps the ``#hash``. The redirect is
  revalidated like the pages, so a browser does not hold it past a rollback.

The page rule is the site's catch-all, as Flask's own static rule was before it
(``config/application.py`` no longer adds one): Werkzeug tries every rule with a
static segment first (``/health``, ``/api/...``, ``/assets/...``, ``/beta...``),
and a method no other rule takes falls through to it and is refused, as before.

The app's ``after_request`` handlers give these answers the same security
headers as every other response, the strict CSP included. The export root is
``app.config["WEB_EXPORT_ROOT"]`` (``config/web_export.py``).
"""
from __future__ import annotations

import os

from flask import Blueprint, abort, current_app, redirect, request, send_file, url_for
from werkzeug.security import safe_join

from ..config.web_export import WEB_EXPORT_ROOT_KEY
from ..static_assets import (
    IMMUTABLE_CACHE_CONTROL,
    REVALIDATE_CACHE_CONTROL,
    send_precompressed,
)

__all__ = ["bp"]

bp = Blueprint("web_export", __name__)

_IMMUTABLE_PREFIX = "_next/static/"
# The export's error pages are served as errors, never as a page of their own.
_ERROR_PAGES = frozenset({"404", "404.html", "500", "500.html"})


def _file(root: str, relative: str) -> str | None:
    path = safe_join(root, relative)
    return path if path is not None and os.path.isfile(path) else None


def _not_found(root: str):
    page = _file(root, "404.html")
    if page is None:
        abort(404)
    # Not conditional: a 404 never becomes a 304 or a range.
    response = send_file(page, mimetype="text/html", conditional=False, etag=False)
    response.status_code = 404
    response.headers["Cache-Control"] = REVALIDATE_CACHE_CONTROL
    return response


@bp.route("/")
@bp.route("/<path:subpath>")
def page(subpath: str = ""):
    if subpath == "api" or subpath.startswith("api/"):
        abort(404)
    root = str(current_app.config[WEB_EXPORT_ROOT_KEY])
    if not os.path.isdir(root):
        abort(404)

    relative = subpath or "index.html"
    if relative in _ERROR_PAGES:
        return _not_found(root)
    path = _file(root, relative)
    if path is None and not relative.endswith((".html", "/")):
        path = _file(root, f"{relative}.html")
    if path is None:
        return _not_found(root)

    if relative.startswith(_IMMUTABLE_PREFIX):
        return send_precompressed(path, IMMUTABLE_CACHE_CONTROL)
    return send_precompressed(path, REVALIDATE_CACHE_CONTROL)


@bp.route("/beta")
@bp.route("/beta/")
@bp.route("/beta/<path:subpath>")
def beta(subpath: str = ""):
    # Built by url_for, never by joining text: each segment is quoted, and no
    # leading slash is kept, so no path (a tab, a backslash, a second slash) can
    # make the target another origin's URL.
    subpath = subpath.lstrip("/")
    location = url_for("web_export.page", subpath=subpath) if subpath else url_for("web_export.page")
    if request.query_string:
        location = f"{location}?{request.query_string.decode('latin-1')}"
    response = redirect(location, code=308)
    response.headers["Cache-Control"] = REVALIDATE_CACHE_CONTROL
    return response
