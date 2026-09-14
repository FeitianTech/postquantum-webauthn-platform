"""Versioned, long-lived caching for frontend static assets.

Asset URLs carry a build id in their path (``/assets/<build id>/scripts/main.js``)
so browsers can cache them indefinitely. ES module imports and CSS ``@import``
rules are relative, so every file a page loads inherits the same prefix and a
deploy never mixes old and new files.
"""
from __future__ import annotations

import mimetypes
import os

from flask import abort, request, send_file
from werkzeug.security import safe_join

from .config import _FRONTEND_ROOT, _FRONTEND_STATIC_ROOT, app

__all__ = ["BUILD_ID", "asset_url"]

_BUILD_ID_ENV = "FIDO_SERVER_BUILD_ID"
_DEV_BUILD_ID = "dev"
_IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"
_REVALIDATE_CACHE_CONTROL = "no-cache"

# Large MDS source files the server reads from disk but browsers never request.
_PRIVATE_STATIC_FILES = frozenset(
    {
        "blob.jwt",
        "fido-mds3.verified.json",
        "fido-mds3.explorer.json",
    }
)

_STATIC_ROOT = str(_FRONTEND_STATIC_ROOT)


def _resolve_build_id() -> str:
    explicit = (os.environ.get(_BUILD_ID_ENV) or "").strip()
    if explicit:
        return explicit
    try:
        with open(_FRONTEND_ROOT / "BUILD_ID", "r", encoding="utf-8") as handle:
            value = handle.read().strip()
    except OSError:
        return _DEV_BUILD_ID
    return value or _DEV_BUILD_ID


BUILD_ID = _resolve_build_id()


def asset_url(filename: str) -> str:
    """Return the versioned URL for a file under ``frontend/static``."""

    return f"/assets/{BUILD_ID}/{filename.lstrip('/')}"


app.jinja_env.globals["asset_url"] = asset_url


def _is_private_static_file(filename: str) -> bool:
    return filename.strip("/") in _PRIVATE_STATIC_FILES


@app.before_request
def _hide_private_static_files():
    if _is_private_static_file(request.path):
        abort(404)
    return None


@app.route("/assets/<build_id>/<path:filename>")
def versioned_static_asset(build_id: str, filename: str):
    if _is_private_static_file(filename):
        abort(404)

    path = safe_join(_STATIC_ROOT, filename)
    if path is None or not os.path.isfile(path):
        abort(404)

    mimetype = mimetypes.guess_type(path)[0] or "application/octet-stream"
    gzip_path = f"{path}.gz"
    has_gzip_variant = os.path.isfile(gzip_path)
    use_gzip = has_gzip_variant and "gzip" in request.headers.get("Accept-Encoding", "").lower()

    response = send_file(
        gzip_path if use_gzip else path,
        mimetype=mimetype,
        conditional=True,
        etag=True,
    )
    if use_gzip:
        response.headers["Content-Encoding"] = "gzip"
    if has_gzip_variant:
        response.vary.add("Accept-Encoding")

    # Only the current build's URLs are immutable; a page from a previous
    # deploy may still request its own build id and must revalidate.
    if build_id == BUILD_ID and BUILD_ID != _DEV_BUILD_ID:
        response.headers["Cache-Control"] = _IMMUTABLE_CACHE_CONTROL
    else:
        response.headers["Cache-Control"] = _REVALIDATE_CACHE_CONTROL
    return response
