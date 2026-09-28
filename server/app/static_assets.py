"""Versioned, long-lived caching for frontend static assets.

Asset URLs carry a build id in their path (``/assets/<build id>/scripts/main.js``)
so browsers can cache them indefinitely. ES module imports and CSS ``@import``
rules are relative, so every file a page loads inherits the same prefix and a
deploy never mixes old and new files.
"""
from __future__ import annotations

import mimetypes
import os

from flask import Blueprint, Flask, abort, request, send_file
from werkzeug.security import safe_join

from . import mds_snapshot_dir
from .config import _FRONTEND_ROOT, _FRONTEND_STATIC_ROOT
from .mds_provisioning import ensure_snapshot_available

__all__ = ["BUILD_ID", "asset_url", "bp", "init_app", "send_precompressed"]

_BUILD_ID_ENV = "FIDO_SERVER_BUILD_ID"
_DEV_BUILD_ID = "dev"
IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"
REVALIDATE_CACHE_CONTROL = "no-cache"

# Of the MDS snapshot's files (and the .gz sibling the provisioning writes next to
# the browsers' copy), browsers get only that copy, at its versioned URL, from the
# snapshot directory. frontend/static is only the default directory: what sits
# there may be another snapshot, so no route serves the rest, nor any of them at
# the site root.
_SNAPSHOT_FILES = frozenset(mds_snapshot_dir.SNAPSHOT_FILENAMES) | frozenset(
    f"{name}.gz" for name in mds_snapshot_dir.BROWSER_FILENAMES
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


def _is_snapshot_file(filename: str) -> bool:
    return filename.strip("/") in _SNAPSHOT_FILES


def _hide_private_static_files():
    if _is_snapshot_file(request.path):
        abort(404)
    return None


bp = Blueprint("static_assets", __name__)


def init_app(app: Flask) -> None:
    """Serve versioned assets and hide the MDS snapshot files.

    The hook is registered on the app, not the blueprint, because a snapshot file
    at the site root would otherwise reach the page rule (``routes/web_export.py``).
    """

    app.before_request(_hide_private_static_files)
    app.register_blueprint(bp)


@bp.route("/assets/<build_id>/<path:filename>")
def versioned_static_asset(build_id: str, filename: str):
    if _is_snapshot_file(filename) and filename not in mds_snapshot_dir.BROWSER_FILENAMES:
        abort(404)

    # The snapshot the page loads is wherever the snapshot directory is
    # (server.app.mds_snapshot_dir); every other asset is in frontend/static. On
    # a cold instance it may still be being provisioned: wait for that (only
    # this file waits; after the first attempt it returns at once).
    root = _STATIC_ROOT
    if filename in mds_snapshot_dir.BROWSER_FILENAMES:
        ensure_snapshot_available()
        root = os.fspath(mds_snapshot_dir.snapshot_dir())
    path = safe_join(root, filename)
    if path is None or not os.path.isfile(path):
        abort(404)

    # Only the current build's URLs are immutable; a page from a previous
    # deploy may still request its own build id and must revalidate.
    if build_id == BUILD_ID and BUILD_ID != _DEV_BUILD_ID:
        return send_precompressed(path, IMMUTABLE_CACHE_CONTROL)
    return send_precompressed(path, REVALIDATE_CACHE_CONTROL)


def send_precompressed(path: str, cache_control: str):
    """Send ``path``, or its build-time ``.gz`` copy when the client accepts gzip.

    Conditional (ETag, 304) like any static file. ``Vary: Accept-Encoding`` is
    added whenever a ``.gz`` copy exists, so a cache keeps both.
    """

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
    response.headers["Cache-Control"] = cache_control
    return response
