"""The MDS explorer's snapshot as a versioned static asset.

Browsers load one file of the MDS snapshot, the explorer's, from
``/assets/mds/fido-mds3.explorer.full.json?v=<version>``, where the version
names the snapshot (``snapshot_version``): a URL with the current version is cached
as immutable, any other revalidates. No other snapshot file is served, at any path.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any
from urllib.parse import quote

from flask import Blueprint, Flask, abort, request

from .. import mds_provisioning, mds_snapshot_dir
from ..webauthn.metadata import blob as metadata_blob
from . import web_export

# The path segment of the snapshot's URL; no other segment is served.
_ASSET_SEGMENT = "mds"

# Of the MDS snapshot's files (and the .gz sibling written next to the browsers'
# copy), browsers get only that copy, at its versioned URL, from the snapshot
# directory: no route serves the rest, nor any of them at the site root.
_SNAPSHOT_FILES = frozenset(mds_snapshot_dir.SNAPSHOT_FILENAMES) | frozenset(
    f"{name}.gz" for name in mds_snapshot_dir.BROWSER_FILENAMES
)


def snapshot_version(meta: dict[str, Any] | None) -> str | None:
    """The version the browsers' snapshot is served under: its serial number and a
    digest of its ETag and generation time, or None without a snapshot.

    The file changes at runtime (Cloud Storage, an upstream refresh) and is cached
    for a year, so each snapshot needs a URL of its own."""

    if meta is None:
        return None
    digest = hashlib.sha256(
        json.dumps([meta.get("etag"), meta.get("generatedAt")]).encode("utf-8")
    ).hexdigest()[:12]
    return quote(f"{meta.get('no')}.{digest}", safe=".")


def asset_url(filename: str) -> str:
    """The URL of a browser file of the snapshot, without its version."""

    return f"/assets/{_ASSET_SEGMENT}/{filename.lstrip('/')}"


def _is_snapshot_file(filename: str) -> bool:
    return filename.strip("/") in _SNAPSHOT_FILES


def _hide_private_static_files():
    if _is_snapshot_file(request.path):
        abort(404)
    return None


bp = Blueprint("assets", __name__)


def init_app(app: Flask) -> None:
    """Serve the snapshot's browser file and hide the other snapshot files.

    The hook is registered on the app, not the blueprint, because a snapshot file
    at the site root would otherwise reach the page rule (``routes/web_export.py``).
    """

    app.before_request(_hide_private_static_files)
    app.register_blueprint(bp)


@bp.route(f"/assets/{_ASSET_SEGMENT}/<path:filename>")
def versioned_static_asset(filename: str):
    if filename not in mds_snapshot_dir.BROWSER_FILENAMES:
        abort(404)

    # On a cold instance the snapshot may still be being provisioned: wait for that
    # (after the first attempt it returns at once).
    mds_provisioning.ensure_snapshot_available()
    path = os.fspath(mds_snapshot_dir.snapshot_file(filename))
    if not os.path.isfile(path):
        abort(404)

    # Only the current snapshot's URL is immutable; a page given an earlier one
    # must revalidate.
    current = snapshot_version(metadata_blob.load_packaged_snapshot_meta())
    if current is not None and request.args.get("v") == current:
        return web_export.send_precompressed(path, web_export.IMMUTABLE_CACHE_CONTROL)
    return web_export.send_precompressed(path, web_export.REVALIDATE_CACHE_CONTROL)
