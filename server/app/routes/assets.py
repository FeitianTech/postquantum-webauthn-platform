"""What browsers load of the MDS snapshot, at ``/assets/mds/``.

- The explorer's files derived from the snapshot (``mds/explorer_files.py``,
  kept by ``cache.load_explorer_files``): the list at one URL, revalidated by
  its ETag, so the page fetches it without asking anything first; each icon,
  named by its digest and so immutable; each entry's detail, immutable at the
  version its URL names.
- The explorer's full file, at ``fido-mds3.explorer.full.json?v=<version>``,
  where the version names the snapshot (``explorer_files.snapshot_version``): a
  URL with the current version is cached as immutable, any other revalidates.

No other snapshot file is served, at any path.
"""
from __future__ import annotations

import os

from flask import Blueprint, Flask, Response, abort, request

from ..mds import cache as mds_cache
from ..mds import explorer_files as mds_explorer_files
from ..mds import files as mds_files
from ..mds import provisioning as mds_provisioning
from . import web_export

# The path segment of the snapshot's URL; no other segment is served.
_ASSET_SEGMENT = "mds"

# Of the MDS snapshot's files (and the .gz sibling written next to the browsers'
# copy), browsers get only that copy, at its versioned URL, from the snapshot
# directory: no route serves the rest, nor any of them at the site root.
_SNAPSHOT_FILES = frozenset(mds_files.SNAPSHOT_FILENAMES) | frozenset(
    f"{name}.gz" for name in mds_files.BROWSER_FILENAMES
)


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
    if filename not in mds_files.BROWSER_FILENAMES:
        abort(404)

    # On a cold instance the snapshot may still be being provisioned: wait for that
    # (after the first attempt it returns at once).
    mds_provisioning.ensure_snapshot_available()
    path = os.fspath(mds_files.snapshot_file(filename))
    if not os.path.isfile(path):
        abort(404)

    # Only the current snapshot's URL is immutable; a page given an earlier one
    # must revalidate.
    current = mds_explorer_files.snapshot_version(mds_cache.load_packaged_snapshot_meta())
    if current is not None and request.args.get("v") == current:
        return web_export.send_precompressed(path, web_export.IMMUTABLE_CACHE_CONTROL)
    return web_export.send_precompressed(path, web_export.REVALIDATE_CACHE_CONTROL)


# A navigated icon (an SVG opened in a tab) runs nothing and loads nothing.
_ICON_POLICY = "default-src 'none'; style-src 'unsafe-inline'; sandbox"


def _explorer_files() -> mds_explorer_files.ExplorerFiles:
    # On a cold instance the snapshot may still be being provisioned: wait for it.
    mds_provisioning.ensure_snapshot_available()
    files = mds_cache.load_explorer_files()
    if files is None:
        abort(404)
    return files


@bp.route(f"{mds_explorer_files.URL_PREFIX}/{mds_explorer_files.LIST_FILENAME}")
def explorer_list():
    """The list, gzipped for a client that takes it; its ETag names the files'
    version and the encoding, so a page loading it again gets a 304."""

    files = _explorer_files()
    gzipped = "gzip" in request.headers.get("Accept-Encoding", "").lower()
    response = Response(files.list_gzip if gzipped else files.list_json, mimetype="application/json")
    if gzipped:
        response.headers["Content-Encoding"] = "gzip"
    response.vary.add("Accept-Encoding")
    response.set_etag(f"{files.version}.gz" if gzipped else files.version)
    response.headers["Cache-Control"] = web_export.REVALIDATE_CACHE_CONTROL
    return response.make_conditional(request)


@bp.route(f"{mds_explorer_files.URL_PREFIX}/{mds_explorer_files.ICON_DIRECTORY}/<name>")
def explorer_icon(name: str):
    icon = _explorer_files().icons.get(name)
    if icon is None:
        abort(404)
    response = Response(icon.data, mimetype=icon.mimetype)
    response.headers["Cache-Control"] = web_export.IMMUTABLE_CACHE_CONTROL
    response.headers["Content-Security-Policy"] = _ICON_POLICY
    response.set_etag(name)
    return response.make_conditional(request)


@bp.route(f"{mds_explorer_files.URL_PREFIX}/{mds_explorer_files.ENTRY_DIRECTORY}/<path:entry_id>")
def explorer_entry(entry_id: str):
    """An entry's detail; immutable at the version its URL names, revalidated at
    any other (a page that loaded the list before a newer snapshot)."""

    files = _explorer_files()
    detail = files.details.get(entry_id)
    if detail is None:
        abort(404)
    response = Response(detail, mimetype="application/json")
    current = request.args.get("v") == files.version
    response.headers["Cache-Control"] = (
        web_export.IMMUTABLE_CACHE_CONTROL if current else web_export.REVALIDATE_CACHE_CONTROL
    )
    return response

