"""What browsers load of the MDS snapshot, at ``/assets/mds/``: the explorer's
files derived from the snapshot (``mds/explorer_files.py``, kept by
``cache.load_explorer_files``).

- The list, at one URL revalidated by its ETag, so the page fetches it without
  asking anything first.
- Each icon, named by its digest, so immutable.
- Each entry's detail, immutable at the version its URL names.

No file of the snapshot directory is served, at any path.
"""
from __future__ import annotations

import hashlib

from flask import Blueprint, Flask, Response, abort, request

from ..mds import cache as mds_cache
from ..mds import explorer_files as mds_explorer_files
from ..mds import files as mds_files
from ..mds import provisioning as mds_provisioning
from . import web_export

# The snapshot's files, and the .gz copy earlier releases wrote beside the
# full one: no route serves them, nor any of them at the site root.
_SNAPSHOT_FILES = frozenset(mds_files.SNAPSHOT_FILENAMES) | {f"{mds_files.EXPLORER_FULL}.gz"}


def _is_snapshot_file(filename: str) -> bool:
    return filename.strip("/") in _SNAPSHOT_FILES


def _hide_private_static_files():
    if _is_snapshot_file(request.path):
        abort(404)
    return None


bp = Blueprint("assets", __name__)


def init_app(app: Flask) -> None:
    """Serve the explorer's files and hide the snapshot's.

    The hook is registered on the app, not the blueprint, because a snapshot file
    at the site root would otherwise reach the page rule (``routes/web_export.py``).
    """

    app.before_request(_hide_private_static_files)
    app.register_blueprint(bp)


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
    response.vary.add("Accept-Encoding")
    response.set_etag(hashlib.sha256(detail).hexdigest(), weak=True)
    return response.make_conditional(request)

