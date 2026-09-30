"""Where the per-session metadata uploads live.

The MDS snapshot's own files are found through ``server.app.mds.files``
(``FIDO_SERVER_MDS_SNAPSHOT_DIR``), which the updater shares without Flask.
"""
from __future__ import annotations

from .paths import store_dir


def session_metadata_dir() -> str:
    return store_dir("FIDO_SERVER_SESSION_METADATA_DIR", "session-metadata")
