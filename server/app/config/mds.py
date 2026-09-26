"""Where the FIDO MDS comes from and where the per-session metadata uploads live.

The snapshot's own files are found through ``server.app.mds_snapshot_dir``
(``FIDO_SERVER_MDS_SNAPSHOT_DIR``), which the updater shares without Flask.
"""
from __future__ import annotations

import os

from .. import mds_snapshot_dir
from .paths import _SERVER_RUNTIME_ROOT

MDS_METADATA_URL = "https://mds3.fidoalliance.org/"
MDS_METADATA_FILENAME = mds_snapshot_dir.BLOB
SESSION_METADATA_DIR = os.environ.get(
    "FIDO_SERVER_SESSION_METADATA_DIR",
    os.path.join(str(_SERVER_RUNTIME_ROOT), "session-metadata"),
)
