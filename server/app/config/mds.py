"""Where the per-session metadata uploads live.

The MDS snapshot's own files are found through ``server.app.mds_snapshot_dir``
(``FIDO_SERVER_MDS_SNAPSHOT_DIR``), which the updater shares without Flask.
"""
from __future__ import annotations

import os

from .paths import _SERVER_RUNTIME_ROOT

SESSION_METADATA_DIR = os.environ.get(
    "FIDO_SERVER_SESSION_METADATA_DIR",
    os.path.join(str(_SERVER_RUNTIME_ROOT), "session-metadata"),
)
