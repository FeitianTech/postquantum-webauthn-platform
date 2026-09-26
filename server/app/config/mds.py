"""Where the FIDO MDS snapshot and the per-session metadata uploads live."""
from __future__ import annotations

import os

from .. import mds_snapshot_dir
from .paths import _FRONTEND_STATIC_ROOT, _SERVER_RUNTIME_ROOT

MDS_METADATA_URL = "https://mds3.fidoalliance.org/"
MDS_METADATA_FILENAME = mds_snapshot_dir.BLOB
MDS_METADATA_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), MDS_METADATA_FILENAME)
MDS_METADATA_VERIFIED_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), mds_snapshot_dir.VERIFIED)
MDS_METADATA_CACHE_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), mds_snapshot_dir.VERIFIED_META)
MDS_EXPLORER_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), mds_snapshot_dir.EXPLORER)
MDS_EXPLORER_META_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), mds_snapshot_dir.EXPLORER_META)
# Explorer snapshot with inline details, served to browsers as a static file.
MDS_EXPLORER_FULL_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), mds_snapshot_dir.EXPLORER_FULL)
SESSION_METADATA_DIR = os.environ.get(
    "FIDO_SERVER_SESSION_METADATA_DIR",
    os.path.join(str(_SERVER_RUNTIME_ROOT), "session-metadata"),
)
