"""Where the FIDO MDS snapshot and the per-session metadata uploads live.

``create_app()`` applies ``FIDO_SERVER_SESSION_METADATA_RECOVER`` to
``app.config["SESSION_METADATA_RECOVER_ON_START"]`` when it is set.
"""
from __future__ import annotations

import os
from typing import Any

from ..env_flags import parse_env_flag
from .paths import _FRONTEND_STATIC_ROOT, _SERVER_RUNTIME_ROOT


def config_from_env() -> dict[str, Any]:
    """The session-metadata setting ``create_app()`` puts into ``app.config``, if set."""

    recover = parse_env_flag("FIDO_SERVER_SESSION_METADATA_RECOVER")
    if recover is None:
        return {}
    return {"SESSION_METADATA_RECOVER_ON_START": recover}


MDS_METADATA_URL = "https://mds3.fidoalliance.org/"
MDS_METADATA_FILENAME = "blob.jwt"
MDS_METADATA_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), MDS_METADATA_FILENAME)
MDS_METADATA_VERIFIED_PATH = os.path.join(
    str(_FRONTEND_STATIC_ROOT), "fido-mds3.verified.json"
)
MDS_METADATA_CACHE_PATH = MDS_METADATA_VERIFIED_PATH + ".meta.json"
MDS_EXPLORER_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), "fido-mds3.explorer.json")
MDS_EXPLORER_META_PATH = MDS_EXPLORER_PATH + ".meta.json"
# Explorer snapshot with inline details, served to browsers as a static file.
MDS_EXPLORER_FULL_PATH = os.path.join(
    str(_FRONTEND_STATIC_ROOT), "fido-mds3.explorer.full.json"
)
SESSION_METADATA_DIR = os.environ.get(
    "FIDO_SERVER_SESSION_METADATA_DIR",
    os.path.join(str(_SERVER_RUNTIME_ROOT), "session-metadata"),
)
