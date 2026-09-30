"""The settings the metadata modules share, and the inactive-session cleanup's state.

A leaf: it imports nothing from ``server.app``, so any module here can depend
on it. The cleanup's entries are reached through the module
(``state._session_cleanup_worker = ...``), since a ``from ... import`` binding
cannot be rebound for other readers; the constants are safe to import by name.
The snapshot's caches are ``blob.CACHE``.
"""
from __future__ import annotations

import threading
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

_SESSION_METADATA_SUFFIX = ".json"
_SESSION_METADATA_INFO_SUFFIX = ".meta.json"
_SESSION_METADATA_SESSION_KEY = "fido.mds.session"
_SESSION_METADATA_COOKIE_NAME = "fido.mds.session"
_SESSION_METADATA_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year
_SESSION_METADATA_INACTIVE_AGE = timedelta(days=14)
# Page views refresh the session's last-access marker at most this often; the
# marker only needs to be accurate relative to the 14-day inactivity cutoff.
_SESSION_METADATA_TOUCH_KEY = "fido.mds.touched_at"
_SESSION_METADATA_TOUCH_THROTTLE_SECONDS = 1800.0

_session_metadata_last_cleanup: float = 0.0
_session_cleanup_worker: threading.Thread | None = None
_session_cleanup_pending: bool = False
_session_cleanup_lock = threading.Lock()
_METADATA_REPO_FOLDER = "metadata"

_METADATA_STATEMENT_REQUIRED_DEFAULTS: Mapping[str, Any] = {
    "description": "",
    "authenticatorVersion": 0,
    "schema": 3,
    "upv": [],
    "attestationTypes": [],
    "userVerificationDetails": [],
    "keyProtection": [],
    "matcherProtection": [],
    "attachmentHint": [],
    "tcDisplay": [],
    "attestationRootCertificates": [],
}
