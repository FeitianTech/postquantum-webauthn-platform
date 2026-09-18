"""Shared mutable runtime state for the metadata submodules.

This module is the single home for the caches, locks and constants the
metadata runtime shares. It is deliberately a leaf: it imports nothing from
``server.app`` and nothing from its sibling fragments, so any fragment can
depend on it without creating a cycle.

Fragments reach the mutable entries through the module
(``runtime_state._base_metadata_cache = ...``) rather than by importing the
name, because a ``from ... import`` binding cannot be rebound for other
readers. The constants below are safe to import by name.
"""
from __future__ import annotations

import threading
from collections.abc import Mapping
from datetime import timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # annotations only; keeps this module free of runtime imports
    from fido2.mds3 import MdsAttestationVerifier, MetadataBlobPayload

_base_metadata_cache: MetadataBlobPayload | None = None
_base_metadata_mtime: float | None = None
_base_metadata_source: str | None = None
_base_verifier_cache: MdsAttestationVerifier | None = None
_base_verifier_mtime: float | None = None
_base_metadata_trust_verified: bool | None = None
_base_metadata_entry_ids: set[int] = set()
_base_explorer_snapshot_cache: dict[str, Any] | None = None
_base_explorer_snapshot_mtime: tuple[float | None, float | None] | None = None
_base_full_snapshot_cache: dict[str, Any] | None = None
_base_full_snapshot_mtime: float | None = None
_session_metadata_entry_ids: set[int] = set()

_base_metadata_lock = threading.RLock()
_base_explorer_snapshot_lock = threading.RLock()
_base_full_snapshot_lock = threading.RLock()
_base_verifier_lock = threading.RLock()

_SESSION_METADATA_SUFFIX = ".json"
_SESSION_METADATA_INFO_SUFFIX = ".meta.json"
_SESSION_METADATA_SESSION_KEY = "fido.mds.session"
_SESSION_METADATA_COOKIE_NAME = "fido.mds.session"
_SESSION_METADATA_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year
_SESSION_METADATA_INACTIVE_AGE = timedelta(days=14)
# Page views refresh the session's last-access marker at most this often; the
# marker only needs to be accurate relative to the 14-day inactivity cutoff.
_SESSION_METADATA_TOUCH_KEY = "fido.mds.touched_at"
_SESSION_METADATA_TOUCH_THROTTLE_ENV = "FIDO_SERVER_SESSION_TOUCH_THROTTLE_SECONDS"
_SESSION_METADATA_TOUCH_THROTTLE_DEFAULT_SECONDS = 1800.0

_SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV = (
    "FIDO_SERVER_SESSION_METADATA_CLEANUP_INTERVAL_SECONDS"
)
_SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV = "FIDO_SERVER_SESSION_METADATA_CLEANUP_HOURS"
_SESSION_METADATA_CLEANUP_ASYNC_ENV = "FIDO_SERVER_SESSION_METADATA_CLEANUP_ASYNC"

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
