"""Metadata handling utilities for the WebAuthn demo server."""
from __future__ import annotations
import json
import os
import secrets
import threading
import time
import types
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, Dict, Mapping, Optional, Set, Tuple
from flask import after_this_request, g, has_request_context, request, session
from fido2.mds3 import MetadataBlobPayload, MetadataBlobPayloadEntry, MdsAttestationVerifier
from . import session_metadata_store
from .config import (MDS_EXPLORER_PATH, MDS_METADATA_CACHE_PATH, MDS_METADATA_PATH,
                     MDS_METADATA_VERIFIED_PATH, MDS_METADATA_URL, app)
from .env_flags import parse_env_flag
from .github_client import git_blob_sha, github_list_directory, github_upload_file, is_logging_enabled
from .mds_snapshot import (build_entry_id, build_bootstrap_snapshot, build_explorer_entry,
                           build_explorer_snapshot, normalise_aaguid_key)
from .metadata_parts import base_snapshot_runtime as _base_snapshot_runtime
from .metadata_parts import cache_runtime as _cache_runtime
from .metadata_parts import effective_snapshot_runtime as _effective_snapshot_runtime
from .metadata_parts import entry_payload_runtime as _entry_payload_runtime
from .metadata_parts import env_runtime as _env_runtime
from .metadata_parts import session_cleanup_runtime as _session_cleanup_runtime
from .metadata_parts import session_identity_runtime as _session_identity_runtime
from .metadata_parts import session_items_runtime as _session_items_runtime
from .metadata_parts import upload_runtime as _upload_runtime
from .metadata_parts import verifier_runtime as _verifier_runtime
__all__ = ["MetadataDownloadError", "download_metadata_blob", "get_mds_verifier",
           "load_metadata_cache_entry", "format_last_modified_header", "store_metadata_cache_entry",
           "load_cached_metadata_snapshot", "load_packaged_explorer_summary", "load_effective_explorer_snapshot",
           "load_effective_full_snapshot", "resolve_effective_metadata_entry", "ensure_metadata_session_id",
           "list_session_metadata_items", "save_session_metadata_item", "serialize_session_metadata_item",
           "delete_session_metadata_item", "expand_metadata_entry_payloads",
           "metadata_entry_trust_anchor_status", "maybe_store_uploaded_metadata_file"]

_base_metadata_cache: Optional[MetadataBlobPayload] = None
_base_metadata_mtime: Optional[float] = None
_base_metadata_source: Optional[str] = None
_base_verifier_cache: Optional[MdsAttestationVerifier] = None
_base_verifier_mtime: Optional[float] = None
_base_metadata_trust_verified: Optional[bool] = None
_base_metadata_entry_ids: Set[int] = set()
_base_explorer_snapshot_cache: Optional[Dict[str, Any]] = None
_base_explorer_snapshot_mtime: Optional[Tuple[Optional[float], Optional[float]]] = None
_base_full_snapshot_cache: Optional[Dict[str, Any]] = None
_base_full_snapshot_mtime: Optional[float] = None
_session_metadata_entry_ids: Set[int] = set()

_SESSION_METADATA_SUFFIX = ".json"
_SESSION_METADATA_INFO_SUFFIX = ".meta.json"
_SESSION_METADATA_SESSION_KEY = "fido.mds.session"
_SESSION_METADATA_COOKIE_NAME = "fido.mds.session"
_SESSION_METADATA_COOKIE_MAX_AGE = 60 * 60 * 24 * 365  # 1 year
_SESSION_METADATA_INACTIVE_AGE = timedelta(days=14)

_SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV = (
    "FIDO_SERVER_SESSION_METADATA_CLEANUP_INTERVAL_SECONDS"
)
_SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV = "FIDO_SERVER_SESSION_METADATA_CLEANUP_HOURS"
_SESSION_METADATA_CLEANUP_ASYNC_ENV = "FIDO_SERVER_SESSION_METADATA_CLEANUP_ASYNC"

_session_metadata_last_cleanup: float = 0.0
_session_cleanup_worker: Optional[threading.Thread] = None
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
SessionMetadataItem = _session_items_runtime.SessionMetadataItem
MetadataDownloadError = _cache_runtime.MetadataDownloadError
_RUNTIME_REBOUND_CACHE: Dict[Callable[..., Any], Callable[..., Any]] = {}


def _run_with_metadata_globals(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    rebound = _RUNTIME_REBOUND_CACHE.get(func)
    if rebound is None:
        rebound = types.FunctionType(
            func.__code__,
            globals(),
            name=func.__name__,
            argdefs=func.__defaults__,
            closure=func.__closure__,
        )
        rebound.__kwdefaults__ = getattr(func, "__kwdefaults__", None)
        _RUNTIME_REBOUND_CACHE[func] = rebound
    return rebound(*args, **kwargs)


def _bind_runtime_function(func: Callable[..., Any]) -> Callable[..., Any]:
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        return _run_with_metadata_globals(func, *args, **kwargs)
    return _wrapped


def _install_runtime_bindings(bindings: Mapping[str, Callable[..., Any]]) -> None:
    for _name, _func in bindings.items():
        globals()[_name] = _bind_runtime_function(_func)


def _binding_dict(module: Any, names: Tuple[str, ...]) -> Dict[str, Callable[..., Any]]:
    return {name: getattr(module, name) for name in names}


_install_runtime_bindings(
    {
        **_binding_dict(_env_runtime, ("_env_flag", "_resolve_cleanup_interval", "_cleanup_async_enabled")),
        **_binding_dict(_upload_runtime, ("_safe_metadata_repo_filename", "maybe_store_uploaded_metadata_file")),
        **_binding_dict(
            _entry_payload_runtime,
            (
                "_clone_json_value",
                "_normalise_status_reports",
                "_normalise_attestation_identifiers",
                "_normalise_metadata_statement",
                "build_metadata_entry_components",
                "expand_metadata_entry_payloads",
                "_normalise_aaguid",
                "_extract_entry_aaguid",
            ),
        ),
        **_binding_dict(
            _session_cleanup_runtime,
            (
                "_touch_session_last_access",
                "_resolve_session_last_access",
                "_maybe_cleanup_inactive_sessions",
                "_run_inactive_session_cleanup_worker",
                "_schedule_inactive_session_cleanup",
            ),
        ),
        **_binding_dict(
            _session_identity_runtime,
            (
                "_normalise_session_identifier",
                "_schedule_session_cookie",
                "_get_metadata_session_id",
                "ensure_metadata_session_id",
                "_session_metadata_directory",
                "_note_session_activity",
                "_validate_session_metadata_filename",
            ),
        ),
        **_binding_dict(
            _session_items_runtime,
            (
                "_prune_session_metadata_directory",
                "_load_session_metadata_info",
                "save_session_metadata_item",
                "list_session_metadata_items",
                "delete_session_metadata_item",
                "serialize_session_metadata_item",
            ),
        ),
        **_binding_dict(
            _cache_runtime,
            (
                "_parse_http_datetime",
                "_format_last_modified",
                "format_last_modified_header",
                "_clean_metadata_cache_value",
                "load_metadata_cache_entry",
                "_store_metadata_cache_entry",
                "store_metadata_cache_entry",
                "download_metadata_blob",
            ),
        ),
        **_binding_dict(
            _base_snapshot_runtime,
            (
                "load_cached_metadata_snapshot",
                "_load_base_metadata",
                "_load_verified_metadata_fallback",
                "_load_verified_metadata_payload",
                "_load_base_explorer_snapshot",
                "_load_base_full_snapshot",
                "load_packaged_explorer_summary",
            ),
        ),
        **_binding_dict(
            _effective_snapshot_runtime,
            (
                "_build_session_snapshot_entry",
                "_session_item_source_info",
                "_entry_matches_lookup",
                "_compose_effective_snapshot",
                "load_effective_explorer_snapshot",
                "load_effective_full_snapshot",
                "resolve_effective_metadata_entry",
            ),
        ),
        **_binding_dict(
            _verifier_runtime,
            (
                "_merge_metadata",
                "metadata_entry_trust_anchor_status",
                "get_mds_verifier",
            ),
        ),
    }
)

_SESSION_METADATA_CLEANUP_INTERVAL = _resolve_cleanup_interval()
