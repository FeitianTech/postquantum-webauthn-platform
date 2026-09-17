"""Metadata handling utilities for the WebAuthn demo server.

The implementation lives in :mod:`server.app.metadata_parts`; this module is the
public face of it and re-exports the pieces callers use. Each fragment resolves
its own names through its own imports, so a name here is the same object the
fragment defines -- patching one of these re-exports changes what callers of
*this module* see, not what the fragments call.
"""
from __future__ import annotations

from .metadata_parts import (
    base_snapshot_runtime,
    cache_runtime,
    effective_snapshot_runtime,
    entry_payload_runtime,
    env_runtime,
    session_cleanup_runtime,
    session_identity_runtime,
    session_items_runtime,
    upload_runtime,
    verifier_runtime,
)
from .metadata_parts.runtime_state import (
    _METADATA_REPO_FOLDER,
    _METADATA_STATEMENT_REQUIRED_DEFAULTS,
    _SESSION_METADATA_CLEANUP_ASYNC_ENV,
    _SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV,
    _SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV,
    _SESSION_METADATA_COOKIE_MAX_AGE,
    _SESSION_METADATA_COOKIE_NAME,
    _SESSION_METADATA_INACTIVE_AGE,
    _SESSION_METADATA_INFO_SUFFIX,
    _SESSION_METADATA_SESSION_KEY,
    _SESSION_METADATA_SUFFIX,
    _SESSION_METADATA_TOUCH_KEY,
    _SESSION_METADATA_TOUCH_THROTTLE_DEFAULT_SECONDS,
    _SESSION_METADATA_TOUCH_THROTTLE_ENV,
)

__all__ = ["MetadataDownloadError", "download_metadata_blob", "get_mds_verifier",
           "load_metadata_cache_entry", "format_last_modified_header", "store_metadata_cache_entry",
           "load_cached_metadata_snapshot", "load_packaged_explorer_summary", "load_effective_explorer_snapshot",
           "load_effective_full_snapshot", "resolve_effective_metadata_entry", "ensure_metadata_session_id",
           "list_session_metadata_items", "save_session_metadata_item", "serialize_session_metadata_item",
           "delete_session_metadata_item", "expand_metadata_entry_payloads",
           "metadata_entry_trust_anchor_status", "maybe_store_uploaded_metadata_file"]

MetadataDownloadError = cache_runtime.MetadataDownloadError
SessionMetadataItem = session_items_runtime.SessionMetadataItem

# Cache and HTTP header helpers.
_parse_http_datetime = cache_runtime._parse_http_datetime
_format_last_modified = cache_runtime._format_last_modified
format_last_modified_header = cache_runtime.format_last_modified_header
_clean_metadata_cache_value = cache_runtime._clean_metadata_cache_value
load_metadata_cache_entry = cache_runtime.load_metadata_cache_entry
_store_metadata_cache_entry = cache_runtime._store_metadata_cache_entry
store_metadata_cache_entry = cache_runtime.store_metadata_cache_entry
download_metadata_blob = cache_runtime.download_metadata_blob

# Environment and cleanup interval helpers.
_env_flag = env_runtime._env_flag
_resolve_cleanup_interval = env_runtime._resolve_cleanup_interval
_cleanup_async_enabled = env_runtime._cleanup_async_enabled

# Repository upload helpers.
_safe_metadata_repo_filename = upload_runtime._safe_metadata_repo_filename
maybe_store_uploaded_metadata_file = upload_runtime.maybe_store_uploaded_metadata_file

# Entry payload normalisation and expansion.
_clone_json_value = entry_payload_runtime._clone_json_value
_normalise_status_reports = entry_payload_runtime._normalise_status_reports
_normalise_attestation_identifiers = entry_payload_runtime._normalise_attestation_identifiers
_normalise_metadata_statement = entry_payload_runtime._normalise_metadata_statement
build_metadata_entry_components = entry_payload_runtime.build_metadata_entry_components
expand_metadata_entry_payloads = entry_payload_runtime.expand_metadata_entry_payloads
_normalise_aaguid = entry_payload_runtime._normalise_aaguid
_extract_entry_aaguid = entry_payload_runtime._extract_entry_aaguid

# Packaged snapshot loaders.
load_cached_metadata_snapshot = base_snapshot_runtime.load_cached_metadata_snapshot
_load_base_metadata = base_snapshot_runtime._load_base_metadata
_load_verified_metadata_fallback = base_snapshot_runtime._load_verified_metadata_fallback
_load_verified_metadata_payload = base_snapshot_runtime._load_verified_metadata_payload
_load_packaged_explorer_meta = base_snapshot_runtime._load_packaged_explorer_meta
_load_base_explorer_snapshot = base_snapshot_runtime._load_base_explorer_snapshot
_load_base_full_snapshot = base_snapshot_runtime._load_base_full_snapshot
load_packaged_explorer_summary = base_snapshot_runtime.load_packaged_explorer_summary

# Session cleanup worker and scheduling.
_touch_session_last_access = session_cleanup_runtime._touch_session_last_access
_resolve_session_last_access = session_cleanup_runtime._resolve_session_last_access
_maybe_cleanup_inactive_sessions = session_cleanup_runtime._maybe_cleanup_inactive_sessions
_run_inactive_session_cleanup_worker = session_cleanup_runtime._run_inactive_session_cleanup_worker
_schedule_inactive_session_cleanup = session_cleanup_runtime._schedule_inactive_session_cleanup

# Session identifier, cookie, and directory helpers.
_normalise_session_identifier = session_identity_runtime._normalise_session_identifier
_schedule_session_cookie = session_identity_runtime._schedule_session_cookie
_get_metadata_session_id = session_identity_runtime._get_metadata_session_id
ensure_metadata_session_id = session_identity_runtime.ensure_metadata_session_id
_session_metadata_directory = session_identity_runtime._session_metadata_directory
_note_session_activity = session_identity_runtime._note_session_activity
_validate_session_metadata_filename = session_identity_runtime._validate_session_metadata_filename

# Session metadata item CRUD.
_prune_session_metadata_directory = session_items_runtime._prune_session_metadata_directory
_load_session_metadata_info = session_items_runtime._load_session_metadata_info
save_session_metadata_item = session_items_runtime.save_session_metadata_item
list_session_metadata_items = session_items_runtime.list_session_metadata_items
delete_session_metadata_item = session_items_runtime.delete_session_metadata_item
serialize_session_metadata_item = session_items_runtime.serialize_session_metadata_item

# Effective (base + session) snapshot composition.
_build_session_snapshot_entry = effective_snapshot_runtime._build_session_snapshot_entry
_session_item_source_info = effective_snapshot_runtime._session_item_source_info
_entry_matches_lookup = effective_snapshot_runtime._entry_matches_lookup
_compose_effective_snapshot = effective_snapshot_runtime._compose_effective_snapshot
load_effective_explorer_snapshot = effective_snapshot_runtime.load_effective_explorer_snapshot
load_effective_full_snapshot = effective_snapshot_runtime.load_effective_full_snapshot
resolve_effective_metadata_entry = effective_snapshot_runtime.resolve_effective_metadata_entry

# Metadata merge, trust anchor, and verifier.
_merge_metadata = verifier_runtime._merge_metadata
metadata_entry_trust_anchor_status = verifier_runtime.metadata_entry_trust_anchor_status
get_mds_verifier = verifier_runtime.get_mds_verifier
