"""Metadata handling utilities for the WebAuthn demo server.

The implementation lives in this package's submodules; this module is the public
face of it and re-exports the pieces callers use. Each fragment resolves
its own names through its own imports, so a name here is the same object the
fragment defines -- patching one of these re-exports changes what callers of
*this module* see, not what the fragments call.
"""
from __future__ import annotations

from . import (
    blob,
    effective_snapshot_runtime,
    entry_payload_runtime,
    runtime_state,
    sessions,
    upload_runtime,
    verifier_runtime,
)

__all__ = ["MetadataDownloadError", "download_metadata_blob", "get_mds_verifier",
           "load_metadata_cache_entry", "format_last_modified_header", "store_metadata_cache_entry",
           "load_cached_metadata_snapshot", "load_packaged_explorer_summary", "load_effective_explorer_snapshot",
           "load_effective_full_snapshot", "resolve_effective_metadata_entry", "ensure_metadata_session_id",
           "list_session_metadata_items", "save_session_metadata_item", "serialize_session_metadata_item",
           "delete_session_metadata_item", "expand_metadata_entry_payloads",
           "metadata_entry_trust_anchor_status", "maybe_store_uploaded_metadata_file"]

MetadataDownloadError = blob.MetadataDownloadError
SessionMetadataItem = sessions.SessionMetadataItem

# Constants shared with the fragments.
_METADATA_REPO_FOLDER = runtime_state._METADATA_REPO_FOLDER
_METADATA_STATEMENT_REQUIRED_DEFAULTS = runtime_state._METADATA_STATEMENT_REQUIRED_DEFAULTS
_SESSION_METADATA_CLEANUP_ASYNC_ENV = runtime_state._SESSION_METADATA_CLEANUP_ASYNC_ENV
_SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV = runtime_state._SESSION_METADATA_CLEANUP_INTERVAL_HOURS_ENV
_SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV = runtime_state._SESSION_METADATA_CLEANUP_INTERVAL_SECONDS_ENV
_SESSION_METADATA_COOKIE_MAX_AGE = runtime_state._SESSION_METADATA_COOKIE_MAX_AGE
_SESSION_METADATA_COOKIE_NAME = runtime_state._SESSION_METADATA_COOKIE_NAME
_SESSION_METADATA_INACTIVE_AGE = runtime_state._SESSION_METADATA_INACTIVE_AGE
_SESSION_METADATA_INFO_SUFFIX = runtime_state._SESSION_METADATA_INFO_SUFFIX
_SESSION_METADATA_SESSION_KEY = runtime_state._SESSION_METADATA_SESSION_KEY
_SESSION_METADATA_SUFFIX = runtime_state._SESSION_METADATA_SUFFIX
_SESSION_METADATA_TOUCH_KEY = runtime_state._SESSION_METADATA_TOUCH_KEY
_SESSION_METADATA_TOUCH_THROTTLE_DEFAULT_SECONDS = runtime_state._SESSION_METADATA_TOUCH_THROTTLE_DEFAULT_SECONDS
_SESSION_METADATA_TOUCH_THROTTLE_ENV = runtime_state._SESSION_METADATA_TOUCH_THROTTLE_ENV

# Cache and HTTP header helpers.
_parse_http_datetime = blob._parse_http_datetime
_format_last_modified = blob._format_last_modified
format_last_modified_header = blob.format_last_modified_header
_clean_metadata_cache_value = blob._clean_metadata_cache_value
load_metadata_cache_entry = blob.load_metadata_cache_entry
_store_metadata_cache_entry = blob._store_metadata_cache_entry
store_metadata_cache_entry = blob.store_metadata_cache_entry
download_metadata_blob = blob.download_metadata_blob

# Environment and cleanup interval helpers.
_env_flag = sessions._env_flag
_resolve_cleanup_interval = sessions._resolve_cleanup_interval
_cleanup_async_enabled = sessions._cleanup_async_enabled

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
load_cached_metadata_snapshot = blob.load_cached_metadata_snapshot
_load_base_metadata = blob._load_base_metadata
_load_verified_metadata_fallback = blob._load_verified_metadata_fallback
_load_verified_metadata_payload = blob._load_verified_metadata_payload
_load_packaged_explorer_meta = blob._load_packaged_explorer_meta
_load_base_explorer_snapshot = blob._load_base_explorer_snapshot
_load_base_full_snapshot = blob._load_base_full_snapshot
load_packaged_explorer_summary = blob.load_packaged_explorer_summary

# Session cleanup worker and scheduling.
_touch_session_last_access = sessions._touch_session_last_access
_resolve_session_last_access = sessions._resolve_session_last_access
_maybe_cleanup_inactive_sessions = sessions._maybe_cleanup_inactive_sessions
_run_inactive_session_cleanup_worker = sessions._run_inactive_session_cleanup_worker
_schedule_inactive_session_cleanup = sessions._schedule_inactive_session_cleanup

# Session identifier, cookie, and directory helpers.
_normalise_session_identifier = sessions._normalise_session_identifier
_schedule_session_cookie = sessions._schedule_session_cookie
_get_metadata_session_id = sessions._get_metadata_session_id
ensure_metadata_session_id = sessions.ensure_metadata_session_id
_session_metadata_directory = sessions._session_metadata_directory
_note_session_activity = sessions._note_session_activity
_validate_session_metadata_filename = sessions._validate_session_metadata_filename

# Session metadata item CRUD.
_prune_session_metadata_directory = sessions._prune_session_metadata_directory
_load_session_metadata_info = sessions._load_session_metadata_info
save_session_metadata_item = sessions.save_session_metadata_item
list_session_metadata_items = sessions.list_session_metadata_items
delete_session_metadata_item = sessions.delete_session_metadata_item
serialize_session_metadata_item = sessions.serialize_session_metadata_item

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
