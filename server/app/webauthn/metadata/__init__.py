"""Metadata handling utilities for the WebAuthn demo server.

The implementation lives in this package's submodules; this module re-exports
the pieces the rest of the server uses. A name here is the same object the
submodule defines: patch the submodule, not this module.
"""
from __future__ import annotations

from . import (
    blob,
    effective,
    entries,
    sessions,
    uploads,
    verifier,
)

__all__ = ["get_mds_verifier",
           "load_cached_metadata_snapshot", "load_packaged_explorer_summary", "load_packaged_snapshot_meta",
           "load_effective_full_snapshot", "resolve_effective_metadata_entry", "ensure_metadata_session_id",
           "list_session_metadata_items", "save_session_metadata_item", "serialize_session_metadata_item",
           "delete_session_metadata_item", "expand_metadata_entry_payloads",
           "metadata_entry_trust_anchor_status", "maybe_store_uploaded_metadata_file"]

# Repository upload helpers.
maybe_store_uploaded_metadata_file = uploads.maybe_store_uploaded_metadata_file

# Entry payload expansion.
expand_metadata_entry_payloads = entries.expand_metadata_entry_payloads

# Packaged snapshot loaders.
load_cached_metadata_snapshot = blob.load_cached_metadata_snapshot
load_packaged_explorer_summary = blob.load_packaged_explorer_summary
load_packaged_snapshot_meta = blob.load_packaged_snapshot_meta

# The metadata session identifier.
ensure_metadata_session_id = sessions.ensure_metadata_session_id

# Session metadata item CRUD.
save_session_metadata_item = sessions.save_session_metadata_item
list_session_metadata_items = sessions.list_session_metadata_items
delete_session_metadata_item = sessions.delete_session_metadata_item
serialize_session_metadata_item = sessions.serialize_session_metadata_item

# Effective (base + session) snapshot composition.
load_effective_full_snapshot = effective.load_effective_full_snapshot
resolve_effective_metadata_entry = effective.resolve_effective_metadata_entry

# Trust anchor status and the verifier.
metadata_entry_trust_anchor_status = verifier.metadata_entry_trust_anchor_status
get_mds_verifier = verifier.get_mds_verifier
