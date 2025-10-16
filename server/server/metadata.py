"""Metadata handling utilities for the WebAuthn demo server."""
from __future__ import annotations

import json
import os
import secrets
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.utils import formatdate, parsedate_to_datetime
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from flask import has_request_context, session

from fido2.mds3 import (
    MetadataBlobPayload,
    MetadataBlobPayloadEntry,
    MdsAttestationVerifier,
)

from .config import MDS_METADATA_CACHE_PATH, MDS_METADATA_PATH, SESSION_METADATA_DIR, app

__all__ = [
    "get_mds_verifier",
    "load_metadata_cache_entry",
    "ensure_metadata_session_id",
    "list_session_metadata_items",
    "save_session_metadata_item",
    "serialize_session_metadata_item",
    "delete_session_metadata_item",
    "expand_metadata_entry_payloads",
    "metadata_entry_trust_anchor_status",
]


_base_metadata_cache: Optional[MetadataBlobPayload] = None
_base_metadata_mtime: Optional[float] = None
_base_verifier_cache: Optional[MdsAttestationVerifier] = None
_base_verifier_mtime: Optional[float] = None
_base_metadata_trust_verified: Optional[bool] = None
_base_metadata_entry_ids: Set[int] = set()
_session_metadata_entry_ids: Set[int] = set()

_SESSION_METADATA_SUFFIX = ".json"
_SESSION_METADATA_INFO_SUFFIX = ".meta.json"
_SESSION_METADATA_SESSION_KEY = "fido.mds.session"
_SESSION_METADATA_RECOVERY_MARKER = ".last-session-id"

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


@dataclass(frozen=True)
class SessionMetadataItem:
    filename: str
    payload: Dict[str, Any]
    legal_header: Optional[str]
    entry: MetadataBlobPayloadEntry
    uploaded_at: Optional[str]
    original_filename: Optional[str]
    mtime: Optional[float]


def _session_metadata_recovery_enabled() -> bool:
    flag = app.config.get("SESSION_METADATA_RECOVER_ON_START")
    if flag is not None:
        return bool(flag)
    return bool(app.debug)


def _normalise_session_identifier(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None

    trimmed = value.strip()
    if not trimmed or trimmed.startswith("."):
        return None

    for separator in (os.sep, os.altsep):
        if separator and separator in trimmed:
            return None

    return trimmed


def _session_metadata_marker_path() -> str:
    return os.path.join(SESSION_METADATA_DIR, _SESSION_METADATA_RECOVERY_MARKER)


def _remember_session_identifier(identifier: str) -> None:
    if not _session_metadata_recovery_enabled():
        return

    normalised = _normalise_session_identifier(identifier)
    if not normalised:
        return

    marker_path = _session_metadata_marker_path()
    try:
        os.makedirs(SESSION_METADATA_DIR, exist_ok=True)
        with open(marker_path, "w", encoding="utf-8") as marker_file:
            marker_file.write(normalised)
            marker_file.write("\n")
    except OSError as exc:
        app.logger.debug(
            "Unable to persist session metadata identifier %s: %s", normalised, exc
        )


def _load_persisted_session_identifier() -> Optional[str]:
    if not _session_metadata_recovery_enabled():
        return None

    marker_path = _session_metadata_marker_path()
    try:
        with open(marker_path, "r", encoding="utf-8") as marker_file:
            candidate = _normalise_session_identifier(marker_file.read())
    except OSError:
        return None

    if not candidate:
        return None

    directory = _session_metadata_directory(candidate, create=False)
    if not directory or not os.path.isdir(directory):
        return None

    return candidate


def _discover_single_session_directory() -> Optional[str]:
    if not _session_metadata_recovery_enabled():
        return None

    try:
        entries = os.listdir(SESSION_METADATA_DIR)
    except OSError:
        return None

    candidates: List[str] = []
    for entry in entries:
        identifier = _normalise_session_identifier(entry)
        if not identifier:
            continue

        path = os.path.join(SESSION_METADATA_DIR, identifier)
        if not os.path.isdir(path):
            continue

        try:
            directory_entries = os.listdir(path)
        except OSError:
            continue

        has_metadata = False
        for name in directory_entries:
            if name.endswith(_SESSION_METADATA_INFO_SUFFIX):
                continue
            if name.endswith(_SESSION_METADATA_SUFFIX):
                has_metadata = True
                break

        if has_metadata:
            candidates.append(identifier)

    if len(candidates) == 1:
        return candidates[0]

    return None


def _recover_session_metadata_identifier() -> Optional[str]:
    candidate = _load_persisted_session_identifier()
    if candidate:
        return candidate

    return _discover_single_session_directory()


def _get_metadata_session_id(*, create: bool = False) -> Optional[str]:
    if not has_request_context():
        return None

    existing = session.get(_SESSION_METADATA_SESSION_KEY)
    if isinstance(existing, str) and existing.strip():
        identifier = existing.strip()
        _remember_session_identifier(identifier)
        return identifier

    if not create:
        return None

    identifier = _recover_session_metadata_identifier()
    if not identifier:
        identifier = secrets.token_urlsafe(32)
    session[_SESSION_METADATA_SESSION_KEY] = identifier
    _remember_session_identifier(identifier)
    return identifier


def ensure_metadata_session_id() -> str:
    identifier = _get_metadata_session_id(create=True)
    if not identifier:
        raise RuntimeError("Unable to establish metadata session identifier.")
    if has_request_context():
        session.permanent = True
    return identifier


def _session_metadata_directory(session_id: str, *, create: bool = False) -> Optional[str]:
    if not session_id:
        return None

    directory = os.path.join(SESSION_METADATA_DIR, session_id)
    if create:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:
            app.logger.error("Failed to prepare session metadata directory %s: %s", directory, exc)
            raise
    return directory


def _validate_session_metadata_filename(filename: str) -> str:
    if not isinstance(filename, str):
        raise ValueError("Invalid metadata filename.")

    trimmed = filename.strip()
    if not trimmed:
        raise ValueError("Invalid metadata filename.")

    if trimmed.startswith("."):
        raise ValueError("Invalid metadata filename.")

    for separator in (os.sep, os.altsep):
        if separator and separator in trimmed:
            raise ValueError("Invalid metadata filename.")

    if os.path.basename(trimmed) != trimmed:
        raise ValueError("Invalid metadata filename.")

    if not trimmed.endswith(_SESSION_METADATA_SUFFIX):
        raise ValueError("Invalid metadata filename.")

    return trimmed


def _prune_session_metadata_directory(directory: str) -> None:
    try:
        entries = os.listdir(directory)
    except OSError:
        return

    if entries:
        return

    try:
        os.rmdir(directory)
    except OSError:
        pass


def _load_session_metadata_info(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as info_file:
            payload = json.load(info_file)
    except (OSError, ValueError, TypeError):
        return {}

    if not isinstance(payload, dict):
        return {}

    return payload


def _clone_json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    try:
        return json.loads(json.dumps(value))
    except (TypeError, ValueError):
        return None


def _normalise_status_reports(raw: Mapping[str, Any]) -> List[Dict[str, Any]]:
    reports: List[Dict[str, Any]] = []
    value = raw.get("statusReports")
    if not isinstance(value, list):
        return reports

    for entry in value:
        cloned = _clone_json_value(entry)
        if isinstance(cloned, dict):
            reports.append(cloned)
    return reports


def _normalise_attestation_identifiers(raw: Mapping[str, Any]) -> Optional[List[str]]:
    identifiers = raw.get("attestationCertificateKeyIdentifiers")
    if not isinstance(identifiers, list):
        return None

    filtered: List[str] = []
    for identifier in identifiers:
        if isinstance(identifier, str):
            trimmed = identifier.strip()
            if trimmed:
                filtered.append(trimmed)
    return filtered or None


def _normalise_metadata_statement(raw: Mapping[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
    legal_header: Optional[str] = None
    raw_legal_header = raw.get("legalHeader")
    if isinstance(raw_legal_header, str):
        legal_header = raw_legal_header.strip() or None

    metadata_source: Mapping[str, Any] = raw
    nested_statement = raw.get("metadataStatement")
    if isinstance(nested_statement, Mapping):
        metadata_source = nested_statement

    excluded_keys = {
        "statusReports",
        "timeOfLastStatusChange",
        "attestationCertificateKeyIdentifiers",
        "aaid",
        "aaguid",
    }

    metadata_statement: Dict[str, Any] = {}
    for key, value in metadata_source.items():
        if metadata_source is raw and key in excluded_keys:
            continue

        cloned = _clone_json_value(value)
        if cloned is not None:
            metadata_statement[key] = cloned

    if legal_header and "legalHeader" not in metadata_statement:
        metadata_statement["legalHeader"] = legal_header

    description = metadata_statement.get("description")
    if not isinstance(description, str):
        metadata_statement["description"] = _METADATA_STATEMENT_REQUIRED_DEFAULTS["description"]

    authenticator_version = metadata_statement.get("authenticatorVersion")
    if not isinstance(authenticator_version, int):
        metadata_statement["authenticatorVersion"] = _METADATA_STATEMENT_REQUIRED_DEFAULTS["authenticatorVersion"]

    schema = metadata_statement.get("schema")
    if not isinstance(schema, int):
        metadata_statement["schema"] = _METADATA_STATEMENT_REQUIRED_DEFAULTS["schema"]

    for key in (
        "upv",
        "attestationTypes",
        "userVerificationDetails",
        "keyProtection",
        "matcherProtection",
        "attachmentHint",
        "tcDisplay",
        "attestationRootCertificates",
    ):
        value = metadata_statement.get(key)
        if not isinstance(value, list):
            default_value = _METADATA_STATEMENT_REQUIRED_DEFAULTS[key]
            metadata_statement[key] = list(default_value) if isinstance(default_value, list) else default_value

    return metadata_statement, legal_header


def build_metadata_entry_components(raw: Mapping[str, Any]) -> Tuple[
    MetadataBlobPayloadEntry,
    Optional[str],
    Dict[str, Any],
]:
    if not isinstance(raw, Mapping):
        raise TypeError("Metadata JSON must be an object.")

    payload: Dict[str, Any] = {}
    payload["statusReports"] = _normalise_status_reports(raw)

    time_of_last_status_change = raw.get("timeOfLastStatusChange")
    if isinstance(time_of_last_status_change, str) and time_of_last_status_change.strip():
        payload["timeOfLastStatusChange"] = time_of_last_status_change.strip()
    else:
        payload["timeOfLastStatusChange"] = datetime.now(timezone.utc).date().isoformat()

    identifiers = _normalise_attestation_identifiers(raw)
    if identifiers:
        payload["attestationCertificateKeyIdentifiers"] = identifiers

    if isinstance(raw.get("aaid"), str) and raw["aaid"].strip():
        payload["aaid"] = raw["aaid"].strip()

    if isinstance(raw.get("aaguid"), str) and raw["aaguid"].strip():
        payload["aaguid"] = raw["aaguid"].strip()

    metadata_statement, legal_header = _normalise_metadata_statement(raw)
    payload["metadataStatement"] = metadata_statement

    entry = MetadataBlobPayloadEntry.from_dict(payload)
    payload_clone = json.loads(json.dumps(payload))
    return entry, legal_header, payload_clone


def expand_metadata_entry_payloads(raw: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    """Expand a JSON payload into individual metadata entries.

    The FIDO Metadata BLOB contains an ``entries`` list with metadata
    statements. Uploaded JSON snippets may either provide a single metadata
    entry object or a structure mirroring the BLOB shape. This helper
    normalises both cases into a list of per-entry payload mappings that can be
    handed to :func:`build_metadata_entry_components`.
    """

    if not isinstance(raw, Mapping):
        raise TypeError("Metadata JSON must be an object.")

    entries_value = raw.get("entries")
    if not isinstance(entries_value, list):
        return [raw]

    if not entries_value:
        raise ValueError("Metadata JSON does not contain any entries.")

    legal_header: Optional[str] = None
    raw_legal_header = raw.get("legalHeader")
    if isinstance(raw_legal_header, str) and raw_legal_header.strip():
        legal_header = raw_legal_header.strip()

    expanded: List[Mapping[str, Any]] = []
    for index, entry in enumerate(entries_value):
        if not isinstance(entry, Mapping):
            raise ValueError(f"Entry {index + 1} is not a JSON object.")

        cloned = _clone_json_value(entry)
        if not isinstance(cloned, dict):
            raise ValueError(f"Entry {index + 1} could not be cloned into a JSON object.")

        if legal_header and "legalHeader" not in cloned:
            cloned["legalHeader"] = legal_header

        expanded.append(cloned)

    return expanded


def _normalise_aaguid(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().replace("-", "").lower()
    return cleaned or None


def _extract_entry_aaguid(entry: MetadataBlobPayloadEntry) -> Optional[str]:
    direct = _normalise_aaguid(getattr(entry, "aaguid", None))
    if direct:
        return direct

    statement = getattr(entry, "metadata_statement", None)
    if statement is None:
        statement = getattr(entry, "metadataStatement", None)
    if isinstance(statement, Mapping):
        return _normalise_aaguid(statement.get("aaguid"))
    return None


def _merge_metadata(
    base_metadata: Optional[MetadataBlobPayload],
    session_items: List[SessionMetadataItem],
) -> MetadataBlobPayload:
    custom_entries: List[MetadataBlobPayloadEntry] = []
    seen_aaguids: Set[str] = set()

    for item in session_items:
        entry = item.entry
        aaguid = _extract_entry_aaguid(entry)
        if aaguid and aaguid in seen_aaguids:
            continue
        if aaguid:
            seen_aaguids.add(aaguid)
        custom_entries.append(entry)

    base_entries: List[MetadataBlobPayloadEntry] = []
    if base_metadata is not None:
        for entry in base_metadata.entries:
            aaguid = _extract_entry_aaguid(entry)
            if aaguid and aaguid in seen_aaguids:
                continue
            base_entries.append(entry)

    combined_entries = tuple(custom_entries + base_entries)
    if base_metadata is not None:
        metadata = replace(base_metadata, entries=combined_entries)
        if not getattr(metadata, "legal_header", None):
            for item in session_items:
                if item.legal_header:
                    metadata = replace(metadata, legal_header=item.legal_header)
                    break
        return metadata

    legal_header = ""
    for item in session_items:
        if item.legal_header:
            legal_header = item.legal_header
            break

    next_update = datetime.now(timezone.utc).date()
    return MetadataBlobPayload(
        legal_header=legal_header,
        no=0,
        next_update=next_update,
        entries=combined_entries,
    )


def save_session_metadata_item(
    raw_payload: Mapping[str, Any],
    *,
    original_filename: Optional[str] = None,
) -> SessionMetadataItem:
    session_id = ensure_metadata_session_id()
    directory = _session_metadata_directory(session_id, create=True)
    if not directory:
        raise RuntimeError("Unable to resolve session metadata storage path.")

    entry, legal_header, payload = build_metadata_entry_components(raw_payload)

    try:
        serialisable_payload = json.loads(json.dumps(raw_payload))
    except (TypeError, ValueError) as exc:
        raise ValueError("Metadata JSON contains unsupported types.") from exc

    os.makedirs(directory, exist_ok=True)
    stored_filename = f"{uuid.uuid4().hex}{_SESSION_METADATA_SUFFIX}"
    metadata_path = os.path.join(directory, stored_filename)

    try:
        with open(metadata_path, "w", encoding="utf-8") as metadata_file:
            json.dump(serialisable_payload, metadata_file, indent=2, sort_keys=True)
            metadata_file.write("\n")
    except OSError as exc:
        app.logger.error("Failed to store session metadata %s: %s", metadata_path, exc)
        raise RuntimeError("Failed to store uploaded metadata on the server.") from exc

    uploaded_at = datetime.now(timezone.utc).isoformat()
    info_payload = {
        "original_filename": original_filename or None,
        "uploaded_at": uploaded_at,
        "stored_filename": stored_filename,
    }

    info_path = metadata_path + _SESSION_METADATA_INFO_SUFFIX
    try:
        with open(info_path, "w", encoding="utf-8") as info_file:
            json.dump(info_payload, info_file, indent=2, sort_keys=True)
            info_file.write("\n")
    except OSError as exc:
        app.logger.warning("Failed to store session metadata info for %s: %s", metadata_path, exc)

    try:
        mtime = os.path.getmtime(metadata_path)
    except OSError:
        mtime = None

    return SessionMetadataItem(
        filename=stored_filename,
        payload=payload,
        legal_header=legal_header,
        entry=entry,
        uploaded_at=uploaded_at,
        original_filename=original_filename or None,
        mtime=mtime,
    )


def list_session_metadata_items(session_id: Optional[str] = None) -> List[SessionMetadataItem]:
    global _session_metadata_entry_ids
    active_session = session_id or _get_metadata_session_id(create=False)
    if not active_session:
        _session_metadata_entry_ids = set()
        return []

    directory = _session_metadata_directory(active_session, create=False)
    if not directory or not os.path.isdir(directory):
        _session_metadata_entry_ids = set()
        return []

    try:
        filenames = [
            name
            for name in os.listdir(directory)
            if name.endswith(_SESSION_METADATA_SUFFIX)
            and not name.endswith(_SESSION_METADATA_INFO_SUFFIX)
        ]
    except OSError:
        return []

    items: List[SessionMetadataItem] = []
    for filename in sorted(filenames):
        metadata_path = os.path.join(directory, filename)
        try:
            with open(metadata_path, "r", encoding="utf-8") as metadata_file:
                raw = json.load(metadata_file)
        except (OSError, ValueError, TypeError) as exc:
            app.logger.warning("Failed to load session metadata from %s: %s", metadata_path, exc)
            continue

        try:
            entry, legal_header, payload = build_metadata_entry_components(raw)
        except Exception as exc:  # pylint: disable=broad-except
            app.logger.warning(
                "Failed to parse session metadata entry from %s: %s",
                metadata_path,
                exc,
            )
            continue

        info_path = metadata_path + _SESSION_METADATA_INFO_SUFFIX
        info = _load_session_metadata_info(info_path)

        raw_uploaded_at = info.get("uploaded_at")
        uploaded_at = raw_uploaded_at.strip() if isinstance(raw_uploaded_at, str) else None
        raw_original_name = info.get("original_filename")
        original_filename = (
            raw_original_name.strip() if isinstance(raw_original_name, str) and raw_original_name.strip() else None
        )

        try:
            mtime = os.path.getmtime(metadata_path)
        except OSError:
            mtime = None

        items.append(
            SessionMetadataItem(
                filename=filename,
                payload=payload,
                legal_header=legal_header,
                entry=entry,
                uploaded_at=uploaded_at,
                original_filename=original_filename,
                mtime=mtime,
            )
        )

    items.sort(key=lambda item: item.mtime or 0, reverse=True)
    _session_metadata_entry_ids = {id(item.entry) for item in items}
    return items


def delete_session_metadata_item(
    stored_filename: str, session_id: Optional[str] = None
) -> bool:
    active_session = session_id or _get_metadata_session_id(create=False)
    if not active_session:
        raise ValueError("No active metadata session.")

    safe_name = _validate_session_metadata_filename(stored_filename)
    directory = _session_metadata_directory(active_session, create=False)
    if not directory or not os.path.isdir(directory):
        return False

    metadata_path = os.path.join(directory, safe_name)
    if not os.path.exists(metadata_path):
        return False

    try:
        os.remove(metadata_path)
    except OSError as exc:
        app.logger.error(
            "Failed to delete session metadata %s: %s", metadata_path, exc
        )
        raise RuntimeError("Failed to delete the uploaded metadata file.") from exc

    info_path = metadata_path + _SESSION_METADATA_INFO_SUFFIX
    try:
        os.remove(info_path)
    except OSError:
        pass

    _prune_session_metadata_directory(directory)
    return True


def serialize_session_metadata_item(item: SessionMetadataItem) -> Dict[str, Any]:
    source: Dict[str, Any] = {
        "storedFilename": item.filename,
    }
    if item.original_filename:
        source["originalFilename"] = item.original_filename
    if item.uploaded_at:
        source["uploadedAt"] = item.uploaded_at
    if item.mtime is not None:
        source["modifiedAt"] = datetime.fromtimestamp(item.mtime, timezone.utc).isoformat()

    payload: Dict[str, Any] = {
        "entry": item.payload,
        "source": source,
    }
    if item.legal_header:
        payload["legalHeader"] = item.legal_header

    return payload


def _parse_http_datetime(value: Optional[str]) -> Optional[datetime]:
    """Best-effort parsing of an HTTP date header into an aware datetime."""

    if not value:
        return None

    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp into an aware datetime if possible."""

    if not value:
        return None

    text = value.strip()
    if not text:
        return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed


def _format_last_modified(header: Optional[str]) -> Optional[str]:
    """Convert an HTTP Last-Modified header to an ISO formatted string."""

    if not header:
        return None

    parsed = _parse_http_datetime(header)
    if parsed is None:
        return header

    return parsed.isoformat()


def _clean_metadata_cache_value(value: Any) -> Optional[str]:
    """Return a trimmed string value from cached metadata state if present."""

    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def load_metadata_cache_entry() -> Dict[str, Optional[str]]:
    """Load cached metadata headers used to describe the local metadata copy."""

    try:
        with open(MDS_METADATA_CACHE_PATH, "r", encoding="utf-8") as cache_file:
            cached = json.load(cache_file)
    except (OSError, ValueError, TypeError):
        cached = {}

    if not isinstance(cached, dict):
        cached = {}

    last_modified_header = _clean_metadata_cache_value(cached.get("last_modified"))
    last_modified_iso = _clean_metadata_cache_value(cached.get("last_modified_iso"))
    if not last_modified_iso and last_modified_header:
        last_modified_iso = _format_last_modified(last_modified_header)
    etag = _clean_metadata_cache_value(cached.get("etag"))
    fetched_at = _clean_metadata_cache_value(cached.get("fetched_at"))

    if not last_modified_header or not last_modified_iso:
        fallback_header, fallback_iso = _last_modified_from_metadata_file()
        last_modified_header = last_modified_header or fallback_header
        last_modified_iso = last_modified_iso or fallback_iso

    return {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": fetched_at,
    }


def _last_modified_from_metadata_file() -> Tuple[Optional[str], Optional[str]]:
    """Return HTTP and ISO formatted timestamps derived from the JSON metadata file."""

    try:
        mtime = os.path.getmtime(MDS_METADATA_PATH)
    except OSError:
        return None, None

    header = formatdate(mtime, usegmt=True)
    iso = datetime.fromtimestamp(mtime, timezone.utc).isoformat()
    return header, iso


def _load_base_metadata() -> Tuple[Optional[MetadataBlobPayload], Optional[float]]:
    global _base_metadata_cache, _base_metadata_mtime
    global _base_metadata_trust_verified, _base_metadata_entry_ids

    try:
        mtime = os.path.getmtime(MDS_METADATA_PATH)
    except OSError:
        mtime = None

    if _base_metadata_cache is not None and _base_metadata_mtime == mtime:
        return _base_metadata_cache, mtime

    metadata: Optional[MetadataBlobPayload] = None
    metadata_verified: Optional[bool] = None
    if mtime is not None:
        try:
            with open(MDS_METADATA_PATH, "r", encoding="utf-8") as metadata_file:
                payload = json.load(metadata_file)
            metadata = MetadataBlobPayload.from_dict(payload)
            metadata_verified = True
        except FileNotFoundError:
            metadata = None
            metadata_verified = None
        except Exception as exc:  # pylint: disable=broad-except
            app.logger.warning(
                "Failed to load MDS metadata from %s: %s",
                MDS_METADATA_PATH,
                exc,
            )
            metadata = None
            metadata_verified = False

    if metadata is not None:
        _base_metadata_entry_ids = {id(entry) for entry in metadata.entries}
    else:
        _base_metadata_entry_ids = set()

    _base_metadata_trust_verified = metadata_verified

    _base_metadata_cache = metadata
    _base_metadata_mtime = mtime
    return metadata, mtime


def metadata_entry_trust_anchor_status(entry: Any) -> Optional[bool]:
    """Return whether *entry* originates from a trust-anchored metadata source."""

    if entry is None or not isinstance(entry, MetadataBlobPayloadEntry):
        return None

    entry_id = id(entry)
    if entry_id in _session_metadata_entry_ids:
        return False
    if entry_id in _base_metadata_entry_ids:
        return _base_metadata_trust_verified

    return _base_metadata_trust_verified


def get_mds_verifier() -> Optional[MdsAttestationVerifier]:
    """Return an MDS attestation verifier using session metadata when available."""

    global _base_verifier_cache, _base_verifier_mtime

    base_metadata, base_mtime = _load_base_metadata()
    session_items = list_session_metadata_items()

    if not session_items:
        if base_metadata is None:
            _base_verifier_cache = None
            _base_verifier_mtime = base_mtime
            return None

        if (
            _base_verifier_cache is not None
            and _base_verifier_mtime is not None
            and _base_verifier_mtime == base_mtime
        ):
            return _base_verifier_cache

        verifier = MdsAttestationVerifier(base_metadata)
        _base_verifier_cache = verifier
        _base_verifier_mtime = base_mtime
        return verifier

    if base_metadata is None and not session_items:
        return None

    metadata = _merge_metadata(base_metadata, session_items)
    return MdsAttestationVerifier(metadata)


