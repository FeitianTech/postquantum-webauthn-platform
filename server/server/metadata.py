"""Metadata handling utilities for the WebAuthn demo server."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import ssl
import tempfile
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.utils import formatdate, parsedate_to_datetime
from typing import Any, Dict, Iterator, List, Mapping, Optional, Set, Tuple

from flask import has_request_context, session

from fido2.mds3 import (
    MetadataBlobPayload,
    MetadataBlobPayloadEntry,
    MdsAttestationVerifier,
    parse_blob,
)

from .config import (
    MDS_METADATA_CACHE_PATH,
    MDS_METADATA_PATH,
    MDS_METADATA_URL,
    MDS_TLS_ADDITIONAL_TRUST_ANCHORS_PEM,
    SESSION_METADATA_DIR,
    app,
    FIDO_METADATA_TRUST_ROOT_CERT,
    FIDO_METADATA_TRUST_ROOT_PEM,
)

try:  # pragma: no cover - optional dependency
    import certifi
except ImportError:  # pragma: no cover - optional dependency
    certifi = None  # type: ignore[assignment]

__all__ = [
    "MetadataDownloadError",
    "download_metadata_blob",
    "get_mds_verifier",
    "load_metadata_cache_entry",
    "ensure_metadata_session_id",
    "list_session_metadata_items",
    "save_session_metadata_item",
    "serialize_session_metadata_item",
    "delete_session_metadata_item",
]


_base_metadata_cache: Optional[MetadataBlobPayload] = None
_base_metadata_mtime: Optional[float] = None
_base_verifier_cache: Optional[MdsAttestationVerifier] = None
_base_verifier_mtime: Optional[float] = None

_SESSION_METADATA_SUFFIX = ".json"
_SESSION_METADATA_INFO_SUFFIX = ".meta.json"
_SESSION_METADATA_SESSION_KEY = "fido.mds.session"


@dataclass(frozen=True)
class SessionMetadataItem:
    filename: str
    payload: Dict[str, Any]
    legal_header: Optional[str]
    entry: MetadataBlobPayloadEntry
    uploaded_at: Optional[str]
    original_filename: Optional[str]
    mtime: Optional[float]


def _get_metadata_session_id(*, create: bool = False) -> Optional[str]:
    if not has_request_context():
        return None

    existing = session.get(_SESSION_METADATA_SESSION_KEY)
    if isinstance(existing, str) and existing.strip():
        return existing.strip()

    if not create:
        return None

    identifier = secrets.token_urlsafe(32)
    session[_SESSION_METADATA_SESSION_KEY] = identifier
    return identifier


def ensure_metadata_session_id() -> str:
    identifier = _get_metadata_session_id(create=True)
    if not identifier:
        raise RuntimeError("Unable to establish metadata session identifier.")
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
    metadata_statement: Dict[str, Any] = {}
    legal_header: Optional[str] = None

    raw_legal_header = raw.get("legalHeader")
    if isinstance(raw_legal_header, str):
        legal_header = raw_legal_header.strip() or None

    excluded_keys = {
        "statusReports",
        "timeOfLastStatusChange",
        "attestationCertificateKeyIdentifiers",
        "aaid",
        "aaguid",
    }

    for key, value in raw.items():
        if key in excluded_keys:
            continue
        cloned = _clone_json_value(value)
        if cloned is not None:
            metadata_statement[key] = cloned

    if legal_header and "legalHeader" not in metadata_statement:
        metadata_statement["legalHeader"] = legal_header

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
    active_session = session_id or _get_metadata_session_id(create=False)
    if not active_session:
        return []

    directory = _session_metadata_directory(active_session, create=False)
    if not directory or not os.path.isdir(directory):
        return []

    try:
        filenames = [
            name
            for name in os.listdir(directory)
            if name.endswith(_SESSION_METADATA_SUFFIX)
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


class MetadataDownloadError(Exception):
    """Raised when the FIDO MDS metadata cannot be downloaded."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        retry_after: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


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
    """Load cached metadata headers used for conditional download requests."""

    try:
        with open(MDS_METADATA_CACHE_PATH, "r", encoding="utf-8") as cache_file:
            cached = json.load(cache_file)
    except (OSError, ValueError, TypeError):
        return {}

    if not isinstance(cached, dict):
        return {}

    last_modified_header = _clean_metadata_cache_value(cached.get("last_modified"))
    last_modified_iso = _clean_metadata_cache_value(cached.get("last_modified_iso"))
    if not last_modified_iso and last_modified_header:
        last_modified_iso = _format_last_modified(last_modified_header)
    etag = _clean_metadata_cache_value(cached.get("etag"))
    fetched_at = _clean_metadata_cache_value(cached.get("fetched_at"))

    return {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": fetched_at,
    }


def _store_metadata_cache_entry(
    *,
    last_modified_header: Optional[str],
    last_modified_iso: Optional[str],
    etag: Optional[str],
) -> None:
    """Persist cached metadata download headers for future requests."""

    payload = {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        os.makedirs(os.path.dirname(MDS_METADATA_CACHE_PATH), exist_ok=True)
        with open(MDS_METADATA_CACHE_PATH, "w", encoding="utf-8") as cache_file:
            json.dump(payload, cache_file, indent=2, sort_keys=True)
            cache_file.write("\n")
    except OSError:
        pass


def _guess_last_modified_from_path(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Derive Last-Modified headers from the local file mtime when possible."""

    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None, None

    header = formatdate(mtime, usegmt=True)
    iso = datetime.fromtimestamp(mtime, timezone.utc).isoformat()
    return header, iso


def _apply_last_modified_timestamp(
    path: str,
    header: Optional[str],
    iso: Optional[str],
) -> None:
    """Update the local file mtime to match the metadata Last-Modified value."""

    timestamp_source = _parse_iso_datetime(iso) or _parse_http_datetime(header)
    if timestamp_source is None:
        return

    timestamp = timestamp_source.timestamp()
    try:
        os.utime(path, (timestamp, timestamp))
    except OSError:
        pass


def _is_certificate_verification_error(error: BaseException) -> bool:
    """Return True if the error represents a TLS certificate verification failure."""

    if isinstance(error, ssl.SSLCertVerificationError):
        return True

    if isinstance(error, ssl.SSLError):
        error_parts = [str(error)]
        if getattr(error, "reason", None):
            error_parts.append(str(error.reason))
        error_parts.extend(str(arg) for arg in getattr(error, "args", ()) if arg)
        combined = " ".join(part for part in error_parts if part)
        if "certificate verify failed" in combined.lower():
            return True

    message = str(error)
    return "certificate verify failed" in message.lower()


def _metadata_ssl_contexts() -> Iterator[ssl.SSLContext]:
    """Yield SSL contexts with different trust stores for the metadata download."""

    contexts = []

    try:
        contexts.append(ssl.create_default_context())
    except Exception:
        pass

    if certifi is not None:
        try:
            contexts.append(ssl.create_default_context(cafile=certifi.where()))
        except Exception:
            pass

    fallback_bundle = "\n".join(
        part.strip()
        for part in (
            FIDO_METADATA_TRUST_ROOT_PEM,
            MDS_TLS_ADDITIONAL_TRUST_ANCHORS_PEM,
        )
        if part.strip()
    )

    if fallback_bundle:
        fallback_bundle += "\n"

        try:
            fallback = ssl.create_default_context()
            fallback.load_verify_locations(cadata=fallback_bundle)
            contexts.append(fallback)
        except Exception:
            pass

    seen = set()
    for context in contexts:
        identifier = id(context)
        if identifier in seen:
            continue
        seen.add(identifier)
        yield context


def download_metadata_blob(
    source_url: str = MDS_METADATA_URL,
    destination: str = MDS_METADATA_PATH,
) -> Tuple[bool, int, Optional[str]]:
    """Fetch the FIDO MDS metadata BLOB and store it locally."""

    metadata_exists = os.path.exists(destination)
    cached_state = load_metadata_cache_entry()
    cached_last_modified = cached_state.get("last_modified")
    cached_last_modified_iso = cached_state.get("last_modified_iso")
    cached_etag = cached_state.get("etag")

    if metadata_exists and not cached_last_modified:
        fallback_header, fallback_iso = _guess_last_modified_from_path(destination)
        if fallback_header:
            cached_last_modified = fallback_header
            if not cached_last_modified_iso:
                cached_last_modified_iso = fallback_iso

    payload: Optional[bytes] = None
    last_modified_header: Optional[str] = None
    last_modified_iso: Optional[str] = None
    etag: Optional[str] = None
    last_cert_error: Optional[BaseException] = None

    for context in _metadata_ssl_contexts():
        headers: Dict[str, str] = {}
        if metadata_exists and cached_last_modified:
            headers["If-Modified-Since"] = cached_last_modified
        if metadata_exists and cached_etag:
            headers["If-None-Match"] = cached_etag

        request = urllib.request.Request(source_url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60, context=context) as response:
                status = getattr(response, "status", None) or response.getcode()
                if status != 200:
                    raise MetadataDownloadError(
                        f"Unexpected response status {status} while downloading metadata.",
                        status_code=status,
                    )
                payload = response.read()
                response_headers = getattr(response, "headers", None)
                if response_headers is not None:
                    last_modified_header = _clean_metadata_cache_value(
                        response_headers.get("Last-Modified")
                    )
                    etag = _clean_metadata_cache_value(response_headers.get("ETag"))
                else:
                    last_modified_header = None
                    etag = None
                last_modified_iso = _format_last_modified(last_modified_header)
                if last_modified_iso is None and cached_last_modified_iso:
                    last_modified_iso = cached_last_modified_iso
                break
        except urllib.error.HTTPError as exc:
            if exc.code == 304 and metadata_exists:
                header = cached_last_modified
                if exc.headers is not None:
                    header = header or _clean_metadata_cache_value(exc.headers.get("Last-Modified"))
                iso = cached_last_modified_iso or _format_last_modified(header)
                etag_header = None
                if exc.headers is not None:
                    etag_header = _clean_metadata_cache_value(exc.headers.get("ETag"))
                etag_to_store = etag_header or cached_etag
                _apply_last_modified_timestamp(destination, header, iso)
                _store_metadata_cache_entry(
                    last_modified_header=header,
                    last_modified_iso=iso,
                    etag=etag_to_store,
                )
                return False, 0, iso

            retry_after = None
            if exc.headers is not None:
                retry_after = _clean_metadata_cache_value(exc.headers.get("Retry-After"))
            raise MetadataDownloadError(
                f"Failed to download metadata (HTTP {exc.code}).",
                status_code=exc.code,
                retry_after=retry_after,
            ) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, BaseException) and _is_certificate_verification_error(reason):
                last_cert_error = reason
                continue
            if isinstance(reason, str) and "certificate verify failed" in reason.lower():
                last_cert_error = exc
                continue
            if _is_certificate_verification_error(exc):
                last_cert_error = exc
                continue
            raise MetadataDownloadError(
                f"Failed to reach FIDO Metadata Service: {reason}"
            ) from exc

    if payload is None:
        if last_cert_error is not None:
            message = "Failed to verify the TLS certificate for the FIDO Metadata Service."
            if str(last_cert_error):
                message = f"{message} ({last_cert_error})."
            raise MetadataDownloadError(message) from last_cert_error
        raise MetadataDownloadError("Failed to reach FIDO Metadata Service.")

    os.makedirs(os.path.dirname(destination), exist_ok=True)

    if metadata_exists and os.path.exists(destination):
        with open(destination, "rb") as existing_file:
            if existing_file.read() == payload:
                _apply_last_modified_timestamp(destination, last_modified_header, last_modified_iso)
                _store_metadata_cache_entry(
                    last_modified_header=last_modified_header,
                    last_modified_iso=last_modified_iso,
                    etag=etag or cached_etag,
                )
                return False, len(payload), last_modified_iso

    with tempfile.NamedTemporaryFile("wb", delete=False, dir=os.path.dirname(destination)) as temp_file:
        temp_file.write(payload)
        temp_path = temp_file.name

    try:
        shutil.move(temp_path, destination)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise

    _apply_last_modified_timestamp(destination, last_modified_header, last_modified_iso)
    _store_metadata_cache_entry(
        last_modified_header=last_modified_header,
        last_modified_iso=last_modified_iso,
        etag=etag,
    )

    return True, len(payload), last_modified_iso


def _load_base_metadata() -> Tuple[Optional[MetadataBlobPayload], Optional[float]]:
    global _base_metadata_cache, _base_metadata_mtime

    try:
        mtime = os.path.getmtime(MDS_METADATA_PATH)
    except OSError:
        mtime = None

    if _base_metadata_cache is not None and _base_metadata_mtime == mtime:
        return _base_metadata_cache, mtime

    metadata: Optional[MetadataBlobPayload] = None
    if mtime is not None:
        try:
            with open(MDS_METADATA_PATH, "rb") as blob_file:
                blob_data = blob_file.read()
            metadata = parse_blob(blob_data, FIDO_METADATA_TRUST_ROOT_CERT)
        except FileNotFoundError:
            metadata = None
        except Exception as exc:  # pylint: disable=broad-except
            app.logger.warning(
                "Failed to load MDS metadata from %s: %s",
                MDS_METADATA_PATH,
                exc,
            )
            metadata = None

    _base_metadata_cache = metadata
    _base_metadata_mtime = mtime
    return metadata, mtime


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


