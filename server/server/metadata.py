"""Metadata handling utilities for the WebAuthn demo server."""
from __future__ import annotations

import json
import os
import shutil
import ssl
import tempfile
import urllib.error
import urllib.request
from dataclasses import replace
from datetime import datetime, timezone
from email.utils import formatdate, parsedate_to_datetime
from typing import Any, Dict, Iterator, Optional, Tuple

from fido2.mds3 import (
    MetadataBlobPayload,
    MetadataBlobPayloadEntry,
    MdsAttestationVerifier,
)

from .config import (
    MDS_METADATA_CACHE_PATH,
    MDS_METADATA_PATH,
    MDS_METADATA_CACHE_STATIC_PATH,
    MDS_METADATA_URL,
    MDS_TLS_ADDITIONAL_TRUST_ANCHORS_PEM,
    MDS_VERIFIED_PAYLOAD_PATH,
    MDS_VERIFIED_PAYLOAD_STATIC_PATH,
    app,
    FEITIAN_PQC_METADATA_PATH,
    FIDO_METADATA_TRUST_ROOT_PEM,
)

try:  # pragma: no cover - optional dependency
    import certifi
except ImportError:  # pragma: no cover - optional dependency
    certifi = None  # type: ignore[assignment]

__all__ = [
    "MetadataDownloadError",
    "download_metadata_blob",
    "combine_with_local_metadata",
    "get_mds_verifier",
    "load_metadata_cache_entry",
]


_mds_verifier_cache: Optional[MdsAttestationVerifier] = None
_mds_verifier_mtime: Optional[float] = None


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

    def _load(path: Optional[str]) -> Optional[Dict[str, Any]]:
        if not path:
            return None
        try:
            with open(path, "r", encoding="utf-8") as cache_file:
                payload = json.load(cache_file)
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError):
            return None
        if not isinstance(payload, dict):
            return None
        return payload

    cached = _load(MDS_METADATA_CACHE_PATH) or _load(MDS_METADATA_CACHE_STATIC_PATH) or {}

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
    os.makedirs(os.path.dirname(destination), exist_ok=True)
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


def combine_with_local_metadata(
    payload: Optional[MetadataBlobPayload],
) -> Optional[MetadataBlobPayload]:
    """Merge verified metadata with bundled local entries if present."""

    feitian_entry, feitian_legal_header = _load_feitian_metadata_entry()

    if payload is None and feitian_entry is None:
        return None

    if payload is None and feitian_entry is not None:
        payload_dict = {
            "legalHeader": feitian_legal_header or "",
            "no": 0,
            "nextUpdate": datetime.now(timezone.utc).date().isoformat(),
            "entries": [dict(feitian_entry)],
        }
        try:
            return MetadataBlobPayload.from_dict(payload_dict)
        except Exception as exc:  # pragma: no cover - defensive
            app.logger.warning(
                "Failed to build metadata payload from %s: %s",
                FEITIAN_PQC_METADATA_PATH,
                exc,
            )
            return None

    if payload is None:
        return None

    if feitian_entry is not None:
        combined_entries = (feitian_entry,) + tuple(payload.entries)
        payload = replace(payload, entries=combined_entries)
        if feitian_legal_header and not getattr(payload, "legal_header", None):
            payload = replace(payload, legal_header=feitian_legal_header)

    return payload


def _load_verified_metadata_payload() -> Optional[MetadataBlobPayload]:
    """Load the cached, verified metadata payload if present."""

    paths = []
    if MDS_VERIFIED_PAYLOAD_PATH:
        paths.append(MDS_VERIFIED_PAYLOAD_PATH)
    if MDS_VERIFIED_PAYLOAD_STATIC_PATH and MDS_VERIFIED_PAYLOAD_STATIC_PATH not in paths:
        paths.append(MDS_VERIFIED_PAYLOAD_STATIC_PATH)

    raw_payload: Optional[Dict[str, Any]] = None
    for candidate in paths:
        try:
            with open(candidate, "r", encoding="utf-8") as payload_file:
                loaded = json.load(payload_file)
        except FileNotFoundError:
            continue
        except (OSError, ValueError, TypeError) as exc:
            app.logger.warning(
                "Failed to load verified metadata payload from %s: %s",
                candidate,
                exc,
            )
            continue
        if not isinstance(loaded, dict):
            app.logger.warning(
                "Verified metadata payload %s is not a JSON object.",
                candidate,
            )
            continue
        raw_payload = loaded
        break

    if raw_payload is None:
        return None

    try:
        return MetadataBlobPayload.from_dict(raw_payload)
    except Exception as exc:  # pragma: no cover - defensive
        app.logger.warning(
            "Failed to parse verified metadata payload from %s: %s",
            MDS_VERIFIED_PAYLOAD_PATH,
            exc,
        )
        return None


def get_mds_verifier() -> Optional[MdsAttestationVerifier]:
    """Return a cached MDS attestation verifier if metadata is available."""

    global _mds_verifier_cache, _mds_verifier_mtime

    try:
        verified_mtime = os.path.getmtime(MDS_VERIFIED_PAYLOAD_PATH)
    except OSError:
        verified_mtime = None

    try:
        verified_fallback_mtime = os.path.getmtime(MDS_VERIFIED_PAYLOAD_STATIC_PATH)
    except OSError:
        verified_fallback_mtime = None

    try:
        feitian_mtime = os.path.getmtime(FEITIAN_PQC_METADATA_PATH)
    except OSError:
        feitian_mtime = None

    mtimes = [
        value
        for value in (verified_mtime, verified_fallback_mtime, feitian_mtime)
        if value is not None
    ]
    combined_mtime = max(mtimes) if mtimes else None

    if (
        _mds_verifier_cache is not None
        and _mds_verifier_mtime is not None
        and _mds_verifier_mtime == combined_mtime
    ):
        return _mds_verifier_cache

    metadata = combine_with_local_metadata(_load_verified_metadata_payload())

    if metadata is None:
        _mds_verifier_cache = None
        _mds_verifier_mtime = combined_mtime
        return None

    verifier = MdsAttestationVerifier(metadata)
    _mds_verifier_cache = verifier
    _mds_verifier_mtime = combined_mtime
    return verifier


def _load_feitian_metadata_entry() -> Tuple[Optional[MetadataBlobPayloadEntry], Optional[str]]:
    """Load the bundled Feitian PQC metadata entry if present."""

    try:
        with open(FEITIAN_PQC_METADATA_PATH, "r", encoding="utf-8") as metadata_file:
            raw = json.load(metadata_file)
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError, TypeError) as exc:
        app.logger.warning(
            "Failed to load bundled metadata from %s: %s",
            FEITIAN_PQC_METADATA_PATH,
            exc,
        )
        return None, None

    if not isinstance(raw, dict):
        app.logger.warning(
            "Bundled metadata %s is not a JSON object.",
            FEITIAN_PQC_METADATA_PATH,
        )
        return None, None

    entry_payload: Dict[str, Any] = {}
    entry_payload["statusReports"] = list(raw.get("statusReports", []))
    time_of_last_status_change = raw.get("timeOfLastStatusChange")
    if isinstance(time_of_last_status_change, str) and time_of_last_status_change.strip():
        entry_payload["timeOfLastStatusChange"] = time_of_last_status_change.strip()
    else:
        entry_payload["timeOfLastStatusChange"] = datetime.now(timezone.utc).date().isoformat()

    for key in ("aaid", "aaguid", "attestationCertificateKeyIdentifiers"):
        if key in raw:
            entry_payload[key] = raw[key]

    metadata_statement_fields = {
        key: value
        for key, value in raw.items()
        if key
        not in {
            "statusReports",
            "timeOfLastStatusChange",
            "attestationCertificateKeyIdentifiers",
        }
    }
    if "legalHeader" not in metadata_statement_fields and raw.get("legalHeader"):
        metadata_statement_fields["legalHeader"] = raw["legalHeader"]
    entry_payload["metadataStatement"] = metadata_statement_fields

    try:
        entry = MetadataBlobPayloadEntry.from_dict(entry_payload)
    except Exception as exc:
        app.logger.warning(
            "Failed to parse bundled metadata entry from %s: %s",
            FEITIAN_PQC_METADATA_PATH,
            exc,
        )
        return None, None

    legal_header = None
    if isinstance(raw.get("legalHeader"), str):
        legal_header = raw["legalHeader"].strip() or None

    return entry, legal_header
