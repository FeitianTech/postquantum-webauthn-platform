"""Utilities for refreshing the cached FIDO MDS metadata once per day."""
from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import ssl
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, time as time_of_day, timedelta, timezone
from email.utils import parsedate_to_datetime
from threading import Event
from typing import Dict, Iterable, Optional, Tuple

from fido2.mds3 import parse_blob

from server.server.config import (
    FIDO_METADATA_TRUST_ROOT_CERT,
    FIDO_METADATA_TRUST_ROOT_PEM,
    MDS_METADATA_CACHE_PATH,
    MDS_METADATA_PATH,
    MDS_METADATA_URL,
    MDS_TLS_ADDITIONAL_TRUST_ANCHORS_PEM,
)
from server.server.metadata import load_metadata_cache_entry

try:  # pragma: no cover - optional dependency
    import certifi
except ImportError:  # pragma: no cover - optional dependency
    certifi = None  # type: ignore[assignment]


LOGGER = logging.getLogger("updater.mds")


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


def _clean_metadata_cache_value(value: object) -> Optional[str]:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def _parse_http_datetime(value: Optional[str]) -> Optional[datetime]:
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
    if not header:
        return None

    parsed = _parse_http_datetime(header)
    if parsed is None:
        return header

    return parsed.isoformat()


def _store_metadata_cache_entry(
    *,
    last_modified_header: Optional[str],
    last_modified_iso: Optional[str],
    etag: Optional[str],
) -> None:
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
        LOGGER.debug("Unable to persist metadata cache state.")


def _apply_last_modified_timestamp(
    path: str,
    header: Optional[str],
    iso: Optional[str],
) -> None:
    timestamp_source = _parse_iso_datetime(iso) or _parse_http_datetime(header)
    if timestamp_source is None:
        return

    timestamp = timestamp_source.timestamp()
    try:
        os.utime(path, (timestamp, timestamp))
    except OSError:
        LOGGER.debug("Unable to adjust timestamp for %s.", path)


def _is_certificate_verification_error(error: BaseException) -> bool:
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


def _metadata_ssl_contexts() -> Iterable[ssl.SSLContext]:
    contexts = []

    try:
        contexts.append(ssl.create_default_context())
    except Exception:  # pragma: no cover - best effort
        pass

    if certifi is not None:
        try:
            contexts.append(ssl.create_default_context(cafile=certifi.where()))
        except Exception:  # pragma: no cover - best effort
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
        except Exception:  # pragma: no cover - best effort
            pass

    seen = set()
    for context in contexts:
        identifier = id(context)
        if identifier in seen:
            continue
        seen.add(identifier)
        yield context


def _decode_jws_payload(blob: bytes) -> Dict[str, object]:
    try:
        header_segment, payload_segment, _signature_segment = blob.split(b".", 2)
    except ValueError as exc:  # pragma: no cover - defensive
        raise MetadataDownloadError("Invalid metadata BLOB format.") from exc

    if not payload_segment:
        raise MetadataDownloadError("Metadata BLOB payload segment missing.")

    padding = b"=" * (-len(payload_segment) % 4)
    decoded = base64.urlsafe_b64decode(payload_segment + padding)
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - defensive
        raise MetadataDownloadError("Metadata payload is not valid UTF-8.") from exc

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise MetadataDownloadError("Metadata payload does not contain valid JSON.") from exc


def download_metadata_json() -> Tuple[bool, int, Optional[str]]:
    metadata_exists = os.path.exists(MDS_METADATA_PATH)
    cached_state = load_metadata_cache_entry()
    cached_last_modified = cached_state.get("last_modified") if cached_state else None
    cached_last_modified_iso = cached_state.get("last_modified_iso") if cached_state else None
    cached_etag = cached_state.get("etag") if cached_state else None

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

        request = urllib.request.Request(MDS_METADATA_URL, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60, context=context) as response:
                status = getattr(response, "status", None) or response.getcode()
                if status == 304:
                    iso = cached_last_modified_iso or _format_last_modified(cached_last_modified)
                    _store_metadata_cache_entry(
                        last_modified_header=cached_last_modified,
                        last_modified_iso=iso,
                        etag=cached_etag,
                    )
                    return False, 0, iso
                if status != 200:
                    raise MetadataDownloadError(
                        f"Unexpected response status {status} while downloading metadata.",
                        status_code=status,
                    )
                payload = response.read()
                response_headers = getattr(response, "headers", None)
                if response_headers is not None:
                    last_modified_header = _clean_metadata_cache_value(response_headers.get("Last-Modified"))
                    etag = _clean_metadata_cache_value(response_headers.get("ETag"))
                else:
                    last_modified_header = None
                    etag = None
                last_modified_iso = _format_last_modified(last_modified_header)
                if last_modified_iso is None and cached_last_modified_iso:
                    last_modified_iso = cached_last_modified_iso
                break
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                etag_to_store = cached_etag or _clean_metadata_cache_value(
                    exc.headers.get("ETag") if exc.headers is not None else None
                )
                iso = cached_last_modified_iso or (
                    _format_last_modified(cached_last_modified) if cached_last_modified else None
                )
                _store_metadata_cache_entry(
                    last_modified_header=cached_last_modified,
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

    try:
        parse_blob(payload, FIDO_METADATA_TRUST_ROOT_CERT)
    except Exception as exc:  # pragma: no cover - defensive
        raise MetadataDownloadError("Failed to verify metadata BLOB signature.") from exc

    metadata_dict = _decode_jws_payload(payload)
    metadata_json = json.dumps(metadata_dict, indent=2, sort_keys=True)
    metadata_bytes = (metadata_json + "\n").encode("utf-8")

    existing_bytes: Optional[bytes] = None
    if metadata_exists and os.path.exists(MDS_METADATA_PATH):
        try:
            with open(MDS_METADATA_PATH, "rb") as existing_file:
                existing_bytes = existing_file.read()
        except OSError:
            existing_bytes = None

    if existing_bytes == metadata_bytes:
        _apply_last_modified_timestamp(MDS_METADATA_PATH, last_modified_header, last_modified_iso)
        _store_metadata_cache_entry(
            last_modified_header=last_modified_header,
            last_modified_iso=last_modified_iso,
            etag=etag or cached_etag,
        )
        return False, len(metadata_bytes), last_modified_iso

    os.makedirs(os.path.dirname(MDS_METADATA_PATH), exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", delete=False, dir=os.path.dirname(MDS_METADATA_PATH)) as temp_file:
        temp_file.write(metadata_bytes)
        temp_path = temp_file.name

    try:
        shutil.move(temp_path, MDS_METADATA_PATH)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise

    _apply_last_modified_timestamp(MDS_METADATA_PATH, last_modified_header, last_modified_iso)
    _store_metadata_cache_entry(
        last_modified_header=last_modified_header,
        last_modified_iso=last_modified_iso,
        etag=etag,
    )

    return True, len(metadata_bytes), last_modified_iso


@dataclass
class DailySchedule:
    hour: int = 18
    minute: int = 0

    def most_recent(self, now: datetime) -> datetime:
        target = datetime.combine(now.date(), time_of_day(self.hour, self.minute, tzinfo=timezone.utc))
        if now >= target:
            return target
        return target - timedelta(days=1)

    def next_after(self, now: datetime) -> datetime:
        target = datetime.combine(now.date(), time_of_day(self.hour, self.minute, tzinfo=timezone.utc))
        if now < target:
            return target
        return target + timedelta(days=1)


class DailyMdsUpdater:
    """Background job that refreshes the cached metadata once per day."""

    def __init__(
        self,
        *,
        schedule: DailySchedule | None = None,
        retry_interval: int = 900,
        min_sleep: int = 300,
        max_sleep: int = 1800,
    ) -> None:
        self.schedule = schedule or DailySchedule()
        self.retry_interval = retry_interval
        self.min_sleep = min_sleep
        self.max_sleep = max_sleep
        self._stop_event = Event()
        self.logger = LOGGER

    def request_stop(self) -> None:
        self._stop_event.set()

    def _load_last_refresh_time(self) -> Optional[datetime]:
        cached = load_metadata_cache_entry()
        fetched_at = _clean_metadata_cache_value(cached.get("fetched_at")) if cached else None
        candidate = _parse_iso_datetime(fetched_at)
        if candidate is not None:
            return candidate

        try:
            mtime = os.path.getmtime(MDS_METADATA_PATH)
        except OSError:
            return None
        return datetime.fromtimestamp(mtime, timezone.utc)

    def _should_run(self, now: datetime) -> bool:
        last_refresh = self._load_last_refresh_time()
        if last_refresh is None:
            return True
        return last_refresh < self.schedule.most_recent(now)

    def _sleep_interval(self, now: datetime, *, due: bool) -> float:
        if due:
            return float(self.retry_interval)
        next_run = self.schedule.next_after(now)
        delta = max(0.0, (next_run - now).total_seconds())
        return float(delta)

    def run_forever(self) -> None:
        self.logger.info(
            "Starting FIDO MDS updater (daily at %02d:%02d UTC).",
            self.schedule.hour,
            self.schedule.minute,
        )

        while not self._stop_event.is_set():
            now = datetime.now(timezone.utc)
            due = self._should_run(now)
            sleep_seconds: float
            try:
                if due:
                    self.logger.info("Checking FIDO metadata for updates…")
                    updated, bytes_written, last_modified = download_metadata_json()
                    if updated:
                        if last_modified:
                            self.logger.info(
                                "Refreshed FIDO metadata (%d bytes written, Last-Modified: %s).",
                                bytes_written,
                                last_modified,
                            )
                        else:
                            self.logger.info("Refreshed FIDO metadata (%d bytes written).", bytes_written)
                    else:
                        if last_modified:
                            self.logger.info(
                                "FIDO metadata already up to date (Last-Modified: %s).",
                                last_modified,
                            )
                        else:
                            self.logger.info("FIDO metadata already up to date.")
                sleep_seconds = self._sleep_interval(now, due=due)
            except MetadataDownloadError as exc:
                self.logger.warning("Metadata update failed: %s", exc)
                sleep_seconds = float(self.retry_interval)
            except Exception:  # pragma: no cover - defensive
                self.logger.exception("Unexpected error while updating FIDO metadata.")
                sleep_seconds = float(self.retry_interval)

            sleep_seconds = max(float(self.min_sleep), min(float(self.max_sleep), sleep_seconds))
            self._stop_event.wait(timeout=sleep_seconds)

        self.logger.info("FIDO MDS updater stopped.")


__all__ = [
    "DailyMdsUpdater",
    "MetadataDownloadError",
    "download_metadata_json",
]
