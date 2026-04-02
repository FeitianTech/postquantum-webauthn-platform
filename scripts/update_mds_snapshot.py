#!/usr/bin/env python3
"""Refresh the packaged FIDO MDS snapshot if the remote BLOB has changed."""

from __future__ import annotations

import base64
import json
import sys
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from fido2.mds3 import parse_blob

REPO_ROOT = Path(__file__).resolve().parents[1]

FRONTEND_STATIC_DIR = REPO_ROOT / "frontend" / "static"

MDS_METADATA_URL = "https://mds3.fidoalliance.org/"
MDS_METADATA_FILENAME = "blob.jwt"
MDS_METADATA_PATH = FRONTEND_STATIC_DIR / MDS_METADATA_FILENAME
MDS_METADATA_VERIFIED_PATH = FRONTEND_STATIC_DIR / "fido-mds3.verified.json"
MDS_METADATA_CACHE_PATH = Path(str(MDS_METADATA_VERIFIED_PATH) + ".meta.json")

FIDO_METADATA_TRUST_ROOT_B64 = (
    "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G"
    "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp"
    "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4"
    "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG"
    "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI"
    "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8"
    "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT"
    "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm"
    "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd"
    "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ"
    "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw"
    "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o"
    "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU"
    "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp"
    "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK"
    "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX"
    "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs"
    "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH"
    "WD9f"
)
FIDO_METADATA_TRUST_ROOT_CERT = base64.b64decode(FIDO_METADATA_TRUST_ROOT_B64)


def _parse_http_datetime(value: str | None) -> datetime | None:
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


def format_last_modified_header(header: str | None) -> str | None:
    parsed = _parse_http_datetime(header)
    if parsed is None:
        return header
    return parsed.isoformat()


def store_metadata_cache_entry(
    *,
    last_modified_header: str | None,
    last_modified_iso: str | None,
    etag: str | None,
) -> None:
    payload = {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        MDS_METADATA_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        MDS_METADATA_CACHE_PATH.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def _fetch_remote_blob() -> tuple[bytes, str | None, str | None]:
    request = urllib.request.Request(
        MDS_METADATA_URL,
        headers={"User-Agent": "webauthnlab-mds-updater"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - trusted host
        payload = response.read()
        headers = response.headers or {}
        last_modified = headers.get("Last-Modified")
        etag = headers.get("ETag")
    return payload, last_modified, etag


def _write_blob(blob: bytes) -> None:
    path = Path(MDS_METADATA_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)


def _write_verified_snapshot(blob: bytes) -> None:
    payload = parse_blob(blob, FIDO_METADATA_TRUST_ROOT_CERT)
    snapshot = dict(payload)
    target = Path(MDS_METADATA_VERIFIED_PATH)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_cache_state(last_modified: str | None, etag: str | None) -> None:
    store_metadata_cache_entry(
        last_modified_header=last_modified,
        last_modified_iso=format_last_modified_header(last_modified),
        etag=etag,
    )

    cache_path = Path(MDS_METADATA_CACHE_PATH)
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:  # pragma: no cover - unexpected format
            data = {}
        if "fetched_at" not in data or not data["fetched_at"]:
            data["fetched_at"] = datetime.now(timezone.utc).isoformat()
            cache_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    try:
        new_blob, last_modified, etag = _fetch_remote_blob()
    except Exception as exc:  # pragma: no cover - network failure propagates
        print(f"::error::Failed to download metadata BLOB: {exc}")
        return 1

    current_path = Path(MDS_METADATA_PATH)
    if current_path.exists() and current_path.read_bytes() == new_blob:
        print("Packaged metadata is already up to date; no changes made.")
        return 0

    _write_blob(new_blob)
    _write_verified_snapshot(new_blob)
    _write_cache_state(last_modified, etag)

    print("Packaged metadata snapshot refreshed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
