"""The GitHub mirror: registrations and uploaded metadata, copied to the credential log repository.

``record_registration_event`` queues one JSON file per registration, for
``logs/<aaguid>/``, and ``queue_uploaded_metadata_files`` a visitor's uploaded metadata, for
``metadata/``, in the outbox (``github_outbox``); a worker delivers them (``deliver``). A
metadata file is not copied when an identical file is there, and none is replaced: one whose
name is taken goes beside it under its content's hash. The mirror is on only with a
``GITHUB_TOKEN``, and ``ENABLE_GITHUB_LOGGING=0`` turns it off.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import posixpath
import secrets
import threading
import time
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import client as http_client
from typing import Any
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request
from zoneinfo import ZoneInfo

import cbor2
from flask import Flask

from .. import aaguid, encoding
from ..encoding import encode_base64, encode_base64url
from ..env_flags import parse_env_flag
from ..json_values import make_json_safe
from . import github_outbox
from .github_outbox import Delivery, OutboxEntry

__all__ = [
    "GitHubUnavailable",
    "RegistrationEvent",
    "credential_log_repository",
    "deliver",
    "git_blob_sha",
    "github_metadata_blobs",
    "github_upload_file",
    "init_app",
    "is_logging_enabled",
    "queue_uploaded_metadata_files",
    "random_shortid",
    "record_registration_event",
    "registration_event",
    "safe_cbor_decode",
    "to_b64url",
    "uuid_bytes_to_str",
]

logger = logging.getLogger(__name__)

_API_BASE = "https://api.github.com"
_DEFAULT_REPO_OWNER = "rainzhang05"
_DEFAULT_REPO_NAME = "CredentialLogs"


def is_logging_enabled() -> bool:
    """Whether the credential log is on: only with a ``GITHUB_TOKEN`` to write with, and
    ``ENABLE_GITHUB_LOGGING=0`` turns it off. Without a token nothing is logged, and nothing
    warns that it was not."""

    if parse_env_flag("ENABLE_GITHUB_LOGGING") is False:
        return False
    return bool(os.environ.get("GITHUB_TOKEN", "").strip())


def credential_log_repository() -> tuple[str, str]:
    """Return the owner/name pair for the credential log repository."""

    owner = os.environ.get("GITHUB_LOG_REPO_OWNER", _DEFAULT_REPO_OWNER).strip()
    name = os.environ.get("GITHUB_LOG_REPO_NAME", _DEFAULT_REPO_NAME).strip()

    if not owner:
        owner = _DEFAULT_REPO_OWNER
    if not name:
        name = _DEFAULT_REPO_NAME

    return owner, name


class GitHubUnavailable(RuntimeError):
    """GitHub cannot take a delivery now: its answer is not what the mirror reads, or there is no
    token to write with. The entry waits in the outbox."""


def _token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        owner, name = credential_log_repository()
        raise GitHubUnavailable(
            f"GITHUB_TOKEN environment variable is required for credential logging to {owner}/{name}"
        )
    return token


def _api_url(path: str) -> str:
    """The API URL of ``path`` in the log repository, the path quoted: a file name may hold a
    space, ``#``, ``?`` or any other character a visitor's upload was named with."""

    path = urllib_parse.quote(path.lstrip("/"), safe="/")
    owner, name = credential_log_repository()
    return f"{_API_BASE}/repos/{owner}/{name}/{path}"


_DEFAULT_HTTP_TIMEOUT_SECONDS = 4.0


def _http_timeout() -> float:
    """Return the per-request GitHub timeout so a slow API cannot stall requests."""

    raw = os.environ.get("GITHUB_HTTP_TIMEOUT_SECONDS")
    try:
        value = float(raw) if raw else _DEFAULT_HTTP_TIMEOUT_SECONDS
    except ValueError:
        return _DEFAULT_HTTP_TIMEOUT_SECONDS
    return value if value > 0 else _DEFAULT_HTTP_TIMEOUT_SECONDS


def _request(method: str, url: str, body: dict[str, Any] | None = None) -> tuple[int, bytes]:
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib_request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {_token()}")
    req.add_header("User-Agent", "postquantum-webauthn-logger")
    if body is not None:
        req.add_header("Content-Type", "application/json")

    timeout = _http_timeout()
    # One retry, a second later, after a server error or a failure to connect.
    try:
        return _send(req, timeout)
    except urllib_error.HTTPError as exc:
        if not 500 <= exc.code < 600:
            raise
    except urllib_error.URLError as exc:
        # Retrying a timeout would double the worst-case request latency.
        if isinstance(exc.reason, TimeoutError):
            raise
    time.sleep(1)
    return _send(req, timeout)


def _send(req: urllib_request.Request, timeout: float) -> tuple[int, bytes]:
    with urllib_request.urlopen(req, timeout=timeout) as resp:
        return resp.getcode(), resp.read()


def _encode_content(data: bytes) -> str:
    return encode_base64(data)


def git_blob_sha(data: bytes) -> str:
    """Return the git blob SHA1 for ``data``."""

    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def github_upload_file(path: str, data: bytes, message: str) -> None:
    """Create a file at ``path`` with ``data`` in the log repository. It names no SHA, so GitHub
    refuses it (422) when a file is there: the mirror never replaces one."""

    body: dict[str, Any] = {
        "message": message,
        "content": _encode_content(data),
    }

    url = _api_url(f"contents/{path}")
    _request("PUT", url, body)


def _says_sha_was_not_supplied(exc: urllib_error.HTTPError) -> bool:
    """Whether GitHub's 422 says a file is at the path already: its message names the "sha" a
    replacement must give."""

    try:
        answer = json.loads(exc.read().decode("utf-8"))
    except (ValueError, OSError):
        return False
    message = answer.get("message") if isinstance(answer, Mapping) else None
    return isinstance(message, str) and '"sha"' in message


def _create_file(path: str, content: bytes, message: str) -> str | None:
    """Create ``path`` in the log repository with ``content``, never replacing a file.

    None when it was created. When GitHub says a file is there already, the blob SHA a read
    shows at ``path``, or "" while the read does not find it yet. Any other refusal raises.
    """

    try:
        github_upload_file(path, content, message)
        return None
    except urllib_error.HTTPError as exc:
        if exc.code != 422 or not _says_sha_was_not_supplied(exc):
            raise
    item = _get_json(f"contents/{path}", missing={})
    sha = item.get("sha") if isinstance(item, Mapping) else None
    return sha if isinstance(sha, str) else ""


def _get_json(path: str, *, missing: Any = None) -> Any:
    """GET ``path`` in the log repository and read its JSON; ``missing`` for a 404 when given."""

    try:
        _, body = _request("GET", _api_url(path))
    except urllib_error.HTTPError as exc:
        if exc.code == 404 and missing is not None:
            return missing
        raise
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError as exc:
        raise GitHubUnavailable(f"GitHub's answer for {path} is not JSON") from exc


def github_metadata_blobs() -> dict[str, str]:
    """Each file directly in the log repository's ``metadata/`` folder: its name and blob SHA.

    Read through the git trees API, which lists a whole folder (the contents API lists at most
    1,000 entries): the root's listing names the folder's tree, and the tree its files. An empty
    repository, or one without the folder, has none. A tree GitHub cuts short (past 100,000
    entries) is logged, and what it lists is used.
    """

    root = _get_json("contents/", missing=[])
    if not isinstance(root, list):
        raise GitHubUnavailable("GitHub's listing of the log repository is not a list")
    tree_sha = next(
        (
            item.get("sha")
            for item in root
            if isinstance(item, Mapping) and item.get("name") == _METADATA_REPO_FOLDER and item.get("type") == "dir"
        ),
        None,
    )
    if not isinstance(tree_sha, str):
        return {}
    tree = _get_json(f"git/trees/{tree_sha}")
    if not isinstance(tree, Mapping) or not isinstance(tree.get("tree"), list):
        raise GitHubUnavailable("GitHub's tree of the metadata folder holds no entries")
    if tree.get("truncated"):
        logger.info("GitHub listed the log repository's metadata folder in part")
    return {
        item["path"]: item["sha"]
        for item in tree["tree"]
        if isinstance(item, Mapping)
        and item.get("type") == "blob"
        and isinstance(item.get("path"), str)
        and isinstance(item.get("sha"), str)
    }


# Registration events, one JSON file per registration.

BEIJING_TZ = ZoneInfo("Asia/Shanghai")
_LOGS_DIR = "logs"


@dataclass(frozen=True)
class RegistrationEvent:
    """Data required to create a registration log entry."""

    timestamp: datetime
    rp_id: str
    aaguid: bytes | None
    device_name_mds: str | None
    attestation_object: bytes
    signature_valid: bool | None = None
    root_valid: bool | None = None
    rp_id_hash_valid: bool | None = None
    aaguid_match: bool | None = None


def registration_event(
    *,
    rp_id: str,
    aaguid: bytes | None,
    metadata_summary: Any,
    attestation_object: bytes,
    signature_valid: bool | None = None,
    root_valid: bool | None = None,
    rp_id_hash_valid: bool | None = None,
    aaguid_match: bool | None = None,
) -> RegistrationEvent:
    """The event for a registration now: the device's MDS description when its summary has one.

    The Simple tab passes the four attestation checks; the Advanced tab leaves them out.
    """

    metadata_description: str | None = None
    if isinstance(metadata_summary, Mapping):
        raw_description = metadata_summary.get("description")
        if isinstance(raw_description, str):
            metadata_description = raw_description

    return RegistrationEvent(
        timestamp=datetime.now(timezone.utc),
        rp_id=rp_id,
        aaguid=aaguid or None,
        device_name_mds=metadata_description,
        attestation_object=attestation_object,
        signature_valid=signature_valid,
        root_valid=root_valid,
        rp_id_hash_valid=rp_id_hash_valid,
        aaguid_match=aaguid_match,
    )


def to_b64url(data: bytes) -> str:
    """Encode *data* using base64url without padding."""

    if not data:
        return ""
    return encode_base64url(data)


def random_shortid(length: int = 8) -> str:
    """Return a cryptographically strong random identifier."""

    if length <= 0:
        raise ValueError("length must be positive")
    # token_hex returns two characters per byte; trim to the requested length.
    return secrets.token_hex((length + 1) // 2)[:length]


def uuid_bytes_to_str(value: bytes | None) -> str:
    """Convert binary UUID data to a canonical string representation."""

    if not value:
        return "unknown"
    guid = aaguid.guid(value)
    return guid if guid is not None else to_b64url(value)


def safe_cbor_decode(data: bytes | str) -> Mapping[str, Any]:
    """Decode a CBOR payload into JSON-safe data.

    On failure a dictionary containing ``{"error": "decode_failed"}`` is returned.
    """

    payload: bytes | None
    if isinstance(data, (bytes, bytearray, memoryview)):
        payload = bytes(data)
    elif isinstance(data, str):
        payload = encoding.try_decode_base64url(data)
    else:
        payload = None

    if not payload:
        return {"error": "decode_failed"}

    try:
        decoded = cbor2.loads(payload)
    except Exception:
        return {"error": "decode_failed"}

    json_safe = make_json_safe(decoded, string_keys=True)
    if isinstance(json_safe, Mapping):
        return json_safe
    return {"value": json_safe}


def _log_path(aaguid: str, timestamp: datetime) -> str:
    folder_name = aaguid or "unknown"
    if "/" in folder_name or ".." in folder_name:
        folder_name = "unknown"
    timestamp_label = timestamp.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{timestamp_label}_{random_shortid(6)}.json"
    return f"{_LOGS_DIR}/{folder_name}/{filename}"


def _build_log_payload(event: RegistrationEvent) -> tuple[str, Mapping[str, Any]]:
    timestamp_local = event.timestamp.astimezone(BEIJING_TZ).replace(microsecond=0)
    timestamp_iso = timestamp_local.isoformat()

    aaguid_bytes = event.aaguid if isinstance(event.aaguid, (bytes, bytearray, memoryview)) else None
    aaguid_str = uuid_bytes_to_str(bytes(aaguid_bytes) if aaguid_bytes else None)

    attestation_bytes = bytes(event.attestation_object)
    attestation_raw = to_b64url(attestation_bytes)
    attestation_decoded = safe_cbor_decode(attestation_bytes)

    path = _log_path(aaguid_str, event.timestamp)

    payload: MutableMapping[str, Any] = {
        "timestamp": timestamp_iso,
        "rp_id": event.rp_id,
        "aaguid": aaguid_str,
        "device_name_mds": event.device_name_mds or "unknown",
        "raw_attestation_object": attestation_raw,
        "decoded_attestation_object": attestation_decoded,
        "signature_valid": event.signature_valid,
        "root_valid": event.root_valid,
        "rp_id_hash_valid": event.rp_id_hash_valid,
        "aaguid_match": event.aaguid_match,
    }

    return path, payload


def _registration_entry(event: RegistrationEvent) -> OutboxEntry:
    """A registration's log entry as the outbox keeps it: its path, fixed now, and its JSON."""

    path, payload = _build_log_payload(event)
    filename = posixpath.basename(path)
    folder = posixpath.basename(posixpath.dirname(path)) or "unknown"
    content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    return OutboxEntry("registration", path, f"add: {filename} (AAGUID={folder})", content)


def _start_flush(*, kick: bool) -> None:
    try:
        github_outbox.schedule_flush(deliver, kick=kick)
    except Exception:
        logger.warning("Could not start flushing the credential log outbox", exc_info=True)


def record_registration_event(event: RegistrationEvent) -> None:
    """Queue a saved registration's log entry for the credential log repository.

    Both tabs call it once the registration is saved. The entry waits in the outbox, at a
    path fixed now, and a worker delivers it (``github_outbox``): the registration's answer
    never waits for GitHub. Never raises: a failure is a warning, and the registration stands.
    """

    if not is_logging_enabled():
        return
    try:
        entry = _registration_entry(event)
    except Exception:
        logger.warning("Could not build the credential log entry of a registration for %s", event.rp_id, exc_info=True)
        return
    if github_outbox.enqueue([entry]):
        _start_flush(kick=True)


# Uploaded metadata, one copy per file.

_METADATA_REPO_FOLDER = "metadata"


def _safe_metadata_repo_filename(filename: str) -> str:
    candidate = os.path.basename(filename.strip()) if isinstance(filename, str) else ""
    if candidate in ("", ".", ".."):
        return "metadata.json"
    return candidate


def _metadata_entry(filename: str, content: bytes) -> OutboxEntry:
    """An uploaded metadata file as the outbox keeps it: at ``metadata/<its name>``."""

    name = _safe_metadata_repo_filename(filename)
    return OutboxEntry("metadata", f"{_METADATA_REPO_FOLDER}/{name}", f"metadata: add {name}", content)


def queue_uploaded_metadata_files(files: Sequence[tuple[str, bytes]]) -> None:
    """Queue uploaded metadata files, each whole and by its name, for the log repository's
    ``metadata/`` folder.

    The upload route calls it once some entry of each file was saved. The files wait in the
    outbox and a worker delivers them (``github_outbox``): the upload's answer never waits for
    GitHub. Never raises.
    """

    if not is_logging_enabled():
        return
    entries = [_metadata_entry(name, content) for name, content in files if content]
    if entries and github_outbox.enqueue(entries):
        _start_flush(kick=True)


@dataclass
class RecentMetadata:
    """The metadata this process delivered lately, by blob SHA: a tree read just after a delivery
    may not show it yet, and the same content queued under another name is not copied twice."""

    delivered: dict[str, float] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


RECENT_METADATA = RecentMetadata()
_RECENT_SECONDS = 600.0


def _delivered_lately(blob_sha: str) -> bool:
    now = time.time()
    with RECENT_METADATA.lock:
        RECENT_METADATA.delivered = {
            sha: when for sha, when in RECENT_METADATA.delivered.items() if 0 <= now - when < _RECENT_SECONDS
        }
        return blob_sha in RECENT_METADATA.delivered


def _deliver_metadata(entry: OutboxEntry) -> Delivery:
    """An uploaded metadata file, unless its content is in the folder already under any name;
    at its queued path, or beside a file of other content there under its hashed name."""

    name = posixpath.basename(entry.path)
    blob_sha = git_blob_sha(entry.content)
    existing = github_metadata_blobs()
    same = next((there for there, sha in existing.items() if sha == blob_sha), None)
    if same is not None or _delivered_lately(blob_sha):
        logger.info(
            "Skipping upload of metadata file %s; identical content already present as %s.",
            name,
            same or "a file delivered lately",
        )
        return Delivery.DELIVERED
    try:
        _create_metadata_file(name, entry.content, blob_sha, name_taken=name in existing)
    except _PathTaken as exc:
        logger.warning("Dropped metadata file %s: %s", name, exc)
        return Delivery.DROPPED
    with RECENT_METADATA.lock:
        RECENT_METADATA.delivered[blob_sha] = time.time()
    logger.info("Delivered %s to the credential log", entry.path)
    return Delivery.DELIVERED


def _deliver_log(entry: OutboxEntry) -> Delivery:
    """A registration's log entry, at its path: found there already, it was delivered before."""

    there = _create_file(entry.path, entry.content, entry.message)
    if there is not None and there not in ("", git_blob_sha(entry.content)):
        logger.warning("Dropped %s: the log repository holds another file at its path", entry.path)
        return Delivery.DROPPED
    logger.info("Delivered %s to the credential log", entry.path)
    return Delivery.DELIVERED


# GitHub's answers that say it cannot take a file now: the token, its scope or the repository
# (401, 403, 404), a timeout, a commit racing another (409), its rate limits; and every 5xx.
_UNAVAILABLE_STATUSES = frozenset({401, 403, 404, 408, 409, 429})


def deliver(entry: OutboxEntry) -> Delivery:
    """Copy one queued entry to its path in the log repository (``github_outbox.flush`` calls it).

    DELIVERED when it is there, put now or found from an earlier delivery; UNAVAILABLE when
    GitHub, the network or the token cannot take it now (it stays queued); DROPPED when GitHub
    refuses it for good, or it cannot be read. Never raises.
    """

    try:
        if entry.kind == "metadata":
            return _deliver_metadata(entry)
        return _deliver_log(entry)
    except urllib_error.HTTPError as exc:
        if exc.code in _UNAVAILABLE_STATUSES or exc.code >= 500:
            logger.warning("GitHub could not take %s now (HTTP %s); it stays queued", entry.path, exc.code)
            return Delivery.UNAVAILABLE
        logger.warning("GitHub refused %s (HTTP %s): dropped", entry.path, exc.code)
        return Delivery.DROPPED
    except (GitHubUnavailable, OSError, http_client.HTTPException) as exc:
        logger.warning("GitHub could not take %s now; it stays queued: %s", entry.path, exc)
        return Delivery.UNAVAILABLE
    except Exception:
        logger.warning("Dropped %s from the credential log: it could not be delivered", entry.path, exc_info=True)
        return Delivery.DROPPED


def _hashed_metadata_path(name: str, blob_sha: str) -> str:
    """Where a metadata file goes when its name holds other content: the name with the start of
    its content's blob SHA, so the same content always lands at the same path."""

    stem, extension = os.path.splitext(name)
    return f"{_METADATA_REPO_FOLDER}/{stem}-{blob_sha[:12]}{extension}"


def _create_metadata_file(name: str, content: bytes, blob_sha: str, *, name_taken: bool) -> bool:
    """Add a metadata file, never replacing one: at ``metadata/<name>``, or, when that name holds
    other content, at its hashed name. True when it was added, False when its content was found
    at the path already (an earlier copy landed); raises when neither path can take it."""

    if not name_taken:
        there = _create_file(f"{_METADATA_REPO_FOLDER}/{name}", content, f"metadata: add {name}")
        if there is None:
            return True
        if there == blob_sha:
            return False
        if not there:
            raise GitHubUnavailable(f"GitHub has a file at metadata/{name} that it does not show yet")
    hashed = _hashed_metadata_path(name, blob_sha)
    there = _create_file(hashed, content, f"metadata: add {os.path.basename(hashed)}")
    if there is None:
        return True
    if there in ("", blob_sha):
        return False
    raise _PathTaken(f"another file is at {hashed}")


class _PathTaken(Exception):
    """Another file holds the only path left for a metadata file: it is dropped."""


def _flush_when_due() -> None:
    if is_logging_enabled():
        _start_flush(kick=False)


def init_app(app: Flask) -> None:
    """Flush the credential log's outbox while requests come in: each request starts a run on a
    worker when one is due (``github_outbox.schedule_flush``), so the outbox drains while Cloud
    Run gives the instance CPU, and never in a request's own time."""

    app.before_request(_flush_when_due)
