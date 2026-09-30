"""Credential storage helpers for the demo server backed by pluggable storage.

Two properties this module is responsible for, both of which used to be absent:

**Containment.** ``name`` is attacker supplied -- it arrives as ``?email=`` --
and it is interpolated into a filesystem path and a GCS object key. Every such
identifier goes through :func:`validate_storage_component` and every resolved
path goes through :func:`resolve_contained_path` / :func:`assert_contained_blob_name`.

**A safe on-disk format.** Records are stored as JSON; the format is
``record_format``'s.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

from .. import visitor_session
from ..config.paths import store_dir
from ..json_values import make_json_safe
from . import record_format
from .cloud import (
    build_blob_name,
    download_bytes,
    download_bytes_with_generation,
    gcs_enabled,
    upload_bytes_if_generation,
)
from .common import (
    StorageReadError,
    assert_contained_blob_name,
    build_session_scoped_prefix,
    file_digest,
    file_lock,
    replace_file,
    resolve_contained_path,
    resolve_session_id,
    using_gcs_backend,
    validate_storage_component,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CredentialsUndecodable",
    "add_public_key_material",
    "read_for_update",
    "readkey",
    "save_if_unchanged",
]


_USER_FOLDER_PREFIX = "user-data"
_USER_CREDENTIAL_SUBDIR = "credentials"



def _local_credential_base() -> str:
    """The local store's root: under the instance folder (gitignored), not next to
    the source. ``FIDO_SERVER_CREDENTIAL_DIR`` moves it, e.g. onto a mounted volume."""

    return store_dir("FIDO_SERVER_CREDENTIAL_DIR", "session-credentials")


_JSON_SUFFIX = "_credential_data.json"


class CredentialsUndecodable(Exception):
    """The user's copy of their credentials exists, but its content does not decode.

    Raised by :func:`read_for_update` alone: the save that follows would replace
    a copy nobody could read. Reads that only show records skip it with a warning.
    """


def _using_gcs() -> bool:
    return using_gcs_backend(gcs_enabled)


def _validate_name(name: Any) -> str:
    return validate_storage_component(
        name,
        type_error="Credential identifier must be a string",
        empty_error="Credential identifier is empty",
    )


def _validate_session_id(session_id: Any) -> str:
    return validate_storage_component(
        session_id,
        type_error="Session identifier must be a string",
        empty_error="Session identifier is empty",
    )


def _credential_prefix(session_id: str) -> str:
    return build_session_scoped_prefix(
        _validate_session_id(session_id),
        user_folder_prefix=_USER_FOLDER_PREFIX,
        subdir=_USER_CREDENTIAL_SUBDIR,
    )


def _credential_blob(name: str, session_id: str) -> str:
    cleaned = _validate_name(name)
    prefix = _credential_prefix(session_id)
    blob_name = build_blob_name(f"{cleaned}{_JSON_SUFFIX}", prefix=prefix)
    return assert_contained_blob_name(blob_name, prefix=prefix)


def _make_session_directory(root: str, directory: str) -> None:
    """Create a session's directory, and give the store's root a ``.gitignore``
    that ignores everything in it (``*``) when it has none.

    ``FIDO_SERVER_CREDENTIAL_DIR`` may name a folder inside a checkout, where
    nothing else keeps git from offering the credentials for a commit."""

    os.makedirs(directory, exist_ok=True)
    ignore = os.path.join(root, ".gitignore")
    if not os.path.exists(ignore):
        replace_file(ignore, b"# Written by the credential store: nothing here belongs in git.\n*\n")


def _local_filename(name: str, session_id: str, *, create: bool = False) -> str:
    root = _local_credential_base()
    cleaned_session = _validate_session_id(session_id)
    cleaned_name = _validate_name(name)
    if create:
        _make_session_directory(root, resolve_contained_path(root, cleaned_session))
    # Contained against the store root rather than the session directory, so a
    # session id and a name cannot combine to climb out.
    return resolve_contained_path(root, cleaned_session, f"{cleaned_name}{_JSON_SUFFIX}")


def _resolve_session_id(session_id: str | None = None) -> str:
    return resolve_session_id(session_id, visitor_session.ensure_id)


def read_for_update(name: str, *, session_id: str | None = None) -> tuple[list[Any], Any]:
    """``readkey``, and the version of the copy a later save would replace.

    The version is opaque: the object's generation on GCS (0 when there is no
    object), the SHA-256 of the file locally (``None`` when there is no file).
    Hand it to :func:`save_if_unchanged`. A copy that does not decode raises
    :class:`CredentialsUndecodable` rather than reading as ``[]``.
    """

    resolved_session = _resolve_session_id(session_id)
    if _using_gcs():
        source = _credential_blob(name, resolved_session)
        try:
            payload, version = download_bytes_with_generation(source)
        except Exception as exc:
            raise StorageReadError(f"Could not read {source}") from exc
    else:
        source = _local_filename(name, resolved_session)
        payload = _read_local_copy(source)
        version = hashlib.sha256(payload).hexdigest() if payload is not None else None

    if payload is None:
        return [], version
    try:
        return record_format.decode_payload(payload), version
    except record_format.UndecodableRecords as exc:
        raise CredentialsUndecodable(f"Could not decode {source}: {exc}") from None


def save_if_unchanged(name: str, key: Any, version: Any, *, session_id: str | None = None) -> bool:
    """Save ``key`` as ``name``'s records, only if the copy it replaces is still at ``version``.

    Compare-and-swap for a read-modify-write such as advancing a signature
    counter: returns ``False``, having written nothing, when another writer
    changed the records since :func:`read_for_update` returned ``version``.
    GCS checks the object generation; locally the check and the write happen
    under the file's lock.
    """

    payload = record_format.encode_records(key)
    resolved_session = _resolve_session_id(session_id)
    if _using_gcs():
        blob_name = _credential_blob(name, resolved_session)
        written = upload_bytes_if_generation(
            blob_name, payload, generation=version, content_type="application/json"
        )
    else:
        path = _local_filename(name, resolved_session, create=True)
        with file_lock(path):
            written = file_digest(path) == version
            if written:
                replace_file(path, payload)

    return written


def _read_local_copy(path: str) -> bytes | None:
    """One stored file's bytes; ``None`` when there is no such file. Any other failure raises."""

    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StorageReadError(f"Could not read {path}") from exc


def _read_gcs_copy(blob_name: str) -> bytes | None:
    """One stored object's bytes; ``None`` when there is no such object. Any other failure raises."""

    try:
        return download_bytes(blob_name)
    except Exception as exc:
        raise StorageReadError(f"Could not read {blob_name}") from exc


def _decode_copy(payload: bytes, source: str) -> list[Any] | None:
    """The records in one stored copy; ``None``, with a warning naming it, when they do not decode."""

    try:
        return record_format.decode_payload(payload)
    except record_format.UndecodableRecords as exc:
        # The reason, never the content: this is the one line an operator gets.
        logger.warning("Skipped undecodable credential data at %s: %s", source, exc)
        return None


def readkey(name: str, *, session_id: str | None = None) -> list[Any]:
    """``name``'s credentials, ``[]`` when there are none.

    A copy that cannot be read raises :class:`StorageReadError`: answering ``[]``
    would answer with no records. A copy whose content does not decode is skipped
    with a warning naming it, and reads as ``[]``.
    """

    resolved_session = _resolve_session_id(session_id)
    if _using_gcs():
        source = _credential_blob(name, resolved_session)
        payload = _read_gcs_copy(source)
    else:
        source = _local_filename(name, resolved_session)
        payload = _read_local_copy(source)
    if payload is None:
        return []
    return _decode_copy(payload, source) or []


def add_public_key_material(target: dict[str, Any], public_key: Any) -> None:
    """Populate JSON-friendly COSE public key details if available."""
    if not isinstance(public_key, dict):
        return

    cose_map = dict(public_key)
    target['publicKeyCose'] = make_json_safe(cose_map)

    raw_key = cose_map.get(-1)
    if isinstance(raw_key, (bytes, bytearray, memoryview)):
        target['publicKeyBytes'] = make_json_safe(raw_key)

    if 'publicKeyType' not in target:
        target['publicKeyType'] = cose_map.get(1)

    if 'publicKeyAlgorithm' not in target:
        target['publicKeyAlgorithm'] = cose_map.get(3)
