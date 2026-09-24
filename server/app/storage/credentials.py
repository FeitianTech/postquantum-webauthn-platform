"""Credential storage helpers for the demo server backed by pluggable storage.

Two properties this module is responsible for, both of which used to be absent:

**Containment.** ``name`` is attacker supplied -- it arrives as ``?email=`` --
and it is interpolated into a filesystem path and a GCS object key. Every such
identifier goes through :func:`validate_storage_component` and every resolved
path goes through :func:`resolve_contained_path` / :func:`assert_contained_blob_name`.

**A safe on-disk format.** Records are stored as JSON, never pickle; the format
and the restricted reader for legacy ``.pkl`` copies are ``record_format``'s.
"""
from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Iterable, Iterator
from typing import Any

from .. import encoding
from ..config import basepath
from ..config.paths import INSTANCE_ROOT
from . import record_format
from .cloud import (
    build_blob_name,
    delete_blob,
    download_bytes,
    download_bytes_with_generation,
    gcs_enabled,
    list_blob_names,
    upload_bytes,
    upload_bytes_if_generation,
)
from .common import (
    assert_contained_blob_name,
    build_session_root_prefix,
    build_session_scoped_prefix,
    file_digest,
    file_lock,
    replace_file,
    resolve_contained_path,
    resolve_metadata_session_id,
    using_gcs_backend,
    validate_storage_component,
)

logger = logging.getLogger(__name__)

__all__ = [
    "add_public_key_material",
    "convert_bytes_for_json",
    "delkey",
    "extract_credential_data",
    "iter_credentials",
    "list_credentials",
    "read_for_update",
    "readkey",
    "save_if_unchanged",
    "savekey",
]


_USER_FOLDER_PREFIX = os.environ.get(
    "FIDO_SERVER_GCS_USER_FOLDER_PREFIX",
    os.environ.get("FIDO_SERVER_GCS_CREDENTIAL_PREFIX", "user-data"),
)
_USER_CREDENTIAL_SUBDIR = os.environ.get(
    "FIDO_SERVER_GCS_USER_CREDENTIAL_SUBDIR",
    os.environ.get("FIDO_SERVER_GCS_CREDENTIAL_PREFIX", "credentials"),
)

# The credential store lives under the Flask instance path (gitignored), not
# next to the source. ``FIDO_SERVER_CREDENTIAL_DIR`` overrides it for
# deployments that mount a volume somewhere else.
_LOCAL_CREDENTIAL_BASE = os.environ.get(
    "FIDO_SERVER_CREDENTIAL_DIR",
    os.path.join(INSTANCE_ROOT, "session-credentials"),
)
# Where the store used to live, inside the source tree. Still read so an
# existing deployment does not lose its credentials on upgrade; never written.
_LEGACY_LOCAL_CREDENTIAL_BASE = os.path.join(basepath, "session-credentials")

_JSON_SUFFIX = "_credential_data.json"
_PICKLE_SUFFIX = "_credential_data.pkl"
_CREDENTIAL_SUFFIXES = (_JSON_SUFFIX, _PICKLE_SUFFIX)

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


def _user_root_prefix(session_id: str) -> str:
    return build_session_root_prefix(
        _validate_session_id(session_id),
        user_folder_prefix=_USER_FOLDER_PREFIX,
    )


def _credential_prefix(session_id: str) -> str:
    return build_session_scoped_prefix(
        _validate_session_id(session_id),
        user_folder_prefix=_USER_FOLDER_PREFIX,
        subdir=_USER_CREDENTIAL_SUBDIR,
    )


def _credential_blob(name: str, session_id: str, *, suffix: str = _JSON_SUFFIX) -> str:
    cleaned = _validate_name(name)
    prefix = _credential_prefix(session_id)
    blob_name = build_blob_name(f"{cleaned}{suffix}", prefix=prefix)
    return assert_contained_blob_name(blob_name, prefix=prefix)


def _legacy_credential_blob(name: str, *, suffix: str = _JSON_SUFFIX) -> str:
    cleaned = _validate_name(name)
    blob_name = build_blob_name(f"{cleaned}{suffix}", prefix=_USER_FOLDER_PREFIX)
    return assert_contained_blob_name(blob_name, prefix=_USER_FOLDER_PREFIX)


def _build_search_prefix(path: str) -> str:
    base_prefix = path.strip().strip("/")
    return f"{base_prefix}/" if base_prefix else ""


def _candidate_gcs_blob_names(name: str, session_id: str) -> Iterable[str]:
    """Object keys to try in order: JSON before pickle, scoped before legacy."""

    seen = set()
    for blob_name in (
        _credential_blob(name, session_id, suffix=_JSON_SUFFIX),
        _credential_blob(name, session_id, suffix=_PICKLE_SUFFIX),
        _legacy_credential_blob(name, suffix=_JSON_SUFFIX),
        _legacy_credential_blob(name, suffix=_PICKLE_SUFFIX),
    ):
        if blob_name in seen:
            continue
        seen.add(blob_name)
        yield blob_name


def _strip_credential_suffix(remainder: str) -> str | None:
    for suffix in _CREDENTIAL_SUFFIXES:
        if remainder.endswith(suffix):
            username = remainder[: -len(suffix)]
            return username or None
    return None


def _list_credential_blob_names(session_id: str) -> Iterable[tuple[str, str]]:
    search_prefixes = []

    primary_prefix = _build_search_prefix(_credential_prefix(session_id))
    search_prefixes.append(primary_prefix)

    legacy_prefix = _build_search_prefix(_USER_FOLDER_PREFIX)
    if legacy_prefix not in search_prefixes:
        search_prefixes.append(legacy_prefix)

    seen_users = set()
    for search_prefix in search_prefixes:
        try:
            for blob_name in list_blob_names(search_prefix):
                remainder = blob_name[len(search_prefix) :] if search_prefix else blob_name
                if search_prefix == legacy_prefix and "/" in remainder.strip("/"):
                    continue
                username = _strip_credential_suffix(remainder)
                if not username or username in seen_users:
                    continue
                seen_users.add(username)
                yield username, blob_name
        except Exception as exc:  # pragma: no cover - depends on storage backend
            logger.warning(
                "Unable to list credential blobs under %s: %s", search_prefix, exc
            )


def _local_directory(
    session_id: str,
    *,
    create: bool = False,
    base: str | None = None,
) -> str:
    cleaned = _validate_session_id(session_id)
    root = _LOCAL_CREDENTIAL_BASE if base is None else base
    directory = resolve_contained_path(root, cleaned)
    if create:
        os.makedirs(directory, exist_ok=True)
    return directory


def _legacy_local_filename(name: str) -> str:
    """Path of the pre-session, flat ``server/app/<name>_credential_data.pkl`` file."""

    cleaned = _validate_name(name)
    return resolve_contained_path(basepath, f"{cleaned}{_PICKLE_SUFFIX}")


def _local_filename(
    name: str,
    session_id: str,
    *,
    create: bool = False,
    suffix: str = _JSON_SUFFIX,
    base: str | None = None,
) -> str:
    root = _LOCAL_CREDENTIAL_BASE if base is None else base
    cleaned_session = _validate_session_id(session_id)
    cleaned_name = _validate_name(name)
    if create:
        os.makedirs(resolve_contained_path(root, cleaned_session), exist_ok=True)
    # Contained against the store root rather than the session directory, so a
    # session id and a name cannot combine to climb out.
    return resolve_contained_path(root, cleaned_session, f"{cleaned_name}{suffix}")


def _candidate_local_paths(name: str, session_id: str) -> Iterator[str]:
    """Every location a credential file for ``name`` may legitimately live in."""

    bases = [_LOCAL_CREDENTIAL_BASE]
    if _LEGACY_LOCAL_CREDENTIAL_BASE != _LOCAL_CREDENTIAL_BASE:
        bases.append(_LEGACY_LOCAL_CREDENTIAL_BASE)

    seen = set()
    for base in bases:
        for suffix in _CREDENTIAL_SUFFIXES:
            path = _local_filename(name, session_id, suffix=suffix, base=base)
            if path not in seen:
                seen.add(path)
                yield path

    legacy_flat = _legacy_local_filename(name)
    if legacy_flat not in seen:
        yield legacy_flat


def _resolve_session_id(session_id: str | None = None) -> str:
    return resolve_metadata_session_id(session_id)


def _discard_superseded_pickle(name: str, session_id: str) -> None:
    """Drop the ``.pkl`` the JSON write just replaced, so it is never read again.

    Only the session-scoped copy is removed. The flat
    ``server/app/<name>_credential_data.pkl`` file is shared by every session,
    so removing it here would delete another session's fallback.
    """

    if _using_gcs():
        try:
            delete_blob(_credential_blob(name, session_id, suffix=_PICKLE_SUFFIX), missing_ok=True)
        except Exception:
            pass
        return

    for base in (_LOCAL_CREDENTIAL_BASE, _LEGACY_LOCAL_CREDENTIAL_BASE):
        try:
            os.remove(_local_filename(name, session_id, suffix=_PICKLE_SUFFIX, base=base))
        except Exception:
            pass


def savekey(name: str, key: Any, *, session_id: str | None = None) -> None:
    payload = record_format.encode_records(key)
    resolved_session = _resolve_session_id(session_id)
    if _using_gcs():
        blob_name = _credential_blob(name, resolved_session)
        upload_bytes(blob_name, payload, content_type="application/json")
    else:
        path = _local_filename(name, resolved_session, create=True)
        with file_lock(path):
            replace_file(path, payload)

    _discard_superseded_pickle(name, resolved_session)


def read_for_update(name: str, *, session_id: str | None = None) -> tuple[list[Any], Any]:
    """``readkey``, and the version of the copy a later save would replace.

    The version is opaque: the object's generation on GCS (0 when there is no
    object), the SHA-256 of the file locally (``None`` when there is no file).
    Hand it to :func:`save_if_unchanged`.
    """

    resolved_session = _resolve_session_id(session_id)
    if _using_gcs():
        source = _credential_blob(name, resolved_session)
        payload, version = download_bytes_with_generation(source)
    else:
        source = _local_filename(name, resolved_session)
        try:
            with open(source, "rb") as f:
                payload = f.read()
        except FileNotFoundError:
            payload = None
        version = hashlib.sha256(payload).hexdigest() if payload is not None else None

    records = record_format.load_payload(payload, source=source) if payload else None
    if records is None:
        # No current copy: the records, if any, are a legacy one's.
        records = readkey(name, session_id=resolved_session)
    return records, version


def save_if_unchanged(name: str, key: Any, version: Any, *, session_id: str | None = None) -> bool:
    """``savekey``, only if the copy it replaces is still at ``version``.

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

    if written:
        _discard_superseded_pickle(name, resolved_session)
    return written


def readkey(name: str, *, session_id: str | None = None) -> list[Any]:
    resolved_session = _resolve_session_id(session_id)
    if _using_gcs():
        for blob_name in _candidate_gcs_blob_names(name, resolved_session):
            try:
                payload = download_bytes(blob_name)
            except Exception:
                payload = None
            if not payload:
                continue
            creds = record_format.load_payload(payload, source=blob_name)
            if creds is not None:
                return creds
        return []

    for path in _candidate_local_paths(name, resolved_session):
        try:
            with open(path, "rb") as f:
                payload = f.read()
        except Exception:
            continue
        if not payload:
            continue
        creds = record_format.load_payload(payload, source=path)
        if creds is not None:
            return creds

    return []


def delkey(name: str, *, session_id: str | None = None) -> None:
    """Delete every copy of ``name``'s credentials; raise if one could not be deleted.

    A copy that is not there is already deleted. Anything else -- a refused
    permission, an unreachable bucket -- is raised once every other copy has
    been tried, so a caller never reports a deletion that did not happen.
    """

    resolved_session = _resolve_session_id(session_id)
    errors: list[Exception] = []
    if _using_gcs():
        for blob_name in _candidate_gcs_blob_names(name, resolved_session):
            try:
                delete_blob(blob_name, missing_ok=True)
            except Exception as exc:
                errors.append(exc)
    else:
        # The copy saves write is removed under the lock they write it under, so
        # a delete cannot land between a compare-and-swap's check and its rename
        # and have the records written back. Legacy copies are never written.
        current = _local_filename(name, resolved_session)
        for path in _candidate_local_paths(name, resolved_session):
            try:
                if path == current and os.path.exists(path):
                    with file_lock(path):
                        os.remove(path)
                else:
                    os.remove(path)
            except FileNotFoundError:
                continue
            except OSError as exc:
                errors.append(exc)
    if errors:
        raise errors[0]


def _iter_local_directory(directory: str) -> Iterable[tuple[str, bytes, str]]:
    try:
        entries = os.listdir(directory)
    except OSError:
        return

    # Sorted so a directory holding both formats for one user resolves
    # deterministically: "..._credential_data.json" sorts before "....pkl".
    for entry in sorted(entries):
        username = _strip_credential_suffix(entry)
        if not username:
            continue
        path = os.path.join(directory, entry)
        try:
            with open(path, "rb") as f:
                payload = f.read()
        except Exception:
            continue
        if payload:
            yield username, payload, path


def iter_credentials(*, session_id: str | None = None) -> Iterator[tuple[str, list[Any]]]:
    resolved_session = _resolve_session_id(session_id)
    if _using_gcs():

        def _download_blob_items() -> Iterable[tuple[str, bytes, str]]:
            for username, blob_name in _list_credential_blob_names(resolved_session):
                try:
                    payload = download_bytes(blob_name)
                except Exception:
                    continue
                if payload:
                    yield username, payload, blob_name

        sources: Iterable[tuple[str, bytes, str]] = _download_blob_items()
    else:

        def _read_local_items() -> Iterable[tuple[str, bytes, str]]:
            directories = [_LOCAL_CREDENTIAL_BASE]
            if _LEGACY_LOCAL_CREDENTIAL_BASE != _LOCAL_CREDENTIAL_BASE:
                directories.append(_LEGACY_LOCAL_CREDENTIAL_BASE)

            for base in directories:
                try:
                    directory = _local_directory(resolved_session, base=base)
                except ValueError as exc:
                    logger.warning(
                        "Refusing to list credentials for session %r under %s: %s",
                        resolved_session,
                        base,
                        exc,
                    )
                    continue
                yield from _iter_local_directory(directory)

            yield from _iter_local_directory(basepath)

        sources = _read_local_items()

    seen_users = set()
    for username, payload, source in sources:
        if username in seen_users:
            continue
        creds = record_format.load_payload(payload, source=source)
        if creds is None:
            continue
        seen_users.add(username)
        yield username, creds


def list_credentials(*, session_id: str | None = None) -> dict[str, list[Any]]:
    entries: dict[str, list[Any]] = {}
    for username, creds in iter_credentials(session_id=session_id):
        entries[username] = creds
    return entries


def convert_bytes_for_json(obj: Any) -> Any:
    """Recursively convert bytes-like objects to base64 strings for JSON serialization.

    NOTE: this is the *API response* encoding, not the storage encoding, and it
    deliberately stays standard base64 (``+``/``/``, padded) while the rest of
    the server speaks base64url.

    The reason is the receiving end. ``base64ToHex`` and ``base64ToUint8Array``
    in ``frontend/static/scripts/shared/utils/binary.js`` pass these values
    straight to ``atob``, and ``atob`` throws on ``-``/``_``. Certificate
    rendering (``advanced/credential-display/certificate-core.js``) and the
    credential detail views (``advanced/credentials/utils.js``) both go through
    those helpers, so switching this function alone would break them; the two
    have to move together, and that is a frontend change.

    The on-disk/GCS format uses unpadded base64url; see ``_encode_value``.
    """
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return encoding.encode_base64(bytes(obj))
    if isinstance(obj, dict):
        return {k: convert_bytes_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert_bytes_for_json(item) for item in obj]
    return obj


def add_public_key_material(target: dict[str, Any], public_key: Any) -> None:
    """Populate JSON-friendly COSE public key details if available."""
    if not isinstance(public_key, dict):
        return

    cose_map = dict(public_key)
    target['publicKeyCose'] = convert_bytes_for_json(cose_map)

    raw_key = cose_map.get(-1)
    if isinstance(raw_key, (bytes, bytearray, memoryview)):
        target['publicKeyBytes'] = convert_bytes_for_json(raw_key)

    if 'publicKeyType' not in target:
        target['publicKeyType'] = cose_map.get(1)

    if 'publicKeyAlgorithm' not in target:
        target['publicKeyAlgorithm'] = cose_map.get(3)


def extract_credential_data(cred: Any) -> Any:
    """Extract AttestedCredentialData from either old or new storage format."""
    if isinstance(cred, dict):
        return cred['credential_data']
    return cred
