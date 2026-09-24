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
    blob_exists,
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
    StorageReadError,
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
    "CredentialsUndecodable",
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


class CredentialsUndecodable(Exception):
    """The current copy of a user's credentials exists, but its content does not decode.

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
            blob_names = list(list_blob_names(search_prefix))
        except Exception as exc:
            # A listing that stopped part-way must not pass for a shorter one.
            raise StorageReadError(f"Could not list the credentials under {search_prefix}") from exc
        for blob_name in blob_names:
            remainder = blob_name[len(search_prefix) :] if search_prefix else blob_name
            if search_prefix == legacy_prefix and "/" in remainder.strip("/"):
                continue
            username = _strip_credential_suffix(remainder)
            if not username or username in seen_users:
                continue
            seen_users.add(username)
            yield username, blob_name


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
    Hand it to :func:`save_if_unchanged`. A current copy that does not decode
    raises :class:`CredentialsUndecodable` rather than reading as ``[]``.
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
        # No current copy: the records, if any, are a legacy one's.
        return readkey(name, session_id=resolved_session), version
    try:
        return record_format.decode_payload(payload), version
    except record_format.UndecodableRecords as exc:
        raise CredentialsUndecodable(f"Could not decode {source}: {exc}") from None


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
    """``name``'s credentials: the first copy that exists, ``[]`` when none does.

    Older copies are read only when no newer one exists. A copy that cannot be
    read raises :class:`StorageReadError`: going on to an older copy, or to
    ``[]``, would answer with stale records or none. A copy whose content does
    not decode is skipped with a warning naming it, and reads as ``[]``.
    """

    resolved_session = _resolve_session_id(session_id)
    if _using_gcs():
        candidates, read = _candidate_gcs_blob_names(name, resolved_session), _read_gcs_copy
    else:
        candidates, read = _candidate_local_paths(name, resolved_session), _read_local_copy
    for source in candidates:
        payload = read(source)
        if payload is not None:
            return _decode_copy(payload, source) or []
    return []


def delkey(name: str, *, session_id: str | None = None) -> None:
    """Delete ``name``'s credentials: empty the current copy, remove every legacy copy.

    When any copy existed, the current copy is left in place holding no records
    instead of being removed. A save that read while there was no current copy
    -- its records a legacy copy's -- holds "there is none" as its version;
    removing the current copy would make that true again, and the save would
    write the deleted records back. An emptied copy never matches it. Locally
    all of this happens under the current copy's lock.

    A copy that is not there is already deleted. Anything else -- a refused
    permission, an unreachable bucket -- is raised once every other copy has
    been tried, so a caller never reports a deletion that did not happen.
    """

    resolved_session = _resolve_session_id(session_id)
    emptied = record_format.encode_records([])
    errors: list[Exception] = []
    if _using_gcs():
        current = _credential_blob(name, resolved_session)
        existed = False
        for blob_name in _candidate_gcs_blob_names(name, resolved_session):
            if blob_name == current:
                continue
            try:
                if blob_exists(blob_name):
                    existed = True
                    delete_blob(blob_name, missing_ok=True)
            except Exception as exc:
                errors.append(exc)
        try:
            # A legacy copy it could not check may exist: empty the current copy then too.
            if existed or errors or blob_exists(current):
                upload_bytes(current, emptied, content_type="application/json")
        except Exception as exc:
            errors.append(exc)
    else:
        current = _local_filename(name, resolved_session)
        legacy = [path for path in _candidate_local_paths(name, resolved_session) if path != current]
        if not any(os.path.exists(path) for path in (current, *legacy)):
            # Nothing stored: no lock file and no session directory either.
            return
        current = _local_filename(name, resolved_session, create=True)
        with file_lock(current):
            existed = False
            for path in (current, *legacy):
                existed = existed or os.path.exists(path)
                if path == current:
                    continue
                try:
                    os.remove(path)
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    errors.append(exc)
            if existed:
                try:
                    replace_file(current, emptied)
                except OSError as exc:
                    errors.append(exc)
    if errors:
        raise errors[0]


def _iter_local_directory(directory: str) -> Iterable[tuple[str, bytes, str]]:
    try:
        entries = os.listdir(directory)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise StorageReadError(f"Could not list {directory}") from exc

    # Sorted so a directory holding both formats for one user resolves
    # deterministically: "..._credential_data.json" sorts before "....pkl".
    for entry in sorted(entries):
        username = _strip_credential_suffix(entry)
        if not username:
            continue
        path = os.path.join(directory, entry)
        payload = _read_local_copy(path)
        if payload is not None:
            yield username, payload, path


def _local_copies(session_id: str) -> Iterable[tuple[str, bytes, str]]:
    directories = [_LOCAL_CREDENTIAL_BASE]
    if _LEGACY_LOCAL_CREDENTIAL_BASE != _LOCAL_CREDENTIAL_BASE:
        directories.append(_LEGACY_LOCAL_CREDENTIAL_BASE)

    for base in directories:
        try:
            directory = _local_directory(session_id, base=base)
        except ValueError as exc:
            logger.warning(
                "Refusing to list credentials for session %r under %s: %s",
                session_id,
                base,
                exc,
            )
            continue
        yield from _iter_local_directory(directory)

    yield from _iter_local_directory(basepath)


def _gcs_copies(session_id: str) -> Iterable[tuple[str, bytes, str]]:
    for username, blob_name in _list_credential_blob_names(session_id):
        payload = _read_gcs_copy(blob_name)
        if payload is not None:
            yield username, payload, blob_name


def iter_credentials(
    *, session_id: str | None = None, undecodable: list[str] | None = None
) -> Iterator[tuple[str, list[Any]]]:
    """Each user's credentials in the session, ``(username, records)``, from the first copy that exists.

    A listing or a copy that cannot be read raises :class:`StorageReadError`: a
    listing that stopped part-way must not pass for a shorter one. A copy whose
    content does not decode is skipped with a warning naming it, and its
    username appended to ``undecodable`` when that list is given.
    """

    resolved_session = _resolve_session_id(session_id)
    sources = _gcs_copies(resolved_session) if _using_gcs() else _local_copies(resolved_session)

    seen_users = set()
    for username, payload, source in sources:
        if username in seen_users:
            continue
        # The first copy that exists is the user's, decodable or not: an older
        # one standing in for it would show stale records as current.
        seen_users.add(username)
        creds = _decode_copy(payload, source)
        if creds is None:
            if undecodable is not None:
                undecodable.append(username)
            continue
        if creds:
            # An emptied copy is what delkey leaves: the user has no credentials to list.
            yield username, creds


def list_credentials(
    *, session_id: str | None = None, undecodable: list[str] | None = None
) -> dict[str, list[Any]]:
    return dict(iter_credentials(session_id=session_id, undecodable=undecodable))


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
