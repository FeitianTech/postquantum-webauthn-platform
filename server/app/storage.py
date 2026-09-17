"""Credential storage helpers for the demo server backed by pluggable storage.

Two properties this module is responsible for, both of which used to be absent:

**Containment.** ``name`` is attacker supplied -- it arrives as ``?email=`` --
and it is interpolated into a filesystem path and a GCS object key. Every such
identifier goes through :func:`validate_storage_component` and every resolved
path goes through :func:`resolve_contained_path` / :func:`assert_contained_blob_name`.

**A safe on-disk format.** Records are stored as JSON (see ``_encode_record`` for
the exact encoding), never pickle. ``pickle.loads`` on bytes that crossed a
trust boundary is arbitrary code execution, so the only remaining pickle reader
is :class:`_RestrictedUnpickler`, which exists purely to keep pre-existing
``.pkl`` deployments readable and refuses to import anything but a small
allowlist of FIDO2 value classes.
"""
from __future__ import annotations

import base64
import io
import json
import os
import pickle
from collections.abc import Iterable, Iterator
from typing import Any

from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from .cloud_storage import (
    build_blob_name,
    delete_blob,
    download_bytes,
    gcs_enabled,
    list_blob_names,
    upload_bytes,
)
from .config import app, basepath
from .env_flags import parse_env_flag
from .storage_common import (
    assert_contained_blob_name,
    build_session_root_prefix,
    build_session_scoped_prefix,
    resolve_contained_path,
    resolve_metadata_session_id,
    using_gcs_backend,
    validate_storage_component,
)

__all__ = [
    "add_public_key_material",
    "convert_bytes_for_json",
    "delkey",
    "encode_records",
    "extract_credential_data",
    "iter_credentials",
    "list_credentials",
    "readkey",
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
    os.path.join(app.instance_path, "session-credentials"),
)
# Where the store used to live, inside the source tree. Still read so an
# existing deployment does not lose its credentials on upgrade; never written.
_LEGACY_LOCAL_CREDENTIAL_BASE = os.path.join(basepath, "session-credentials")

_JSON_SUFFIX = "_credential_data.json"
_PICKLE_SUFFIX = "_credential_data.pkl"
_CREDENTIAL_SUFFIXES = (_JSON_SUFFIX, _PICKLE_SUFFIX)

_JSON_FORMAT_VERSION = 1
_JSON_BYTES_ENCODING = "base64url"
_TYPE_KEY = "__t"
_VALUE_KEY = "__v"

_T_BYTES = "bytes"
_T_ATTESTED_CREDENTIAL_DATA = "fido2.AttestedCredentialData"
_T_AUTHENTICATOR_DATA = "fido2.AuthenticatorData"
_T_MAP = "map"
_T_TUPLE = "tuple"
_T_SET = "set"
_T_UNSUPPORTED = "unsupported"

# Legacy pickles may only name classes from these modules, and only classes --
# never functions. That rules out ``os.system``, ``builtins.eval``,
# ``subprocess.Popen`` and every other code-execution gadget a crafted pickle
# reaches for, while still reconstructing the FIDO2 values we actually stored.
_PICKLE_ALLOWED_MODULES = frozenset(
    {
        "collections",
        "fido2.attestation",
        "fido2.attestation.base",
        "fido2.cose",
        "fido2.utils",
        "fido2.webauthn",
    }
)


def _legacy_pickle_reads_enabled() -> bool:
    """Whether pre-existing ``.pkl`` files may still be read at all.

    Defaults to on so an upgrade does not drop stored credentials. Set
    ``FIDO_SERVER_LEGACY_PICKLE_READS=0`` to refuse them outright once a
    deployment has been migrated.
    """

    flag = parse_env_flag("FIDO_SERVER_LEGACY_PICKLE_READS")
    return True if flag is None else flag


class _RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that refuses every global outside the FIDO2 value allowlist."""

    def find_class(self, module: str, name: str) -> Any:  # noqa: D102
        if module not in _PICKLE_ALLOWED_MODULES:
            raise pickle.UnpicklingError(
                f"Refusing to load {module}.{name} from a legacy credential pickle"
            )
        resolved = super().find_class(module, name)
        if not isinstance(resolved, type):
            raise pickle.UnpicklingError(
                f"Refusing to load non-class {module}.{name} from a legacy credential pickle"
            )
        return resolved


def _restricted_pickle_loads(payload: bytes) -> Any:
    return _RestrictedUnpickler(io.BytesIO(payload)).load()


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def _b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _encode_value(value: Any) -> Any:
    """Convert a stored credential value into JSON-representable data.

    Bytes-like values become ``{"__t": "bytes", "__v": "<unpadded base64url>"}``.
    ``AttestedCredentialData`` and ``AuthenticatorData`` are ``bytes``
    subclasses, so they are stored as their exact wire bytes under their own
    type tag and reconstructed as the same class on read. Mappings with
    non-string keys (COSE maps are keyed by integers) are stored as an entry
    list so the keys survive.
    """

    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, AttestedCredentialData):
        return {_TYPE_KEY: _T_ATTESTED_CREDENTIAL_DATA, _VALUE_KEY: _b64u_encode(value)}
    if isinstance(value, AuthenticatorData):
        return {_TYPE_KEY: _T_AUTHENTICATOR_DATA, _VALUE_KEY: _b64u_encode(value)}
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {_TYPE_KEY: _T_BYTES, _VALUE_KEY: _b64u_encode(bytes(value))}
    if isinstance(value, int):
        # Covers IntEnum/IntFlag (e.g. AuthenticatorData.FLAG) as plain ints.
        return int(value)
    if isinstance(value, float):
        return float(value)
    if isinstance(value, dict):
        if all(isinstance(key, str) for key in value) and _TYPE_KEY not in value:
            return {key: _encode_value(item) for key, item in value.items()}
        return {
            _TYPE_KEY: _T_MAP,
            _VALUE_KEY: [[_encode_value(key), _encode_value(item)] for key, item in value.items()],
        }
    if isinstance(value, list):
        return [_encode_value(item) for item in value]
    if isinstance(value, tuple):
        return {_TYPE_KEY: _T_TUPLE, _VALUE_KEY: [_encode_value(item) for item in value]}
    if isinstance(value, (set, frozenset)):
        return {_TYPE_KEY: _T_SET, _VALUE_KEY: [_encode_value(item) for item in value]}

    app.logger.warning(
        "Credential record contains unsupported type %s; storing its text form",
        type(value).__name__,
    )
    return {_TYPE_KEY: _T_UNSUPPORTED, _VALUE_KEY: str(value)}


def _decode_value(value: Any) -> Any:
    """Inverse of :func:`_encode_value`."""

    if isinstance(value, list):
        return [_decode_value(item) for item in value]
    if not isinstance(value, dict):
        return value

    tag = value.get(_TYPE_KEY)
    if tag is None:
        return {key: _decode_value(item) for key, item in value.items()}

    raw = value.get(_VALUE_KEY)

    if tag == _T_BYTES:
        return _b64u_decode(raw) if isinstance(raw, str) else b""
    if tag in (_T_ATTESTED_CREDENTIAL_DATA, _T_AUTHENTICATOR_DATA):
        if not isinstance(raw, str):
            return b""
        decoded = _b64u_decode(raw)
        cls = AttestedCredentialData if tag == _T_ATTESTED_CREDENTIAL_DATA else AuthenticatorData
        try:
            return cls(decoded)
        except Exception:
            # A record written by a different fido2 version should degrade to
            # its bytes rather than take down the whole read.
            return decoded
    if tag == _T_MAP:
        entries = raw if isinstance(raw, list) else []
        decoded_map: dict[Any, Any] = {}
        for entry in entries:
            if isinstance(entry, list) and len(entry) == 2:
                decoded_map[_decode_value(entry[0])] = _decode_value(entry[1])
        return decoded_map
    if tag == _T_TUPLE:
        return tuple(_decode_value(item) for item in raw) if isinstance(raw, list) else ()
    if tag == _T_SET:
        return set(_decode_value(item) for item in raw) if isinstance(raw, list) else set()
    if tag == _T_UNSUPPORTED:
        return raw

    return {key: _decode_value(item) for key, item in value.items()}


def _encode_records(records: Any) -> bytes:
    """Serialise the credential list into the versioned JSON envelope."""

    items = list(records) if isinstance(records, (list, tuple)) else [records]
    envelope = {
        "version": _JSON_FORMAT_VERSION,
        "encoding": _JSON_BYTES_ENCODING,
        "credentials": [_encode_value(item) for item in items],
    }
    return json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def encode_records(records: Any) -> bytes:
    """Public: serialise credentials to the versioned JSON envelope for export."""

    return _encode_records(records)


def _decode_records(payload: bytes) -> list[Any] | None:
    """Decode a JSON credential payload, or return ``None`` if it is not JSON."""

    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None

    if isinstance(parsed, dict) and isinstance(parsed.get("credentials"), list):
        return [_decode_value(item) for item in parsed["credentials"]]
    if isinstance(parsed, list):
        # Tolerate a bare list in case something wrote one directly.
        return [_decode_value(item) for item in parsed]
    return None


def _load_payload(payload: bytes, *, source: str) -> list[Any] | None:
    """Turn stored bytes into a credential list, JSON first, legacy pickle second.

    The format is sniffed from the content rather than the file extension so a
    half-migrated store (or a ``.json`` object holding older bytes) still reads.
    """

    if not payload:
        return None

    decoded = _decode_records(payload)
    if decoded is not None:
        return decoded

    if not _legacy_pickle_reads_enabled():
        app.logger.warning("Ignoring non-JSON credential payload at %s", source)
        return None

    try:
        legacy = _restricted_pickle_loads(payload)
    except Exception as exc:
        app.logger.warning("Unable to read legacy credential payload at %s: %s", source, exc)
        return None

    return legacy if isinstance(legacy, list) else None


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
            app.logger.warning(
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
    payload = _encode_records(key)
    resolved_session = _resolve_session_id(session_id)
    if _using_gcs():
        blob_name = _credential_blob(name, resolved_session)
        upload_bytes(blob_name, payload, content_type="application/json")
    else:
        path = _local_filename(name, resolved_session, create=True)
        # Write-then-rename so concurrent readers never see a truncated file.
        tmp_path = f"{path}.tmp.{os.urandom(6).hex()}"
        try:
            with open(tmp_path, "wb") as f:
                f.write(payload)
            os.replace(tmp_path, path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    _discard_superseded_pickle(name, resolved_session)


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
            creds = _load_payload(payload, source=blob_name)
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
        creds = _load_payload(payload, source=path)
        if creds is not None:
            return creds

    return []


def delkey(name: str, *, session_id: str | None = None) -> None:
    resolved_session = _resolve_session_id(session_id)
    if _using_gcs():
        for blob_name in _candidate_gcs_blob_names(name, resolved_session):
            try:
                delete_blob(blob_name, missing_ok=True)
            except Exception:
                pass
        return

    for path in _candidate_local_paths(name, resolved_session):
        try:
            os.remove(path)
        except Exception:
            pass


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
                    app.logger.warning(
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
        creds = _load_payload(payload, source=source)
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

    NOTE: this is the *API response* encoding, not the storage encoding. It
    emits standard base64 (``+``/``/``, padded) because frontend helpers such
    as ``base64ToHex``/``base64ToUint8Array`` call ``atob`` on these values
    directly. The on-disk/GCS format uses unpadded base64url; see
    ``_encode_value``.
    """
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(obj)).decode('utf-8')
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
