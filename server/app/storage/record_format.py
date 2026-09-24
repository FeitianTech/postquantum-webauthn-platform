"""The on-disk format of stored credential records.

Records are stored as JSON (see ``_encode_value`` for the exact encoding),
never pickle. ``pickle.loads`` on bytes that crossed a trust boundary is
arbitrary code execution, so the only remaining pickle reader is
:class:`_RestrictedUnpickler`, which exists purely to keep pre-existing ``.pkl``
deployments readable and refuses to import anything but a small allowlist of
FIDO2 value classes. Where the bytes live is ``credentials``' business.
"""
from __future__ import annotations

import io
import json
import logging
import pickle
from typing import Any

from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from .. import encoding
from ..env_flags import parse_env_flag

logger = logging.getLogger(__name__)

__all__ = [
    "UndecodableRecords",
    "decode_payload",
    "encode_records",
    "legacy_pickle_reads_enabled",
    "restricted_pickle_loads",
]

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


def legacy_pickle_reads_enabled() -> bool:
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


def restricted_pickle_loads(payload: bytes) -> Any:
    return _RestrictedUnpickler(io.BytesIO(payload)).load()


def _b64u_encode(data: bytes) -> str:
    return encoding.encode_base64url(data)


def _b64u_decode(value: str) -> bytes:
    return encoding.decode_base64url(value)


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

    logger.warning(
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


def encode_records(records: Any) -> bytes:
    """Serialise the credential list into the versioned JSON envelope."""

    items = list(records) if isinstance(records, (list, tuple)) else [records]
    envelope = {
        "version": _JSON_FORMAT_VERSION,
        "encoding": _JSON_BYTES_ENCODING,
        "credentials": [_encode_value(item) for item in items],
    }
    return json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class UndecodableRecords(ValueError):
    """Stored bytes that are not a credential list. The message never quotes them."""


def _decode_records(payload: bytes) -> list[Any] | None:
    """Decode a JSON credential payload, or return ``None`` if it is not JSON."""

    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None

    if isinstance(parsed, dict) and isinstance(parsed.get("credentials"), list):
        items = parsed["credentials"]
    elif isinstance(parsed, list):
        # Tolerate a bare list in case something wrote one directly.
        items = parsed
    else:
        raise UndecodableRecords("it is JSON but not a credential list")
    try:
        return [_decode_value(item) for item in items]
    except Exception as exc:
        raise UndecodableRecords(f"its JSON records do not decode ({type(exc).__name__})") from None


def decode_payload(payload: bytes) -> list[Any]:
    """Turn stored bytes into a credential list, JSON first, legacy pickle second.

    The format is sniffed from the content rather than the file extension so a
    half-migrated store (or a ``.json`` object holding older bytes) still reads.
    Bytes that are neither raise :class:`UndecodableRecords`, naming the reason
    and never the content: an unpickling error's own message quotes the bytes.
    """

    if not payload:
        raise UndecodableRecords("it is empty")

    decoded = _decode_records(payload)
    if decoded is not None:
        return decoded

    if not legacy_pickle_reads_enabled():
        raise UndecodableRecords("it is not JSON, and legacy pickle reads are disabled")

    try:
        legacy = restricted_pickle_loads(payload)
    except Exception as exc:
        raise UndecodableRecords(f"it is neither JSON nor a legacy pickle this server loads ({type(exc).__name__})") from None

    if not isinstance(legacy, list):
        raise UndecodableRecords("it is a legacy pickle that does not hold a list")
    return legacy
