"""The on-disk format of stored credential records.

Records are stored as JSON (see ``_encode_value`` for the exact encoding). Where
the bytes live is ``credentials``' business.
"""
from __future__ import annotations

import json
from typing import Any

from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from .. import encoding

__all__ = [
    "UndecodableRecords",
    "decode_payload",
    "encode_records",
]

_JSON_FORMAT_VERSION = 1
_JSON_BYTES_ENCODING = "base64url"
_TYPE_KEY = "__t"
_VALUE_KEY = "__v"

_T_BYTES = "bytes"
_T_ATTESTED_CREDENTIAL_DATA = "fido2.AttestedCredentialData"
_T_AUTHENTICATOR_DATA = "fido2.AuthenticatorData"
_T_MAP = "map"

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
    # A record holds fido2's objects, JSON and what fido2's CBOR reads: nothing else.
    raise TypeError(f"a credential record holds a {type(value).__name__}, which the store does not write")


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
    # No writer of this format writes another tag (encode_records is its only one).
    raise ValueError(f"a value tagged {tag!r}")


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

    # encode_records always writes the envelope.
    if not (isinstance(parsed, dict) and isinstance(parsed.get("credentials"), list)):
        raise UndecodableRecords("it is JSON but not a credential list")
    items = parsed["credentials"]
    try:
        return [_decode_value(item) for item in items]
    except Exception as exc:
        raise UndecodableRecords(f"its JSON records do not decode ({type(exc).__name__})") from None


def decode_payload(payload: bytes) -> list[Any]:
    """Turn stored bytes into a credential list.

    Bytes that are not a JSON credential list raise :class:`UndecodableRecords`,
    naming the reason and never the content.
    """

    if not payload:
        raise UndecodableRecords("it is empty")

    decoded = _decode_records(payload)
    if decoded is None:
        raise UndecodableRecords("it is not JSON")
    return decoded
