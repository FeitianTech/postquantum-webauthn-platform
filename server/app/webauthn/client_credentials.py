"""A credential the page sends back from its saved list, read one way for both tabs.

Each tab names the fields it reads and their order (``CredentialFields``); the
key material is read the same way for both: an AAGUID, a credential ID and a
COSE public key (an ML-DSA key's raw form included), made into fido2's
``AttestedCredentialData``. Each tab then builds its own record from it.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import AttestedCredentialData

from .. import encoding
from . import client_binary, mldsa


@dataclass(frozen=True)
class CredentialFields:
    """Where one tab looks for each part of a credential, and how it reads them.

    ``default_aaguid`` stands in for an entry without an AAGUID; without one,
    such an entry is skipped. ``skip_none`` passes over a field that is
    present but null; ``iterables`` and ``wrappers`` are ``client_binary.read``'s.
    """

    aaguid: tuple[str, ...]
    credential_id: tuple[str, ...]
    public_key: tuple[str, ...]
    default_aaguid: bytes | None = None
    skip_none: bool = True
    iterables: bool = False
    wrappers: bool = False


@dataclass(frozen=True)
class KeyMaterial:
    aaguid: bytes
    credential_id: bytes
    public_key: bytes
    attested: AttestedCredentialData


def select_field(mapping: Mapping[str, Any], keys: Iterable[str], *, skip_none: bool = True) -> tuple[str | None, Any]:
    """The first of ``keys`` in ``mapping`` and its value; with ``skip_none``, the first that is not null."""

    for key in keys:
        if key in mapping:
            value = mapping[key]
            if value is not None or not skip_none:
                return key, value
    return None, None


def select_first(mapping: Mapping[str, Any], keys: Iterable[str], *, skip_none: bool = True) -> Any:
    """The value of the first of ``keys`` in ``mapping``; with ``skip_none``, the first that is not null."""

    return select_field(mapping, keys, skip_none=skip_none)[1]


def read_aaguid(field: str | None, value: Any, *, iterables: bool = False, wrappers: bool = False) -> bytes:
    """An AAGUID's bytes: ``aaguidHex`` holds hex, as its name says; any other field is read as a client's bytes.

    Read as a client's bytes, 32 hex digits would be valid base64url: 24 wrong bytes.
    """

    if field == "aaguidHex" and isinstance(value, str):
        return encoding.decode_hex(value, allow_separators=True)
    return client_binary.read(value, iterables=iterables, wrappers=wrappers)


def read_key_material(entry: Mapping[str, Any], fields: CredentialFields) -> KeyMaterial | None:
    """The entry's key material; ``None`` when a part it needs is absent, and raises when one does not read."""

    aaguid_field, aaguid_raw = select_field(entry, fields.aaguid, skip_none=fields.skip_none)
    credential_id_raw = select_first(entry, fields.credential_id, skip_none=fields.skip_none)
    public_key_raw = select_first(entry, fields.public_key, skip_none=fields.skip_none)
    if credential_id_raw is None or public_key_raw is None:
        return None
    if aaguid_raw is None and fields.default_aaguid is None:
        return None

    def read(value: Any) -> bytes:
        return client_binary.read(value, iterables=fields.iterables, wrappers=fields.wrappers)

    aaguid = (
        fields.default_aaguid
        if aaguid_raw is None
        else read_aaguid(aaguid_field, aaguid_raw, iterables=fields.iterables, wrappers=fields.wrappers)
    )
    credential_id = read(credential_id_raw)
    public_key = read(public_key_raw)

    cose_key = CoseKey.parse(mldsa.with_raw_public_key(cbor.decode(public_key)))
    attested = AttestedCredentialData.create(aaguid, credential_id, cose_key)
    return KeyMaterial(aaguid, credential_id, public_key, attested)
