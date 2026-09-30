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


def select_first(mapping: Mapping[str, Any], keys: Iterable[str], *, skip_none: bool = True) -> Any:
    """The value of the first of ``keys`` in ``mapping``; with ``skip_none``, the first that is not null."""

    for key in keys:
        if key in mapping:
            value = mapping[key]
            if value is not None or not skip_none:
                return value
    return None


def read_key_material(entry: Mapping[str, Any], fields: CredentialFields) -> KeyMaterial | None:
    """The entry's key material; ``None`` when a part it needs is absent, and raises when one does not read."""

    aaguid_raw = select_first(entry, fields.aaguid, skip_none=fields.skip_none)
    credential_id_raw = select_first(entry, fields.credential_id, skip_none=fields.skip_none)
    public_key_raw = select_first(entry, fields.public_key, skip_none=fields.skip_none)
    if credential_id_raw is None or public_key_raw is None:
        return None
    if aaguid_raw is None and fields.default_aaguid is None:
        return None

    def read(value: Any) -> bytes:
        return client_binary.read(value, iterables=fields.iterables, wrappers=fields.wrappers)

    aaguid = fields.default_aaguid if aaguid_raw is None else read(aaguid_raw)
    credential_id = read(credential_id_raw)
    public_key = read(public_key_raw)

    cose_key = CoseKey.parse(mldsa.with_raw_public_key(cbor.decode(public_key)))
    attested = AttestedCredentialData.create(aaguid, credential_id, cose_key)
    return KeyMaterial(aaguid, credential_id, public_key, attested)
