"""Credentials for the storage and route tests: records stored the way the routes do
(read, then compare-and-swap), and the public key a credential the page sends back carries."""

from __future__ import annotations

from typing import Any

from fido2 import cbor


def seed_records(store: Any, name: str, records: Any, *, session_id: str) -> None:
    _, version = store.read_for_update(name, session_id=session_id)
    assert store.save_if_unchanged(name, records, version, session_id=session_id)


def sample_public_key_bytes() -> bytes:
    """An ES256 COSE key, CBOR-encoded."""

    return cbor.encode(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: b"\x01" * 32,
            -3: b"\x02" * 32,
        }
    )
