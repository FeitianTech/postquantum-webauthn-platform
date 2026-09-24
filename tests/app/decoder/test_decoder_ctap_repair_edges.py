import hashlib

import pytest

from fido2 import cbor


def _build_auth_data_bytes() -> bytes:
    from fido2.cose import CoseKey
    from fido2.webauthn import AttestedCredentialData, AuthenticatorData

    public_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), b"cred-id", public_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        1,
        credential_data,
    )
    return bytes(auth_data)


def test_decode_cbor_sequence_decodes_multiple_items():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    payload = cbor.encode({"a": 1}) + cbor.encode([1, 2, 3])
    structures, values, consumed, remaining = decode_module._decode_cbor_sequence(payload)

    assert len(structures) == 2
    assert values == [{"a": 1}, [1, 2, 3]]
    assert consumed == len(payload)
    assert remaining == b""
