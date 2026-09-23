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


def test_extract_and_split_get_assertion_trailing_fields_from_raw_signature_blob():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    signature = b"S" * 32
    raw_bytes = (
        cbor.encode(3)
        + cbor.encode(signature)
        + cbor.encode(4)
        + cbor.encode({"id": "user"})
        + cbor.encode(5)
        + cbor.encode(2)
    )

    extracted_signature, trailing_fields = decode_module._extract_get_assertion_trailing_from_raw(raw_bytes)
    assert extracted_signature == signature
    assert trailing_fields[4]["id"] == "user"
    assert trailing_fields[5] == 2

    split_signature, split_fields = decode_module._split_get_assertion_trailing_fields(
        signature
        + cbor.encode(4)
        + cbor.encode({"id": "split-user"})
        + cbor.encode(5)
        + cbor.encode(1)
    )
    assert split_signature == signature
    assert split_fields[4]["id"] == "split-user"
    assert split_fields[5] == 1


def test_repair_get_assertion_entries_recovers_signature_user_and_extra_fields():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    signature = b"A" * 32
    structure = {
        "entries": [
            {
                "key": {"majorType": 2, "hex": signature.hex()},
                "value": {"summary": "bytes"},
            }
        ],
        "length": 1,
        "summary": "map[1]",
    }

    raw_bytes = (
        cbor.encode(3)
        + cbor.encode(signature)
        + cbor.encode(4)
        + cbor.encode({"id": "u"})
        + cbor.encode(5)
        + cbor.encode(3)
    )

    repaired_structure, repaired_value, repaired_signature = decode_module._repair_get_assertion_entries(
        structure,
        {},
        raw_bytes=raw_bytes,
    )

    assert repaired_signature == signature
    assert repaired_value[3] == signature
    assert repaired_value[4]["id"] == "u"
    assert repaired_value[5] == 3
    assert repaired_structure["summary"].startswith("map[")
