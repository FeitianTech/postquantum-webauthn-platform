import hashlib

import pytest


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

    payload = decode_module.cbor.encode({"a": 1}) + decode_module.cbor.encode([1, 2, 3])
    structures, values, consumed, remaining = decode_module._decode_cbor_sequence(payload)

    assert len(structures) == 2
    assert values == [{"a": 1}, [1, 2, 3]]
    assert consumed == len(payload)
    assert remaining == b""


def test_repair_make_credential_entries_promotes_signature_fragments_to_att_stmt():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    structure = {
        "entries": [
            {
                "key": {"majorType": 2, "hex": "aa" * 32},
                "value": {"summary": "bytes"},
            }
        ],
        "length": 1,
        "summary": "map[1]",
    }
    value = {13: [b"sig-part-1", b"sig-part-2", {"alg": -7}]}

    repaired_structure, repaired_value, signature_bytes = decode_module._repair_make_credential_entries(
        structure,
        value,
        default_alg=-50,
    )

    assert signature_bytes == b"sig-part-1sig-part-2"
    assert repaired_value[3]["alg"] == -7
    assert repaired_value[3]["sig"] == signature_bytes
    assert repaired_structure["length"] == len(repaired_structure["entries"])


def test_merge_ctap_make_credential_consumes_split_attestation_statement_inputs():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    structure = {
        "entries": [
            {
                "keySummary": "3",
                "key": {"majorType": 0, "value": 3},
                "value": {"summary": "placeholder"},
            }
        ]
    }
    value = {"al&": "sig", "alg": -7, "sig": b"legacy-sig"}
    extra_structures = [{"summary": "map[2]"}]
    extra_values = [{"alg": -8, "sig": b"X" * 32}]

    merged_structure, merged_value, remaining_structures, remaining_values, signature_bytes = (
        decode_module._merge_ctap_make_credential(
            structure,
            value,
            extra_structures,
            extra_values,
        )
    )

    assert signature_bytes == b"X" * 32
    assert merged_value[3]["sig"] == b"X" * 32
    assert merged_value[3]["alg"] == -8
    assert remaining_structures == []
    assert remaining_values == []
    assert merged_structure["entries"][-1]["keySummary"] == "3"


def test_extract_and_split_get_assertion_trailing_fields_from_raw_signature_blob():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    signature = b"S" * 32
    raw_bytes = (
        decode_module.cbor.encode(3)
        + decode_module.cbor.encode(signature)
        + decode_module.cbor.encode(4)
        + decode_module.cbor.encode({"id": "user"})
        + decode_module.cbor.encode(5)
        + decode_module.cbor.encode(2)
    )

    extracted_signature, trailing_fields = decode_module._extract_get_assertion_trailing_from_raw(raw_bytes)
    assert extracted_signature == signature
    assert trailing_fields[4]["id"] == "user"
    assert trailing_fields[5] == 2

    split_signature, split_fields = decode_module._split_get_assertion_trailing_fields(
        signature
        + decode_module.cbor.encode(4)
        + decode_module.cbor.encode({"id": "split-user"})
        + decode_module.cbor.encode(5)
        + decode_module.cbor.encode(1)
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
        decode_module.cbor.encode(3)
        + decode_module.cbor.encode(signature)
        + decode_module.cbor.encode(4)
        + decode_module.cbor.encode({"id": "u"})
        + decode_module.cbor.encode(5)
        + decode_module.cbor.encode(3)
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


def test_merge_trailing_signature_adds_att_stmt_for_packed_attestations_only():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = _build_auth_data_bytes()
    structure = {"entries": []}

    merged = decode_module._merge_trailing_signature(
        structure,
        {1: "packed", 2: auth_data},
        b"sig-trailing",
    )

    assert merged is not None
    merged_structure, merged_value, signature_bytes, remaining = merged
    assert signature_bytes == b"sig-trailing"
    assert merged_value[3]["sig"] == b"sig-trailing"
    assert "alg" not in merged_value[3] or isinstance(merged_value[3]["alg"], int)
    assert remaining == b""
    assert merged_structure["entries"][-1]["keySummary"] == "3"

    assert (
        decode_module._merge_trailing_signature(
            structure,
            {1: "none", 2: auth_data},
            b"sig-trailing",
        )
        is None
    )
