import base64

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _sample_public_key_bytes() -> bytes:
    from fido2 import cbor

    return cbor.encode(
        {
            1: 2,
            3: -7,
            -1: 1,
            -2: b"\x01" * 32,
            -3: b"\x02" * 32,
        }
    )


def _valid_credential_entry(*, resident=None, properties=None, algorithm=None):
    entry = {
        "credentialId": _b64url(b"credential-id-1"),
        "publicKey": _b64url(_sample_public_key_bytes()),
        "aaguid": _b64url(bytes.fromhex("00112233445566778899aabbccddeeff")),
        "signCount": 7,
    }
    if resident is not None:
        entry["resident"] = resident
    if properties is not None:
        entry["properties"] = properties
    if algorithm is not None:
        entry["algorithm"] = algorithm
    return entry


def test_decode_client_binary_accepts_base64url_mapping_key():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    raw = b"\x00\x01\x02\xfa"
    decoded = advanced_module._decode_client_binary({"$base64url": _b64url(raw)})

    assert decoded == raw


def test_decode_client_binary_honors_explicit_hex_wrapper():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    decoded = advanced_module._decode_client_binary({"$hex": "0011223344556677"})

    assert decoded == bytes.fromhex("0011223344556677")


def test_decode_client_binary_rejects_invalid_explicit_hex_wrapper():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    with pytest.raises(ValueError, match="invalid binary value"):
        advanced_module._decode_client_binary({"$hex": "zz"})


def test_decode_client_binary_rejects_invalid_explicit_base64url_wrapper():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    with pytest.raises(ValueError, match="invalid binary value"):
        advanced_module._decode_client_binary({"$base64url": "%%%"})


def test_decode_client_binary_rejects_invalid_string_value():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    with pytest.raises(ValueError, match="invalid binary value"):
        advanced_module._decode_client_binary("g$")


def test_decode_client_binary_rejects_unsupported_input_type():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    with pytest.raises(ValueError, match="unsupported binary value type"):
        advanced_module._decode_client_binary(1234)


def test_parse_client_supplied_credentials_skips_entries_missing_required_fields():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    records, serialized = advanced_module._parse_client_supplied_credentials(
        [
            {"publicKey": _b64url(_sample_public_key_bytes())},
            {"credentialId": _b64url(b"id-only")},
        ]
    )

    assert records == []
    assert serialized == []


def test_parse_client_supplied_credentials_skips_malformed_entries_and_keeps_valid_ones():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    malformed = {
        "credentialId": "g$",
        "publicKey": _b64url(_sample_public_key_bytes()),
    }
    valid = _valid_credential_entry(resident=True)

    records, serialized = advanced_module._parse_client_supplied_credentials([malformed, valid])

    assert len(records) == 1
    assert len(serialized) == 1
    assert records[0]["resident"] is True
    assert serialized[0]["resident"] is True
    assert serialized[0]["credentialId"] == valid["credentialId"]


def test_parse_client_supplied_credentials_uses_properties_resident_flag_when_top_level_absent():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    entry = _valid_credential_entry(properties={"residentKey": True})

    records, serialized = advanced_module._parse_client_supplied_credentials([entry])

    assert len(records) == 1
    assert records[0]["resident"] is True
    assert serialized[0]["resident"] is True


def test_parse_client_supplied_credentials_prefers_top_level_resident_over_properties():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    entry = _valid_credential_entry(resident=False, properties={"residentKey": True})

    records, serialized = advanced_module._parse_client_supplied_credentials([entry])

    assert len(records) == 1
    assert records[0]["resident"] is False
    assert serialized[0]["resident"] is False


def test_parse_client_supplied_credentials_defaults_missing_aaguid_to_zero_bytes():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    entry = _valid_credential_entry()
    entry.pop("aaguid")

    records, serialized = advanced_module._parse_client_supplied_credentials([entry])

    assert len(records) == 1
    assert len(records[0]["data"].aaguid) == 16
    assert serialized[0]["aaguid"] == _b64url(bytes(16))


def test_parse_client_supplied_credentials_coerces_named_algorithm_identifier():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    entry = _valid_credential_entry(algorithm="ES256")

    records, serialized = advanced_module._parse_client_supplied_credentials([entry])

    assert len(records) == 1
    assert records[0]["algorithm"] == -7
    assert serialized[0]["algorithm"] == -7


def test_decode_client_binary_handles_none_bytes_and_empty_string_inputs():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    with pytest.raises(ValueError, match="missing binary value"):
        advanced_module._decode_client_binary(None)

    assert advanced_module._decode_client_binary(b"\x00\x01\x02") == b"\x00\x01\x02"

    with pytest.raises(ValueError, match="empty binary value"):
        advanced_module._decode_client_binary("   ")


def test_parse_client_supplied_credentials_ignores_non_list_and_non_mapping_entries():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._parse_client_supplied_credentials({"not": "a-list"}) == ([], [])

    valid = _valid_credential_entry(resident=True)
    records, serialized = advanced_module._parse_client_supplied_credentials([1, "x", valid])

    assert len(records) == 1
    assert len(serialized) == 1
    assert records[0]["resident"] is True


def test_parse_client_supplied_credentials_derives_resident_from_client_extension_outputs():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    rk_mapping_entry = _valid_credential_entry()
    rk_mapping_entry["clientExtensionOutputs"] = {"credProps": {"rk": True}}

    rk_boolean_entry = _valid_credential_entry()
    rk_boolean_entry["credentialId"] = _b64url(b"credential-id-2")
    rk_boolean_entry["clientExtensionOutputs"] = {"credProps": False}

    records, serialized = advanced_module._parse_client_supplied_credentials(
        [rk_mapping_entry, rk_boolean_entry]
    )

    assert [record["resident"] for record in records] == [True, False]
    assert [entry["resident"] for entry in serialized] == [True, False]


def test_parse_client_supplied_credentials_uses_property_attachment_and_defaults_sign_count():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    entry = _valid_credential_entry()
    entry["signCount"] = "9"  # Non-int values are intentionally normalized to 0.
    entry["properties"] = {"authenticator_attachment": "cross-platform"}

    records, serialized = advanced_module._parse_client_supplied_credentials([entry])

    assert len(records) == 1
    assert records[0]["attachment"] == "cross-platform"
    assert serialized[0]["authenticatorAttachment"] == "cross-platform"
    assert serialized[0]["signCount"] == 0


def test_lookup_named_cose_algorithm_supports_suffix_matching_for_descriptive_labels():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._lookup_named_cose_algorithm("WebAuthn: RSASSA-PKCS1-V1_5-SHA1") == -65535
    assert advanced_module._lookup_named_cose_algorithm("Experimental profile ML-DSA-65") == -49
