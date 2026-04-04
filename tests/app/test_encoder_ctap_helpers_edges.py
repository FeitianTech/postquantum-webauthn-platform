import base64

import pytest


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_encode_make_credential_request_full_structure():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    structure = {
        "1 (clientDataHash)": _b64url(b"\x01" * 32),
        "2 (rp)": {"id": "example.com", "name": "Example"},
        "3 (user)": {
            "id": _b64url(b"user-id"),
            "name": "alice",
            "displayName": "Alice",
            "icon": "https://example.com/icon.png",
        },
        "4 (pubKeyCredParams)": [{"alg": -7, "type": "public-key"}],
        "5 (excludeList)": [{"type": "public-key", "id": _b64url(b"cred-1")}],
        "6 (extensions)": {"credProps": True},
        "7 (options)": {"rk": True},
        "8 (pinUvAuthParam)": {"hex": "aabb"},
        "9 (pinUvAuthProtocol)": "1",
        "10 (enterpriseAttestation)": 1,
        "11 (largeBlobKey)": {"bytes": [1, 2, 3]},
    }

    mapping = encode_module._encode_make_credential_request(structure)

    assert mapping[1] == b"\x01" * 32
    assert mapping[2]["id"] == "example.com"
    assert mapping[3]["name"] == "alice"
    assert mapping[4][0]["alg"] == -7
    assert mapping[8] == b"\xaa\xbb"
    assert mapping[9] == 1
    assert mapping[11] == b"\x01\x02\x03"


def test_encode_get_assertion_request_and_response_full_structures():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    request_mapping = encode_module._encode_get_assertion_request(
        {
            "rpId": "example.com",
            "clientDataHash": _b64url(b"\x02" * 32),
            "allowList": [{"type": "public-key", "id": _b64url(b"cred")}],
            "extensions": {"largeBlob": True},
            "options": {"uv": True},
            "pinUvAuthParam": _b64url(b"\x03\x04"),
            "pinUvAuthProtocol": "1",
            "largeBlobKey": {"bytes": [4, 5, 6]},
        }
    )
    assert request_mapping[1] == "example.com"
    assert request_mapping[2] == b"\x02" * 32
    assert request_mapping[6] == b"\x03\x04"
    assert request_mapping[7] == 1

    response_mapping = encode_module._encode_get_assertion_response(
        {
            "credential": {"type": "public-key", "id": _b64url(b"cred-1")},
            "authData": _b64url(b"\xaa" * 37),
            "signature": _b64url(b"\xbb" * 64),
            "user": {"id": _b64url(b"u"), "name": "alice", "displayName": "Alice", "icon": 42},
            "numberOfCredentials": "2",
            "userSelected": "true",
            "largeBlobKey": {"hex": "a1a2"},
            "extensions": {"credBlob": {"bytes": [1, 2]}},
        }
    )
    assert response_mapping[2] == b"\xaa" * 37
    assert response_mapping[3] == b"\xbb" * 64
    assert response_mapping[4]["icon"] == "42"
    assert response_mapping[5] == 2
    assert response_mapping[6] is True


def test_encode_make_credential_response_and_attestation_statement_edges():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    mapping = encode_module._encode_make_credential_response(
        {
            "fmt": "packed",
            "authData": _b64url(b"\x11" * 37),
            "attStmt": {
                "sig": _b64url(b"\x22\x23"),
                "x5c": [{"hex": "aabb"}],
                "alg": -7,
            },
            "epAtt": False,
            "largeBlobKey": _b64url(b"\x33"),
            "extensions": {"credProps": {"rk": True}},
        }
    )

    assert mapping[1] == "packed"
    assert mapping[2] == b"\x11" * 37
    assert mapping[3]["sig"] == b"\x22\x23"
    assert mapping[3]["x5c"][0] == b"\xaa\xbb"

    assert encode_module._encode_attestation_statement(_b64url(b"\xaa")) == b"\xaa"

    with pytest.raises(ValueError, match="must be an array"):
        encode_module._encode_attestation_statement({"x5c": 123})

    with pytest.raises(ValueError, match="Unable to decode certificate PEM contents"):
        encode_module._require_certificate_bytes({"pem": "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"}, 0)


def test_core_validators_key_matching_and_prefix_determination():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="must be an object"):
        encode_module._require_mapping([], "field")

    assert encode_module._ensure_text("  abc  ", "field") == "abc"
    with pytest.raises(ValueError, match="non-empty"):
        encode_module._ensure_text("   ", "field")

    assert encode_module._ensure_int("0x10", "field") == 16
    with pytest.raises(ValueError, match="not a boolean"):
        encode_module._ensure_int(True, "field")

    assert encode_module._ensure_bool("yes", "field") is True
    assert encode_module._ensure_bool("0", "field") is False
    with pytest.raises(ValueError, match="boolean"):
        encode_module._ensure_bool("maybe", "field")

    assert encode_module._ctap_key_matches("1 (rpId)", {"1", "rpid"}) is True
    assert encode_module._ctap_key_matches("other", {"1", "rpid"}) is False

    structure = {"1 (rpId)": "example.com", "2 (clientDataHash)": "hash"}
    assert encode_module._get_ctap_field_value(structure, "rpId", 1) == "example.com"

    assert encode_module._determine_ctap_prefix({"code": 1, "kind": "command"}, None) == (1, "command")
    assert encode_module._determine_ctap_prefix({"codeHex": "0x02"}, None) == (2, None)
    assert encode_module._determine_ctap_prefix({"codeHex": "invalid"}, "getAssertionRequest") == (0x02, "command")


def test_binary_decoding_helpers_and_ctap_structure_detection():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._maybe_decode_bytes("aabb") == b"\xaa\xbb"
    assert encode_module._maybe_decode_bytes("hello") is None
    assert encode_module._maybe_decode_bytes({"base64": _b64(b"abc")}) == b"abc"
    assert encode_module._maybe_decode_bytes({"base64url": _b64url(b"xyz")}) == b"xyz"
    assert encode_module._maybe_decode_bytes({"bytes": [1, 2, 3]}) == b"\x01\x02\x03"
    assert encode_module._maybe_decode_bytes({"pem": "-----BEGIN DATA-----\nYWJj\n-----END DATA-----"}) == b"abc"
    assert encode_module._maybe_decode_bytes([4, 5, 6]) == b"\x04\x05\x06"

    with pytest.raises(ValueError, match="Unable to interpret field"):
        encode_module._require_bytes({"oops": True}, "field")

    assert encode_module._extract_binary_input([1, 2], "field") == b"\x01\x02"

    decoded_map, kind = encode_module._encode_ctap_from_decoded(
        {
            "ignored": "value",
            "makeCredentialRequest": {
                "clientDataHash": _b64url(b"\x01" * 32),
                "rp": {"id": "example.com"},
                "user": {"id": _b64url(b"user")},
                "pubKeyCredParams": [{"alg": -7, "type": "public-key"}],
            },
        }
    )
    assert kind == "makeCredentialRequest"
    assert decoded_map is not None

    _, kind_mc = encode_module._encode_ctap_from_structure({"fmt": "packed", "authData": _b64url(b"\xaa" * 37)})
    _, kind_ga = encode_module._encode_ctap_from_structure(
        {
            "credential": {"id": _b64url(b"c")},
            "authData": _b64url(b"\x55" * 37),
            "signature": _b64url(b"s"),
        }
    )
    _, kind_gar = encode_module._encode_ctap_from_structure({"rpId": "example.com", "clientDataHash": _b64url(b"\x00" * 32)})

    assert kind_mc == "makeCredentialResponse"
    assert kind_ga == "getAssertionResponse"
    assert kind_gar == "getAssertionRequest"
