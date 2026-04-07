import base64

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_encode_ctap_from_structure_detects_all_ctap_shapes():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    make_req, make_req_kind = encode_module._encode_ctap_from_structure(
        {
            "clientDataHash": _b64url(b"\x00" * 32),
            "rp": {"id": "example.com", "name": "Example"},
            "user": {"id": _b64url(b"user"), "name": "user", "displayName": "User"},
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        }
    )
    assert make_req_kind == "makeCredentialRequest"
    assert make_req[1] == b"\x00" * 32

    get_req, get_req_kind = encode_module._encode_ctap_from_structure(
        {
            "rpId": "example.com",
            "clientDataHash": _b64url(b"\x11" * 32),
        }
    )
    assert get_req_kind == "getAssertionRequest"
    assert get_req[1] == "example.com"

    make_resp, make_resp_kind = encode_module._encode_ctap_from_structure(
        {
            "fmt": "packed",
            "authData": _b64url(b"\x22" * 37),
        }
    )
    assert make_resp_kind == "makeCredentialResponse"
    assert make_resp[1] == "packed"

    get_resp, get_resp_kind = encode_module._encode_ctap_from_structure(
        {
            "credential": {"id": _b64url(b"cred"), "type": "public-key"},
            "authData": _b64url(b"\x33" * 37),
            "signature": _b64url(b"\x44" * 64),
        }
    )
    assert get_resp_kind == "getAssertionResponse"
    assert get_resp[3] == b"\x44" * 64


def test_encode_ctap_from_decoded_returns_first_supported_entry_and_none_for_non_mapping():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    encoded, kind = encode_module._encode_ctap_from_decoded(
        {
            "makeCredentialRequest": {
                "clientDataHash": _b64url(b"\xaa" * 32),
                "rp": {"id": "example.com", "name": "Example"},
                "user": {"id": _b64url(b"user"), "name": "user", "displayName": "User"},
                "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            },
            "getAssertionRequest": {
                "rpId": "ignored.example",
                "clientDataHash": _b64url(b"\xbb" * 32),
            },
        }
    )

    assert kind == "makeCredentialRequest"
    assert encoded[1] == b"\xaa" * 32

    assert encode_module._encode_ctap_from_decoded("not-a-mapping") == (None, None)


def test_determine_ctap_prefix_prefers_metadata_and_falls_back_to_defaults():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    prefix, kind = encode_module._determine_ctap_prefix({"codeHex": "0x02", "kind": "command"}, None)
    assert prefix == 0x02
    assert kind == "command"

    prefix2, kind2 = encode_module._determine_ctap_prefix({"codeHex": "bad"}, "getAssertionRequest")
    assert (prefix2, kind2) == (0x02, "command")

    assert encode_module._determine_ctap_prefix(None, "makeCredentialResponse") == (0x00, "status")
    assert encode_module._determine_ctap_prefix(None, None) == (None, None)


def test_ctap_key_match_and_value_lookup_handle_labeled_variants_case_insensitively():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._ctap_key_matches("1 (rpId)", {"1", "rpid"}) is True
    assert encode_module._ctap_key_matches("RPID", {"rpid"}) is True
    assert encode_module._ctap_key_matches("2 (clientDataHash)", {"clientdatahash"}) is True
    assert encode_module._ctap_key_matches("3", {"2"}) is False

    structure = {"1 (rpId)": "example.com", "2 (clientDataHash)": _b64url(b"\x01" * 32)}
    assert encode_module._get_ctap_field_value(structure, "rpId", 1) == "example.com"
    assert encode_module._get_ctap_field_value(structure, "clientDataHash", 2) == _b64url(b"\x01" * 32)


def test_encode_attestation_statement_and_certificate_bytes_error_paths():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._encode_attestation_statement(_b64url(b"sig")) == b"sig"

    with pytest.raises(ValueError, match="attStmt.x5c must be an array"):
        encode_module._encode_attestation_statement({"x5c": 123})

    with pytest.raises(ValueError, match="Unable to decode certificate PEM contents"):
        encode_module._require_certificate_bytes({"pem": "%%%%"}, 0)


def test_encode_ctap_user_and_descriptor_handle_binary_extras_and_validation_errors():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    user = encode_module._encode_ctap_user(
        {
            "id": _b64url(b"user-id"),
            "name": "alice",
            "displayName": "Alice",
            "icon": "https://example.com/icon.png",
            "customBlob": {"base64": base64.b64encode(b"blob").decode("ascii")},
        }
    )

    assert user["id"] == b"user-id"
    assert user["name"] == "alice"
    assert user["displayName"] == "Alice"
    assert user["icon"] == "https://example.com/icon.png"
    assert user["customBlob"] == b"blob"

    descriptor = encode_module._encode_credential_descriptor(
        {
            "type": "public-key",
            "id": _b64url(b"cred-id"),
            "transports": ["usb"],
            "extra": {"hex": "414243"},
        }
    )
    assert descriptor["id"] == b"cred-id"
    assert descriptor["extra"] == b"ABC"

    with pytest.raises(ValueError, match="allowList must be an array"):
        encode_module._encode_allow_list("not-a-list")


def test_numeric_and_boolean_coercion_and_require_bytes_guards():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._ensure_int("0x10", "field") == 16
    assert encode_module._ensure_bool("yes", "field") is True
    assert encode_module._ensure_bool("0", "field") is False

    with pytest.raises(ValueError, match="not a boolean"):
        encode_module._ensure_int(True, "field")

    with pytest.raises(ValueError, match="must be a boolean"):
        encode_module._ensure_bool("maybe", "field")

    assert encode_module._require_bytes({"hex": "aabb"}, "binary") == b"\xaa\xbb"

    with pytest.raises(ValueError, match="Unable to interpret binary"):
        encode_module._require_bytes({"text": "plain"}, "binary")


def test_maybe_decode_bytes_supports_mapping_and_sequence_forms():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._maybe_decode_bytes({"bytes": [1, 2, 3]}) == b"\x01\x02\x03"
    assert encode_module._maybe_decode_bytes({"base64url": _b64url(b"xyz")}) == b"xyz"
    assert encode_module._maybe_decode_bytes("AA:BB") == b"\xaa\xbb"
    assert encode_module._maybe_decode_bytes([65, 66, 67]) == b"ABC"
