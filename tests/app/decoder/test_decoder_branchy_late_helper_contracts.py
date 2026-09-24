from __future__ import annotations

import base64

import cbor2
import pytest


def _auth_header(flags: int = 0x01, sign_count: int = 1) -> bytes:
    return b"\x11" * 32 + bytes([flags]) + sign_count.to_bytes(4, "big")


def test_late_cose_and_base64_helpers_cover_fallback_and_conversion_branches():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._resolve_cose_algorithm({"3": "-257"}) == "RS256 (RSA)"
    assert decode_module._resolve_cose_algorithm({"alg": "custom-alg"}) == "custom-alg"
    assert decode_module._resolve_cose_algorithm({}, {"publicKeyAlgorithm": -259}) == "RS512 (RSA)"
    assert decode_module._resolve_cose_algorithm({}, -999) == "COSE alg -999"
    assert decode_module._resolve_cose_algorithm({}, None) is None

    converted = decode_module._convert_cose_key_for_display([
        "AQI=",
        {"k": "AQI="},
        "not-base64$$",
    ])
    assert converted[0] == "0102"
    assert converted[1]["k"] == "0102"
    assert converted[2] == "not-base64$$"

    assert decode_module._decode_base64_field("++8") == b"\xfb\xef"
    assert decode_module._decode_base64_field("   ") is None


def test_binary_extract_helpers_cover_nested_hex_error_and_fallback(monkeypatch, binary):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._extract_hex_from_binary({"binary": {"hex": "AABB"}}) == "AABB"

    monkeypatch.setattr(
        base64,
        "urlsafe_b64decode",
        lambda _value: (_ for _ in ()).throw(ValueError("invalid-base64")),
    )
    assert decode_module._extract_bytes_from_binary({"hex": "ZZ", "raw": "%%%%"}) is None
    monkeypatch.undo()

    raw = base64.urlsafe_b64encode(b"\x01\x02").decode("ascii").rstrip("=")
    assert decode_module._extract_bytes_from_binary({"raw": raw}) == b"\x01\x02"

    called: dict[str, object] = {}

    def _fake_extract(attestation_entry):
        called["entry"] = attestation_entry
        return b"\x99"

    monkeypatch.setattr(
        binary,
        "_extract_authenticator_bytes_from_attestation",
        _fake_extract,
    )

    assert (
        decode_module._extract_authenticator_bytes("not-a-mapping", {"raw": "AQI="})
        == b"\x99"
    )
    assert called["entry"] == {"raw": "AQI="}

    assert (
        decode_module._extract_authenticator_bytes(
            {"authenticatorData": {"hex": "aa"}}, {"raw": "AQI="}
        )
        == b"\xaa"
    )


def test_parse_and_collect_attested_info_cover_truncated_and_fallback_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    short_payload = _auth_header() + b"\xaa\xbb"
    assert decode_module._parse_attested_data(short_payload) == {"raw": b"\xaa\xbb"}

    truncated_payload = _auth_header(flags=0x41, sign_count=3) + b"\x00" * 16 + (10).to_bytes(
        2, "big"
    ) + b"\xaa\xbb\xcc"
    parsed_truncated = decode_module._parse_attested_data(truncated_payload)
    assert parsed_truncated is not None
    assert parsed_truncated["credential_id"] == b"\xaa\xbb\xcc"
    assert parsed_truncated["public_key"] == b""

    full_payload = _auth_header(flags=0x41, sign_count=4) + b"\x11" * 16 + (1).to_bytes(
        2, "big"
    ) + b"\xdd" + b"\x01\x02"
    parsed_full = decode_module._parse_attested_data(full_payload)
    assert parsed_full is not None
    assert parsed_full["public_key"] == b"\x01\x02"

    attested = {
        "aaguid": "00112233-4455-6677-8899-aabbccddeeff",
        "aaguidHex": "00112233445566778899aabbccddeeff",
        "credentialId": {"hex": "beef", "length": 2},
        "publicKey": {},
    }
    info = decode_module._collect_attested_info(
        attested,
        None,
        fallback_alg={"publicKeyAlgorithm": -7},
    )
    assert info["credential_id"] == "beef"
    assert "0002" in info["credential_lines"]
    assert info["algorithm"] == "ES256 (ECDSA)"

    info_from_parsed = decode_module._collect_attested_info(
        {"publicKey": {3: -7}},
        full_payload,
        fallback_alg=None,
    )
    assert "0102" in info_from_parsed["credential_lines"]


def test_late_summary_extension_and_client_data_helpers_cover_fallback_rendering_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    lines: list[str] = []
    decode_module._extend_with_authenticator_extensions(lines, {"extensions": {}})
    assert "Authenticator extensions:\t(none)" in lines

    lines = []
    decode_module._extend_with_authenticator_extensions(
        lines, {"extensions": {"raw": {"uvm": True}}}
    )
    assert any(line == "Authenticator extensions:\t" for line in lines)

    lines = []
    decode_module._extend_with_attestation_section(
        lines,
        {"hex": "aa"},
        {
            "attestationFormat": "packed",
            "attestationCertificate": {"summary": "   ", "subject": "CN=Demo"},
        },
        include_certificates=True,
    )
    assert any(line == "Att. certificates:\t" for line in lines)
    assert any("subject" in line.lower() for line in lines)

    lines = []
    decode_module._extend_with_client_data_entry(lines, {"unexpected": True})
    assert "Client data:\t(none)" in lines

    lines = []
    decode_module._extend_with_client_data_details(
        lines,
        {
            "rawText": "line-1\nline-2",
            "type": "webauthn.get",
            "challenge": {"binary": "only"},
            "origin": "https://example.com",
            "crossOrigin": "MAYBE",
        },
    )
    assert any(line == "  line-1" for line in lines)
    assert "Challenge:\t(none)" in lines
    assert "Cross-origin:\tMAYBE" in lines

    cbor_lines = decode_module._format_cbor_summary(
        {
            "decoded": {
                "ctap": {"codeHex": "0x02", "kind": "command"},
                "ctapDecoded": {"getAssertionRequest": {"1 (rpId)": "example.com"}},
            }
        }
    )
    assert all(not line.startswith("CTAP interpretation:\t") for line in cbor_lines)
    assert any(line == "CTAP decoded:\t" for line in cbor_lines)

    generic_lines = decode_module._format_generic_summary(
        {"format": "Opaque blob", "decoded": None, "binary": {"hex": "aabb"}}
    )
    assert any(line == "Binary:\t" for line in generic_lines)


def test_ctap_interpretation_variants_cover_request_guard_and_attstmt_bytes(monkeypatch, ctap):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = _auth_header(flags=0x01, sign_count=9)

    make_with_byte_attstmt = {1: "packed", 2: auth_data, 3: b"\xaa\xbb", 9: b"\x01"}
    interpreted_make = decode_module._interpret_make_credential_map(make_with_byte_attstmt)
    assert interpreted_make is not None
    assert interpreted_make["3 (attStmt)"] == "aabb"
    assert interpreted_make["9"] == "01"

    assert decode_module._interpret_make_credential_map({1: "packed", 2: auth_data, 3: 5}) is None

    assert decode_module._interpret_get_assertion_map({1: "example.com", 2: b"\x00" * 32}) is None

    # Text names are not CTAP members: only the integer-keyed map is a request.
    assert decode_module._interpret_ctap_cbor_value({"rpId": "example.com", "clientDataHash": b"\x10" * 32}) is None
    interpreted_request = decode_module._interpret_ctap_cbor_value({1: "example.com", 2: b"\x10" * 32})
    assert interpreted_request is not None
    assert "getAssertionRequest" in interpreted_request
    assert decode_module._interpret_ctap_cbor_value("not-a-map") is None

    trailing = cbor2.dumps(3) + cbor2.dumps("not-bytes") + cbor2.dumps(10) + cbor2.dumps(1)
    monkeypatch.setattr(
        ctap,
        "_format_auth_data_for_expanded_json",
        lambda _auth: ({"rpIdHash": "00" * 32}, trailing),
    )
    interpreted_assertion = decode_module._interpret_get_assertion_map({2: auth_data})
    assert interpreted_assertion is not None
    # The patch is what the interpreter read (it looks the helper up on ctap).
    assert interpreted_assertion["2 (authData)"] == {"rpIdHash": "00" * 32}
    assert interpreted_assertion["3 (signature)"] is None
    assert "trailingFields" not in interpreted_assertion
    assert "10" not in interpreted_assertion


def test_try_decode_cbor_reports_trailing_bytes_and_padding_alike():
    # MAKE_CREDENTIAL, the integer 42, then two more bytes. Padding is reported
    # as well, as padding: nothing after the item goes unmentioned.
    decode_module = pytest.importorskip("server.app.decoder.decode")

    result = decode_module._try_decode_cbor(b"\x01\x18\x2a\x11\x22", "hex")
    assert result["malformed"] == ["Trailing 2 byte(s) after CBOR payload."]
    assert result["decoded"]["ctap"]["trailingBytesHex"] == "1122"
    assert result["decoded"]["ctap"]["payloadLength"] == 2

    result_padding = decode_module._try_decode_cbor(b"\x01\x18\x2a\x00\xff", "hex")
    assert result_padding["decoded"]["ctap"]["ignoredPaddingBytes"] == 2
    assert result_padding["malformed"] == [
        "Trailing 2 byte(s) after CBOR payload (all 0x00/0xff: HID report padding?)."
    ]
