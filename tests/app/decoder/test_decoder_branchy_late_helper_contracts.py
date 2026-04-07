from __future__ import annotations

import base64

import cbor2
import pytest


def _auth_header(flags: int = 0x01, sign_count: int = 1) -> bytes:
    return b"\x11" * 32 + bytes([flags]) + sign_count.to_bytes(4, "big")


def test_late_cose_and_base64_helpers_cover_fallback_and_conversion_branches():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._resolve_cose_algorithm({"3": "-257"}) == "RS256"
    assert decode_module._resolve_cose_algorithm({"alg": "custom-alg"}) == "custom-alg"
    assert decode_module._resolve_cose_algorithm({}, {"publicKeyAlgorithm": -259}) == "RS512"
    assert decode_module._resolve_cose_algorithm({}, -999) == "-999"
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


def test_binary_extract_helpers_cover_nested_hex_error_and_fallback(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._extract_hex_from_binary({"binary": {"hex": "AABB"}}) == "AABB"

    monkeypatch.setattr(
        decode_module.base64,
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
        decode_module,
        "_extract_authenticator_bytes_from_attestation",
        _fake_extract,
        raising=False,
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
    assert info["algorithm"] == "ES256"

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


def test_lenient_decode_variants_cover_tag_and_truncated_float_branches():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    tagged, tagged_offset = decode_module._lenient_decode_from(b"\xc1\x01")
    assert tagged == {"tag": 1, "value": 1}
    assert tagged_offset == 2

    simple_value, simple_offset = decode_module._lenient_decode_from(b"\xf8")
    assert simple_value == 0
    assert simple_offset == 2

    float_value, float_offset = decode_module._lenient_decode_from(b"\xfa\x00")
    assert float_value == 0.0
    assert float_offset == 2

    text_value, text_offset = decode_module._lenient_decode_from(b"\x7f\x01\xff")
    assert text_value == ""
    assert text_offset == 3

    array_value, array_offset = decode_module._lenient_decode_from(b"\x81")
    assert array_value == []
    assert array_offset == 1

    map_value, map_offset = decode_module._lenient_decode_from(b"\xa1")
    assert map_value == {}
    assert map_offset == 1


def test_ctap_interpretation_variants_cover_request_guard_and_attstmt_bytes(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = _auth_header(flags=0x01, sign_count=9)

    make_with_byte_attstmt = {1: "packed", 2: auth_data, 3: b"\xaa\xbb", 9: b"\x01"}
    interpreted_make = decode_module._interpret_make_credential_map(make_with_byte_attstmt)
    assert interpreted_make is not None
    assert interpreted_make["3 (attStmt)"] == "aabb"
    assert interpreted_make["9"] == "01"

    assert decode_module._interpret_make_credential_map({1: "packed", 2: auth_data, 3: 5}) is None

    assert decode_module._interpret_get_assertion_map({1: "example.com", 2: b"\x00" * 32}) is None

    interpreted_request = decode_module._interpret_ctap_cbor_value(
        {"rpId": "example.com", "clientDataHash": b"\x10" * 32}
    )
    assert interpreted_request is not None
    assert "getAssertionRequest" in interpreted_request
    assert decode_module._interpret_ctap_cbor_value("not-a-map") is None

    trailing = cbor2.dumps(3) + cbor2.dumps("not-bytes") + cbor2.dumps(10) + cbor2.dumps(1)
    monkeypatch.setattr(
        decode_module,
        "_format_auth_data_for_expanded_json",
        lambda _auth: ({"rpIdHash": "00" * 32}, trailing),
        raising=False,
    )
    interpreted_assertion = decode_module._interpret_get_assertion_map({2: auth_data})
    assert interpreted_assertion is not None
    assert interpreted_assertion["3 (signature)"] is None
    assert interpreted_assertion["trailingFields"]["10"] == 1


def test_try_decode_cbor_warns_for_trailing_bytes_and_records_ignored_padding(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        decode_module,
        "_decode_cbor_sequence",
        lambda _payload: ([{"byteLength": 1}], [42], 1, b"\x11\x22"),
        raising=False,
    )
    result = decode_module._try_decode_cbor(b"\x01\xaa", "hex")
    assert result is not None
    assert any("Trailing 2 byte(s)" in msg for msg in result.get("malformed", []))
    assert result["decoded"]["ctap"]["trailingBytesHex"] == "1122"

    monkeypatch.setattr(
        decode_module,
        "_decode_cbor_sequence",
        lambda _payload: ([{"byteLength": 1}], [42], 1, b"\x00\xff"),
        raising=False,
    )
    result_padding = decode_module._try_decode_cbor(b"\x01\xaa", "hex")
    assert result_padding is not None
    assert result_padding["decoded"]["ctap"]["ignoredPaddingBytes"] == 2
    assert all(
        "Trailing" not in msg for msg in result_padding.get("malformed", [])
    )
