import base64
import hashlib

import cbor2
import pytest


def _build_authenticator_data_bytes() -> bytes:
    rp_id_hash = hashlib.sha256(b"example.com").digest()
    flags = bytes([0x45])  # UP + UV + AT
    sign_count = (7).to_bytes(4, "big")

    aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")
    credential_id = b"\x10\x20\x30\x40"
    credential_length = len(credential_id).to_bytes(2, "big")
    cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})

    return rp_id_hash + flags + sign_count + aaguid + credential_length + credential_id + cose_key


def _build_attestation_object_bytes() -> tuple[bytes, bytes]:
    from fido2.cose import CoseKey
    from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData

    credential_id = b"decode-edge-cred"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x03" * 32, -3: b"\x04" * 32})
    credential_data = AttestedCredentialData.create(bytes(16), credential_id, cose_key)
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        11,
        credential_data,
    )
    attestation = AttestationObject.create("none", auth_data, {})
    return bytes(attestation), bytes(auth_data)


def test_format_certificate_extension_value_orders_known_fields_and_nested_entries():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    value = {
        "Hex value": "DEADBEEF",
        "Device identifier": "1.3.6.1.4.1.41482.1.1",
        "Nested": {"Inner": "value"},
        "Items": ["alpha", {"beta": "gamma"}],
        "Empty": "",
    }

    lines = decode_module._format_certificate_extension_value(value)

    assert lines[0] == "Hex value: DEADBEEF"
    assert lines[1] == "1.3.6.1.4.1.41482.1.1 (Security Key by Yubico Series)"
    assert "Nested:" in lines
    assert "Inner: value" in lines
    assert "alpha" in lines
    assert "beta: gamma" in lines


def test_build_signature_and_fingerprint_lines_cover_hex_and_preformatted_inputs():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    direct_lines = decode_module._build_signature_lines(
        {"algorithm": "sha256WithRSAEncryption", "lines": ["aa:bb", "cc:dd"]}
    )
    assert direct_lines == ["Signature Algorithm: sha256WithRSAEncryption", "aa:bb", "cc:dd"]

    derived_lines = decode_module._build_signature_lines(
        {"algorithm": "sha256WithRSAEncryption", "hex": "AABBCCDD"}
    )
    assert derived_lines[0] == "Signature Algorithm: sha256WithRSAEncryption"
    assert any("aa:bb:cc:dd" in line for line in [line.lower() for line in derived_lines[1:]])

    fingerprint_lines = decode_module._build_fingerprint_lines(
        {
            "md5": "00112233445566778899aabbccddeeff",
            "sha1": "aabbccddeeff00112233445566778899aabbccdd",
            "sha256": "00112233445566778899aabbccddeeff" * 2,
        }
    )
    assert fingerprint_lines[0] == "Fingerprint:"
    assert "MD5:" in fingerprint_lines
    assert "SHA1:" in fingerprint_lines
    assert "SHA256:" in fingerprint_lines


def test_collect_attested_info_uses_fallback_details_without_raw_auth_bytes():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    attested = {
        "aaguid": "00112233-4455-6677-8899-aabbccddeeff",
        "aaguidHex": "00112233445566778899aabbccddeeff",
        "credentialId": {"hex": "10203040", "length": 4},
        "publicKey": {"alg": -7, -2: "AQID", -3: "BAUG"},
    }

    info = decode_module._collect_attested_info(attested, None, fallback_alg=-7)

    assert info["credential_id"] == "10203040"
    assert info["algorithm"] == "ES256"
    assert any("010203" in line for line in info["public_key_lines"])


def test_build_authenticator_data_payload_falls_back_to_raw_bytes_when_details_absent():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_bytes = _build_authenticator_data_bytes()
    payload = decode_module._build_authenticator_data_payload(auth_bytes, None, fallback_alg=-7)

    assert payload["rpIdHash"] == hashlib.sha256(b"example.com").hexdigest()
    assert payload["flags"]["UP"] is True
    assert payload["flags"]["AT"] is True
    assert payload["counter"] == 7
    assert payload["credential"]["credentialIdLength"] == "0004"
    assert payload["credential"]["credentialId"] == "10203040"
    assert payload["credential"]["publicKey"]["alg"] == "ES256"


def test_extend_with_attestation_section_renders_certificate_multiline_summary():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    lines = []
    decode_module._extend_with_attestation_section(
        lines,
        {"hex": "aabb"},
        {
            "attestationFormat": "packed",
            "attestationCertificate": {"summary": "line-one\nline-two"},
        },
        include_certificates=True,
    )

    assert "Attestation object:\taabb" in lines
    assert "Att. format:\tpacked" in lines
    assert "Att. certificates:\t" in lines
    assert "  line-one" in lines
    assert "  line-two" in lines


def test_extend_with_authenticator_details_adds_defaults_when_only_raw_bytes_exist():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_bytes = hashlib.sha256(b"example.com").digest() + b"\x01" + (1).to_bytes(4, "big")

    lines = []
    decode_module._extend_with_authenticator_details(lines, None, auth_bytes)

    assert any(line.startswith("Authenticator data:\t") for line in lines)
    assert "RP ID hash:\t(none)" in lines
    assert "Flags:\t(none)" in lines
    assert "Counter:\t(none)" in lines


def test_extract_authenticator_bytes_from_attestation_parses_valid_object_and_handles_invalid():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    attestation_bytes, auth_data_bytes = _build_attestation_object_bytes()
    attestation_entry = {"raw": base64.b64encode(attestation_bytes).decode("ascii")}

    extracted = decode_module._extract_authenticator_bytes_from_attestation(attestation_entry)
    assert extracted == auth_data_bytes

    assert decode_module._extract_authenticator_bytes_from_attestation({"raw": "%%%%"}) is None


def test_format_result_summary_covers_generic_and_client_data_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    generic_summary = decode_module._format_result_summary(
        {"format": None, "decoded": {"alpha": 1}}
    )
    assert "Detected type:\tDecoded data" in generic_summary
    assert "Decoded:" in generic_summary

    client_summary = decode_module._format_result_summary(
        {
            "format": "WebAuthn client data",
            "decoded": {
                "type": "webauthn.create",
                "challenge": "AQID",
                "origin": "https://example.com",
                "crossOrigin": True,
            },
        }
    )
    assert "Detected type:\tWebAuthn client data" in client_summary
    assert "Type:\twebauthn.create" in client_summary
    assert "Origin:\thttps://example.com" in client_summary
    assert "Cross-origin:\ttrue" in client_summary
