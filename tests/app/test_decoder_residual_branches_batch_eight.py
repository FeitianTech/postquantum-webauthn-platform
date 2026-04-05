from __future__ import annotations

import base64

import cbor2
import pytest


def test_build_credential_payload_covers_length_string_and_empty_public_key_payload():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    payload = decode_module._build_credential_payload(
        {
            "credentialId": {
                "hex": "aabb",
                "length": "len-as-text",
            },
            "publicKey": "not-a-mapping",
        },
        b"\x00" * 38,
        None,
    )

    assert payload["credentialId"] == "aabb"
    assert payload["credentialIdLength"] == "len-as-text"
    assert "publicKey" not in payload


def test_build_certificate_summary_lines_handles_partial_fields_and_validity_shapes():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    lines = decode_module._build_certificate_summary_lines(
        {
            "version": {"display": ""},
            "serialNumber": {"decimal": "12345"},
            "signatureAlgorithm": "sha256WithRSAEncryption",
            "issuer": "CN=Issuer",
            "validity": {
                "notBefore": "2025-01-01T00:00:00+00:00",
                "notAfter": "",
            },
            "subject": "CN=Leaf",
            "publicKeyInfo": {},
            "extensions": [],
            "signature": None,
            "fingerprints": None,
        }
    )

    assert "Certificate Serial Number: 12345" in lines
    assert "Signature Algorithm: sha256WithRSAEncryption" in lines
    assert "Validity" in lines
    assert any(line.startswith("Not Before:") for line in lines)


def test_build_subject_key_identifier_lines_handles_extension_bytes_der_failures_and_spki_fallback(
    monkeypatch,
):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    ext_lines = decode_module._build_subject_key_identifier_lines(
        {
            "extensions": [
                "skip",
                {
                    "oid": "2.5.29.14",
                    "value": {"Subject Key Identifier": "  "},
                    "bytes": bytearray(b"\xAA\xBB"),
                },
            ]
        }
    )
    assert ext_lines

    der_b64 = base64.b64encode(b"fake-der").decode("ascii")

    class _Extensions:
        def get_extension_for_oid(self, _oid):
            raise decode_module.x509.ExtensionNotFound("missing", _oid)

    class _Certificate:
        extensions = _Extensions()

        def public_key(self):
            raise RuntimeError("no public key")

    monkeypatch.setattr(
        decode_module.x509,
        "load_der_x509_certificate",
        lambda _value: _Certificate(),
        raising=False,
    )

    assert (
        decode_module._build_subject_key_identifier_lines(
            {
                "derBase64": der_b64,
                "publicKeyInfo": {
                    "subjectPublicKeyInfoBase64": base64.b64encode(b"spki").decode("ascii")
                },
            }
        )
        == decode_module.format_hex_bytes_lines(__import__("hashlib").sha1(b"spki").digest())
    )


def test_collect_attested_info_fallback_paths_without_auth_bytes():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    info = decode_module._collect_attested_info(
        {
            "aaguidHex": "00112233445566778899aabbccddeeff",
            "aaguid": "00112233-4455-6677-8899-aabbccddeeff",
            "credentialId": {
                "length": 2,
                "hex": "cafe",
            },
            "publicKey": {
                "alg": "-7",
            },
        },
        None,
    )

    assert info["credential_id"] == "cafe"
    assert info["algorithm"] == "ES256"
    assert "00112233445566778899aabbccddeeff" in info["credential_lines"]

    assert decode_module._collect_attested_info({}, None) == {}


def test_binary_extractors_and_authenticator_fallback_paths(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._extract_hex_from_binary({"binary": {"hex": "aabb"}}) == "aabb"

    monkeypatch.setattr(
        decode_module,
        "_extract_authenticator_bytes_from_attestation",
        lambda _entry: b"from-attestation",
        raising=False,
    )

    assert (
        decode_module._extract_authenticator_bytes(
            {
                "attestationObject": {
                    "raw": base64.b64encode(cbor2.dumps({"authData": b"\x00" * 37})).decode("ascii")
                }
            }
        )
        == b"from-attestation"
    )


def test_append_authenticator_section_uses_response_context_public_key_algorithm(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    captured = {}

    def _collect(attested, auth_bytes, fallback_alg=None):
        captured["fallback_alg"] = fallback_alg
        return {
            "credential_lines": ["cred"],
            "aaguid_lines": ["aaguid"],
            "credential_id": "id",
            "algorithm": "ES256",
            "public_key_lines": ["pk"],
        }

    monkeypatch.setattr(decode_module, "_collect_attested_info", _collect, raising=False)

    lines = []
    decode_module._extend_with_authenticator_details(
        lines,
        {
            "rpIdHash": {"hex": "abcd"},
            "flags": {"UP": True},
            "signCount": 1,
            "attestedCredentialData": {"aaguidHex": "aa"},
        },
        None,
        response_context={"publicKeyAlgorithm": -7},
    )

    assert captured["fallback_alg"] == -7
    assert any("Credential data" in line for line in lines)


def test_append_attestation_and_client_data_sections_cover_none_and_mapping_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    lines = []
    decode_module._extend_with_attestation_section(
        lines,
        {"binary": {"hex": "deadbeef"}},
        {
            "attestationFormat": "packed",
            "attestationCertificate": "not-a-mapping",
        },
        include_certificates=True,
    )
    assert any(line.startswith("Att. certificates:") for line in lines)

    decode_module._extend_with_client_data_entry(
        lines,
        {
            "details": {
                "type": "webauthn.create",
                "challenge": "abc",
                "origin": "https://example.com",
            }
        },
    )
    assert any(line.startswith("Client data") for line in lines)


def test_build_get_assertion_expanded_json_handles_invalid_trailing_hex(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_key = decode_module._format_ctap_entry_key(
        2,
        decode_module._resolve_ctap_label(decode_module._GET_ASSERTION_RESPONSE_LABELS, 2),
    )
    sig_key = decode_module._format_ctap_entry_key(
        3,
        decode_module._resolve_ctap_label(decode_module._GET_ASSERTION_RESPONSE_LABELS, 3),
    )

    monkeypatch.setattr(
        decode_module,
        "_build_labeled_ctap_map",
        lambda *_args, **_kwargs: {
            auth_key: {"trailingBytesHex": "not-hex"},
            sig_key: None,
        },
        raising=False,
    )

    result = decode_module._build_get_assertion_expanded_json({2: b"auth"})
    assert sig_key in result
    assert result[sig_key] is None
