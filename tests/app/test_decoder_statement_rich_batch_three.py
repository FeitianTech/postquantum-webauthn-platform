from __future__ import annotations

import base64
import hashlib

import pytest

from tests.fido2.test_attestation import _GSR2_DER


def _build_attested_auth_data(sign_count: int = 1) -> bytes:
    from fido2.cose import CoseKey
    from fido2.webauthn import AttestedCredentialData, AuthenticatorData

    credential_id = b"batch-three-cred"
    cose_key = CoseKey.parse({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    credential_data = AttestedCredentialData.create(
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        credential_id,
        cose_key,
    )
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT,
        sign_count,
        credential_data,
    )
    return bytes(auth_data)


def test_try_decode_cbor_make_credential_output_merges_trailing_signature_and_builds_expanded_json(
    monkeypatch,
):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = _build_attested_auth_data(sign_count=2)
    trailing_signature = b"\xaa\xbb\xcc\xdd"
    base_structure = {
        "byteLength": 1,
        "summary": "map[3]",
        "length": 3,
        "entries": [
            {
                "keySummary": "fmt",
                "key": {"majorType": 3, "type": "text string", "value": "fmt", "summary": '"fmt"'},
                "value": {"majorType": 3, "type": "text string", "value": "packed", "summary": '"packed"'},
            }
        ],
    }

    monkeypatch.setattr(
        decode_module,
        "_decode_cbor_sequence",
        lambda _payload: (
            [base_structure],
            [{"fmt": "packed", "authData": auth_data, "attStmt": {"sig": b"\x01\x02"}}],
            1,
            trailing_signature,
        ),
        raising=False,
    )

    result = decode_module._try_decode_cbor(b"\x00\xa0", "hex")

    assert result is not None
    decoded = result["decoded"]
    assert decoded["ctap"]["kind"] == "status"
    assert decoded["ctap"]["signatureLength"] == len(trailing_signature)
    assert "expandedJson" in decoded
    assert any("attStmt" in key for key in decoded["expandedJson"])


def test_try_decode_cbor_status_fallback_promotes_get_assertion_and_records_trailing_warning(
    monkeypatch,
):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = _build_attested_auth_data(sign_count=3)
    base_structure = {
        "byteLength": 1,
        "summary": "map[1]",
        "length": 1,
        "entries": [],
    }

    monkeypatch.setattr(
        decode_module,
        "_decode_cbor_sequence",
        lambda _payload: (
            [base_structure],
            [{"authData": auth_data}],
            1,
            b"\x12\x34",
        ),
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_repair_get_assertion_entries",
        lambda structure, value, raw_bytes=None: (structure, value, None),
        raising=False,
    )

    result = decode_module._try_decode_cbor(b"\x00\xa0", "hex")

    assert result is not None
    decoded = result["decoded"]
    assert decoded["ctap"]["kind"] == "status"
    assert "expandedJson" in decoded
    assert any("signature" in key for key in decoded["expandedJson"])
    assert decoded["ctap"]["trailingBytesHex"] == "1234"
    assert "malformed" in result
    assert any("Trailing 2 byte(s) after CBOR payload." in message for message in result["malformed"])


def test_format_public_key_credential_summary_uses_response_fallback_algorithm_and_renders_sections():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_data = _build_attested_auth_data(sign_count=5)
    rp_hash = hashlib.sha256(b"example.com").hexdigest()

    summary_lines = decode_module._format_public_key_credential_summary(
        {
            "format": "PublicKeyCredential (authentication)",
            "decoded": {
                "response": {
                    "authenticatorData": {
                        "binary": {"hex": auth_data.hex()},
                        "details": {
                            "rpIdHash": {"hex": rp_hash},
                            "flags": {
                                "value": 0x41,
                                "bitfield": "0b01000001",
                                "userPresent": True,
                                "userVerified": False,
                                "backupEligibility": False,
                                "backupState": False,
                                "attestedCredentialDataIncluded": True,
                                "extensionDataIncluded": False,
                            },
                            "signCount": 5,
                            "attestedCredentialData": {
                                "aaguid": "00112233-4455-6677-8899-aabbccddeeff",
                                "aaguidHex": "00112233445566778899aabbccddeeff",
                                "credentialId": {
                                    "hex": "62617463682d74687265652d63726564",
                                    "length": 16,
                                },
                                "publicKey": {},
                            },
                        },
                    },
                    "publicKeyAlgorithm": -257,
                    "clientDataJSON": {
                        "details": {
                            "type": "webauthn.get",
                            "challenge": {"hex": "a1b2"},
                            "origin": "https://example.com",
                            "crossOrigin": False,
                        }
                    },
                },
                "clientExtensionResults": {"credProps": {"rk": True}},
            },
        }
    )

    assert "Detected type:\tPublicKeyCredential" in summary_lines
    assert f"RP ID hash:\t{rp_hash}" in summary_lines
    assert "Counter:\t0x00000005=5" in summary_lines
    assert "Key algorithm:\tRS256" in summary_lines
    assert any(line.startswith("Client extensions:\t") for line in summary_lines)
    assert "Att. certificates:\t" in summary_lines


def test_build_subject_key_identifier_lines_covers_extension_der_and_spki_fallback_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    from_extensions = decode_module._build_subject_key_identifier_lines(
        {
            "extensions": [
                "skip-non-mapping",
                {"oid": "2.5.29.14", "bytes": b"\x01\x02\x03"},
            ]
        }
    )
    assert from_extensions == decode_module.format_hex_bytes_lines(b"\x01\x02\x03")

    from_der = decode_module._build_subject_key_identifier_lines(
        {"derBase64": base64.b64encode(_GSR2_DER).decode("ascii")}
    )
    assert from_der

    spki_bytes = b"statement-rich-spki"
    from_spki_fallback = decode_module._build_subject_key_identifier_lines(
        {
            "derBase64": "%%%invalid%%%",
            "publicKeyInfo": {
                "subjectPublicKeyInfoBase64": base64.b64encode(spki_bytes).decode("ascii")
            },
        }
    )
    assert from_spki_fallback == decode_module.format_hex_bytes_lines(
        hashlib.sha1(spki_bytes).digest()
    )
