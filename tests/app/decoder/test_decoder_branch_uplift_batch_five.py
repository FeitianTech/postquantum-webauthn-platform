from __future__ import annotations

import base64

import cbor2
import pytest

from fido2 import cbor
from fido2.webauthn import AuthenticatorData


def test_lenient_decode_from_indefinite_and_float_paths_cover_remaining_edges():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._lenient_decode_from(b"\x5f\xff") == (b"", 2)

    byte_chunks, byte_offset = decode_module._lenient_decode_from(b"\x5f\x41A\x61b")
    assert byte_chunks == b"A"
    assert byte_offset == 5

    text_chunks, text_offset = decode_module._lenient_decode_from(b"\x7f\x61a\xff")
    assert text_chunks == "a"
    assert text_offset == 4

    assert decode_module._lenient_decode_from(b"\x81\xf6") == ([], 2)
    assert decode_module._lenient_decode_from(b"\xa1\xf6") == ({}, 2)

    assert decode_module._lenient_decode_from(b"\xf9\x3c\x00")[0] == pytest.approx(1.0)
    assert decode_module._lenient_decode_from(b"\xfa\x3f\x80\x00\x00")[0] == pytest.approx(1.0)
    assert decode_module._lenient_decode_from(b"\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00")[0] == pytest.approx(1.0)


def test_decode_cbor_sequence_handles_fallback_decoder_and_zero_consumed_paths(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        cbor,
        "decode_from",
        lambda _payload: (_ for _ in ()).throw(ValueError("bad-cbor")),
    )

    class _FallbackDecoder:
        def __init__(self, fp):
            self._fp = fp

        def decode(self):
            self._fp.read(1)
            return {"decoded": True}

    monkeypatch.setattr(cbor2, "CBORDecoder", _FallbackDecoder)

    structures, values, consumed, remaining = decode_module._decode_cbor_sequence(b"\x01")
    assert len(structures) == 1
    assert values == [{"decoded": True}]
    assert consumed == 1
    assert remaining == b""

    monkeypatch.setattr(
        cbor,
        "decode_from",
        lambda payload: (1, payload),
    )
    structures, values, consumed, remaining = decode_module._decode_cbor_sequence(b"\x01")
    assert structures == []
    assert values == []
    assert consumed == 0
    assert remaining == b"\x01"


def test_decode_cbor_sequence_breaks_when_lenient_fallback_raises(monkeypatch, cbor_parser):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        cbor,
        "decode_from",
        lambda _payload: (_ for _ in ()).throw(ValueError("bad-cbor")),
    )

    class _BrokenDecoder:
        def __init__(self, _fp):
            pass

        def decode(self):
            raise ValueError("broken")

    monkeypatch.setattr(cbor2, "CBORDecoder", _BrokenDecoder)
    monkeypatch.setattr(
        cbor_parser,
        "_decode_cbor_structure",
        lambda _payload: (_ for _ in ()).throw(
            decode_module._CborDecodingError("bad", 0)
        ),
    )
    monkeypatch.setattr(
        cbor_parser,
        "_lenient_decode_from",
        lambda _payload, _offset=0: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    structures, values, consumed, remaining = decode_module._decode_cbor_sequence(b"\xa1")
    assert structures == []
    assert values == []
    assert consumed == 0
    assert remaining == b"\xa1"


def test_parse_authenticator_data_bytes_handles_truncation_and_decode_failures(monkeypatch, cbor_parser):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    truncated_payload = b"\x00" * 32 + bytes([AuthenticatorData.FLAG.AT]) + (1).to_bytes(4, "big")
    details, trimmed, trailing = decode_module._parse_authenticator_data_bytes(truncated_payload)
    assert "attestedCredentialData" not in details
    assert trimmed == truncated_payload
    assert trailing == b""

    mismatch_payload = (
        b"\x01" * 32
        + bytes([AuthenticatorData.FLAG.AT])
        + (2).to_bytes(4, "big")
        + (b"\x02" * 16)
        + (4).to_bytes(2, "big")
        + b"AB"
    )
    mismatch_details, _, _ = decode_module._parse_authenticator_data_bytes(mismatch_payload)
    assert mismatch_details["attestedCredentialData"]["lengthMismatch"] is True

    payload_with_bad_cose = (
        b"\x01" * 32
        + bytes([AuthenticatorData.FLAG.AT])
        + (2).to_bytes(4, "big")
        + (b"\x02" * 16)
        + (2).to_bytes(2, "big")
        + b"AB"
        + b"\xa1"
    )

    monkeypatch.setattr(
        cbor_parser,
        "_lenient_decode_from",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("decode failure")),
    )

    details, _, _ = decode_module._parse_authenticator_data_bytes(payload_with_bad_cose)
    assert details["attestedCredentialData"]["credentialPublicKey"] == "a1"


def test_parse_authenticator_data_bytes_handles_extension_non_mapping_and_zero_consumed(monkeypatch, cbor_parser):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    extension_payload = (
        b"\x03" * 32
        + bytes([AuthenticatorData.FLAG.ED])
        + (3).to_bytes(4, "big")
        + cbor.encode(7)
    )
    details, _, trailing = decode_module._parse_authenticator_data_bytes(extension_payload)
    assert details["extensions"] == 7
    assert trailing == b""

    monkeypatch.setattr(
        cbor_parser,
        "_lenient_decode_from",
        lambda *_args, **_kwargs: (None, 0),
    )
    details, trimmed, trailing = decode_module._parse_authenticator_data_bytes(extension_payload)
    assert trimmed == extension_payload
    assert trailing == cbor.encode(7)


def test_convert_ctap_user_attestation_entry_and_payload_helpers_cover_remaining_edges():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._convert_ctap_user(b"\x80") == "80"
    assert decode_module._convert_ctap_user("not-binary") == "not-binary"
    assert decode_module._convert_ctap_user(123) == 123

    converted_user = decode_module._convert_ctap_user(
        {
            "id": b"uid",
            "name": "alice",
            "displayName": "Alice",
            "icon": b"\xff",
            "extra": True,
        }
    )
    assert converted_user["id"] == "756964"
    assert "icon" in converted_user
    assert converted_user["extra"] is True

    assert decode_module._convert_attestation_entry("not-mapping") == {}

    cert_bytes = b"\x30\x82\x01\x00"
    cert_payload = {
        "raw": cert_bytes.hex(),
        "derBase64": base64.b64encode(cert_bytes).decode("ascii"),
    }
    converted_attestation = decode_module._convert_attestation_entry(
        {
            "details": {
                "cbor": {"fmt": "packed"},
                "attestationStatement": {"x5c": []},
                "attestationCertificates": [cert_payload],
            }
        }
    )
    assert converted_attestation["fmt"] == "packed"
    assert converted_attestation["attStmt"]["x5c"]

    assert decode_module._build_flag_payload(None, None, auth_byte_length=20) == {}
    assert decode_module._build_flag_payload({"value": "bad"}, None) == {}

    credential_payload = decode_module._build_credential_payload(
        {
            "credentialId": {"hex": "aa", "length": "len-as-text"},
            "publicKey": {},
        },
        None,
    )
    assert credential_payload["credentialIdLength"] == "len-as-text"


def test_build_subject_key_identifier_lines_handles_der_parse_and_spki_decode_failures():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert (
        decode_module._build_subject_key_identifier_lines(
            {"derBase64": base64.b64encode(b"not-der").decode("ascii")}
        )
        == []
    )
    assert (
        decode_module._build_subject_key_identifier_lines(
            {"publicKeyInfo": {"subjectPublicKeyInfoBase64": "%%%"}}
        )
        == []
    )
