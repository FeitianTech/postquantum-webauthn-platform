from __future__ import annotations

import base64

from server.app.decoder import values as decoder_values
from server.app.decoder.decode import attestation_object as decode_attestation_object
from server.app.decoder.decode import authenticator_data as decode_authenticator_data
from server.app.decoder.decode import binary_text, credential_json
from server.app.decoder.decode import pem as decode_pem
from server.app.decoder.decode import text as decode_text
from tests.app.python_fido2_vectors import GSR2_DER as _GSR2_DER


def _pem_block(der_bytes: bytes) -> str:
    body = base64.b64encode(der_bytes).decode("ascii")
    wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----"


def test_decode_public_key_credential_includes_signature_and_user_handle_summaries(monkeypatch):
    def _decode_binary(value):
        if value == "sig":
            return b"\xaa\xbb", "base64"
        if value == "uh":
            return b"\x01\x02", "base64url"
        return None

    monkeypatch.setattr(binary_text, "decode_binary_field", _decode_binary)

    result = credential_json.decode_public_key_credential(
        {
            "id": "credential-id",
            "type": "public-key",
            "response": {
                "signature": "sig",
                "userHandle": "uh",
            },
        }
    )

    response = result["decoded"]["response"]
    assert response["signature"]["binary"]["hex"] == "aabb"
    assert response["userHandle"]["binary"]["hex"] == "0102"


def test_decode_pem_certificates_skips_decode_errors_and_uses_single_certificate_payload_shape():
    invalid_body_block = "-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----"
    pem_text = "\n".join([invalid_body_block, _pem_block(_GSR2_DER)])

    result = decode_pem.decode_pem_certificates(pem_text)
    assert result["format"] == "X.509 certificate (PEM)"
    assert isinstance(result["decoded"], dict)
    assert "rawPem" in result["decoded"]
    assert "certificates" not in result["decoded"]


def test_decode_binary_payload_uses_authenticator_data_path_when_other_binary_decoders_fail(monkeypatch):
    monkeypatch.setattr(decoder_values, "try_decode_utf8", lambda _data: None)
    monkeypatch.setattr(decode_pem, "try_decode_der_certificate", lambda _data, _enc: None)
    monkeypatch.setattr(decode_attestation_object, "try_decode", lambda _data, _enc: None)
    monkeypatch.setattr(
        decode_authenticator_data,
        "try_decode",
        lambda _data, enc: {"format": "Authenticator data (binary)", "inputEncoding": enc},
    )

    result = decode_text._decode_binary_payload(b"raw", "hex")
    assert result["format"] == "Authenticator data (binary)"
    assert result["inputEncoding"] == "hex"


def test_try_decode_authenticator_data_returns_structured_payload_on_success(monkeypatch):
    monkeypatch.setattr(
        decode_authenticator_data,
        "_describe_authenticator_data_bytes",
        lambda _data: {"parsed": True},
    )
    monkeypatch.setattr(
        decoder_values,
        "binary_summary",
        lambda data, encoding=None: {"hex": data.hex(), "encoding": encoding},
    )

    result = decode_authenticator_data.try_decode(b"\x01\x02", "hex")
    assert result == {
        "format": "Authenticator data (binary)",
        "inputEncoding": "hex",
        "decoded": {"parsed": True},
        "binary": {"hex": "0102", "encoding": "hex"},
        "extraData": {},
        "findings": [],
    }
