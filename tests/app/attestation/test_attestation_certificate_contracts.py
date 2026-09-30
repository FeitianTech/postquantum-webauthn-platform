import base64
import hashlib

import pytest


def test_der_octet_string_content_unwraps_one_octet_string(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    assert attestation_module.der_octet_string_content(b"\x04\x02\xaa\xbb") == b"\xaa\xbb"
    # The content is shown as it is: an OCTET STRING inside is not unwrapped too.
    assert attestation_module.der_octet_string_content(b"\x04\x04\x04\x02\xaa\xbb") == b"\x04\x02\xaa\xbb"
    # Trailing bytes are not DER: the bytes are shown as sent.
    assert attestation_module.der_octet_string_content(b"\x04\x01\xaa\xbb") == b"\x04\x01\xaa\xbb"


def test_der_octet_string_content_keeps_a_truncated_long_form_length(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    payload = b"\x04\x82\x00"

    decoded = attestation_module.der_octet_string_content(payload)

    assert decoded == payload


def test_der_octet_string_content_keeps_an_indefinite_length(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    payload = b"\x04\x80\xaa\xbb"

    decoded = attestation_module.der_octet_string_content(payload)

    assert decoded == payload


def test_serialize_attestation_certificate_returns_none_for_empty_bytes(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    assert attestation_module.serialize_attestation_certificate(b"") is None


def test_serialize_attestation_certificate_returns_fallback_shape_for_malformed_der(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    malformed_der = b"\x30\x82\x01\x00"

    result = attestation_module.serialize_attestation_certificate(malformed_der)

    assert isinstance(result, dict)
    assert result["error"].startswith("Unable to parse attestation certificate:")
    assert isinstance(result["parseError"], str)
    assert result["raw"] == malformed_der.hex()
    assert result["derBase64"] == base64.b64encode(malformed_der).decode("ascii")
    assert result["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert result["pem"].strip().endswith("-----END CERTIFICATE-----")
    assert result["fingerprints"] == {
        "sha256": hashlib.sha256(malformed_der).hexdigest(),
        "sha1": hashlib.sha1(malformed_der).hexdigest(),
        "md5": hashlib.md5(malformed_der).hexdigest(),
    }
    assert isinstance(result["publicKeyInfo"], dict)
    assert "summary" in result


def test_coerce_attestation_certificate_bytes_supports_raw_hex_mapping(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    cert_bytes = b"\x30\x82\x01\x00"
    coerced = attestation_module._coerce_attestation_certificate_bytes(
        {"raw": cert_bytes.hex()}
    )

    assert coerced == cert_bytes


def test_coerce_attestation_certificate_bytes_supports_der_base64_mapping(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    cert_bytes = b"\x30\x82\x01\x00"
    coerced = attestation_module._coerce_attestation_certificate_bytes(
        {"derBase64": base64.b64encode(cert_bytes).decode("ascii")}
    )

    assert coerced == cert_bytes


def test_coerce_attestation_certificate_bytes_supports_pem_mapping(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    cert_bytes = b"\x30\x82\x01\x00"
    body = base64.b64encode(cert_bytes).decode("ascii")
    pem_value = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"

    coerced = attestation_module._coerce_attestation_certificate_bytes({"pem": pem_value})

    assert coerced == cert_bytes


def test_coerce_attestation_certificate_bytes_returns_none_for_invalid_input(attestation_module):
    attestation_module = pytest.importorskip("server.app.webauthn.attestation")

    assert attestation_module._coerce_attestation_certificate_bytes(None) is None
    assert attestation_module._coerce_attestation_certificate_bytes("") is None
    assert attestation_module._coerce_attestation_certificate_bytes({"raw": "zz"}) is None
