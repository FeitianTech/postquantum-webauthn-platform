"""SafetyNet's JWS and Apple's nonce extension are decoded, marked as not verified.

Real vectors: the android-safetynet and apple attestations in
tests/fido2/attestation/test_attestation.py (:292, :314). The tests below do
the comparisons the decoder deliberately does not make, to show that what it
decoded is the value WebAuthn L3 sections 8.5 and 8.8 talk about.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from server.app.decoder.decode import apple_anonymous, safetynet
from tests.app.decoder.real_vectors import (
    ANDROID_SAFETYNET_ATT_STMT,
    ANDROID_SAFETYNET_AUTH_DATA,
    ANDROID_SAFETYNET_CLIENT_DATA_HASH,
    APPLE_ATT_STMT,
    APPLE_AUTH_DATA,
    APPLE_CLIENT_DATA_HASH,
    PACKED_ATT_STMT,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_the_real_safetynet_response_is_decoded_and_marked_not_verified():
    view = safetynet.read_response(ANDROID_SAFETYNET_ATT_STMT["response"])

    assert view["verification"].startswith("NOT VERIFIED")
    assert view["deprecated"] == "WebAuthn L3 section 8.5: this format is deprecated and expected to be removed"
    assert view["header"]["json"]["alg"] == "RS256"
    leaf, intermediate = view["header"]["certificates"]
    assert "CN=attest.android.com" in leaf["subject"]
    assert "CN=GTS CA 1O1" in leaf["issuer"]
    assert leaf["notValidAfter"] == "2019-10-09T07:19:45+00:00"
    assert "CN=GTS CA 1O1" in intermediate["subject"]
    payload = view["payload"]
    assert payload["json"]["timestampMs"] == 1543482568858
    assert payload["timestampUtc"] == "2018-11-29T09:09:28.858000+00:00"
    assert payload["json"]["apkPackageName"] == "com.google.android.gms"
    assert view["signature"]["length"] == 256
    # The nonce is what section 8.5 says it is; the decoder shows it, a verifier compares it.
    expected_nonce = hashlib.sha256(ANDROID_SAFETYNET_AUTH_DATA + ANDROID_SAFETYNET_CLIENT_DATA_HASH).digest()
    assert base64.b64decode(payload["json"]["nonce"]) == expected_nonce


def test_a_response_that_is_not_a_jws_says_where():
    header = _b64url(json.dumps({"alg": "RS256", "x5c": ["not base64 der!", base64.b64encode(b"junk").decode()]}).encode())
    payload = _b64url(b"{not json")

    assert safetynet.read_response(b"\xff\xfe")["error"] == "response is not UTF-8 (at byte 0)"
    assert safetynet.read_response(b"a.b")["error"] == (
        "a JWS in compact serialization has 3 parts separated by '.'; this has 2"
    )
    assert safetynet.read_response(42)["error"] == "response is a byte string holding a JWS; this is not"
    view = safetynet.read_response(f"{header}.{payload}.!!")
    assert view["header"]["certificates"][0] == {"error": "an x5c entry is base64 DER; this is not"}
    assert view["header"]["certificates"][1]["error"].startswith("not an X.509 certificate")
    assert view["payload"]["error"] == "the payload is not JSON: Expecting property name enclosed in double quotes at character 1"
    assert view["signature"] == {"error": "the signature part is not base64url"}
    assert safetynet.read_response("!!.e30.AA")["header"] == {"error": "the header part is not base64url"}
    assert safetynet.read_response(f"{_b64url(b'\xff')}.e30.AA")["header"] == {"error": "the header is not UTF-8 (at byte 0)"}


def test_the_real_apple_nonce_is_decoded_not_compared():
    view = apple_anonymous.read_certificate(APPLE_ATT_STMT["x5c"][0])

    assert view["extension"] == "1.2.840.113635.100.8.2"
    assert view["length"] == 32
    assert "not compared" in view["note"]
    # The decoder does not compare; this test does, to show the nonce is the right bytes.
    assert view["nonce"] == hashlib.sha256(APPLE_AUTH_DATA + APPLE_CLIENT_DATA_HASH).hexdigest()


def _certificate_with(extension_value: bytes) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(apple_anonymous.NONCE_OID), extension_value),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.DER)


def test_a_nonce_extension_of_another_shape_is_shown_as_hex():
    view = apple_anonymous.read_certificate(_certificate_with(b"\x04\x02\xab\xcd"))

    assert view["hex"] == "0402abcd"
    assert view["error"].startswith("not SEQUENCE {[1] EXPLICIT OCTET STRING}")


def test_certificates_without_the_nonce_or_that_are_not_certificates():
    assert apple_anonymous.read_certificate(PACKED_ATT_STMT["x5c"][0]) == {
        "note": "credCert has no 1.2.840.113635.100.8.2 extension"
    }
    assert apple_anonymous.read_certificate(b"junk")["error"].startswith("credCert is not DER X.509")
