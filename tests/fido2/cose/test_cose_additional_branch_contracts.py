from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from fido2 import cose
from tests.pqc import mldsa_helpers


def _self_signed_cert_der(private_key) -> bytes:
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "cose-branch-test")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=7))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _raw_ec_public_key(curve=ec.SECP256R1()) -> bytes:
    return (
        ec.generate_private_key(curve)
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )


class _FakeOqsVerifier:
    def __init__(self, *, should_verify: bool, details=None):
        self._should_verify = should_verify
        self.details = details

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def verify(self, _message, _signature, _public_key):
        return self._should_verify


def test_get_optional_oqs_and_parameter_details_with_fake_oqs(monkeypatch):
    fake_oqs = SimpleNamespace(
        Signature=lambda _name: _FakeOqsVerifier(
            should_verify=True,
            details={"length_public_key": 4444, "length_signature": 5555},
        )
    )
    monkeypatch.setattr(cose, "oqs", fake_oqs, raising=False)

    assert cose._get_optional_oqs() is fake_oqs
    details = cose._get_mldsa_parameter_details("ML-DSA-65")
    assert details["public_key_length"] == 1952
    assert details["signature_length"] == 3309


def test_get_mldsa_parameter_details_handles_missing_or_failing_oqs(monkeypatch):
    monkeypatch.setattr(cose, "_get_optional_oqs", lambda: None, raising=False)
    assert cose._get_mldsa_parameter_details("ML-DSA-44")["public_key_length"] == 1312
    assert cose._get_mldsa_parameter_details(None) == {}

    class _BrokenOqs:
        def Signature(self, _name):
            raise RuntimeError("broken")

    monkeypatch.setattr(cose, "_get_optional_oqs", lambda: _BrokenOqs(), raising=False)
    fallback = cose._get_mldsa_parameter_details("ML-DSA-87")
    assert fallback["signature_length"] == 4627


def test_cosekey_parse_for_name_and_no_debug_context_paths(capsys):
    assert cose.CoseKey.for_name("DoesNotExist") is cose.UnsupportedKey
    with pytest.raises(ValueError, match="must be provided"):
        cose.CoseKey.parse({1: 2, 3: 0})

    # No key holds assertion context for later logging any more.
    key = cose.CoseKey({})
    for removed in (
        "set_assertion_debug_data",
        "_consume_assertion_debug_data",
        "_log_signature_debug",
        "_assertion_debug_context",
    ):
        assert not hasattr(key, removed), f"{removed} should have been removed"
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "cls,alg_id,param_name,missing_key_error",
    [
        (cose.MLDSA87, -50, "ML-DSA-87", "Missing ML-DSA-87 public key"),
        (cose.MLDSA65, -49, "ML-DSA-65", "Missing ML-DSA-65 public key"),
        (cose.MLDSA44, -48, "ML-DSA-44", "Missing ML-DSA-44 public key"),
    ],
)
def test_mldsa_verify_error_and_invalid_signature_paths(
    cls, alg_id, param_name, missing_key_error
):
    real_key_bytes = mldsa_helpers.public_key_bytes(param_name)

    wrong_param_key = cls({1: 1, 3: alg_id, -1: real_key_bytes})
    with pytest.raises(ValueError, match="Unsupported"):
        wrong_param_key.verify(b"msg", b"sig")

    missing_pub_key = cls({1: 7, 3: alg_id})
    with pytest.raises(ValueError, match=missing_key_error):
        missing_pub_key.verify(b"msg", b"sig")

    # A public key of the wrong length is rejected before any verification.
    short_key = cls({1: 7, 3: alg_id, -1: real_key_bytes[:-1]})
    with pytest.raises(ValueError, match="public key must be"):
        short_key.verify(b"msg", mldsa_helpers.sign(param_name, b"msg"))

    # A forged signature raises InvalidSignature, never ValueError: the
    # @catch_builtins decorator on the attestation verifiers would otherwise
    # relabel a forgery as InvalidData.
    key = cls({1: 7, 3: alg_id, -1: real_key_bytes})
    signature = mldsa_helpers.sign(param_name, b"msg")
    with pytest.raises(InvalidSignature):
        key.verify(bytearray(b"msg"), memoryview(mldsa_helpers.flip_bit(signature)))

    # ... and a genuine signature still verifies through the same call shapes.
    key.verify(bytearray(b"msg"), memoryview(signature))


@pytest.mark.parametrize(
    "cls,alg_id,param_name",
    [
        (cose.MLDSA87, -50, "ML-DSA-87"),
        (cose.MLDSA65, -49, "ML-DSA-65"),
        (cose.MLDSA44, -48, "ML-DSA-44"),
    ],
)
def test_mldsa_from_cryptography_key_calls_coercion(monkeypatch, cls, alg_id, param_name):
    called = {}

    def _fake_coerce(public_key, parameter_set=None):
        called["parameter_set"] = parameter_set
        called["key_type"] = type(public_key).__name__
        return b"normalized"

    monkeypatch.setattr(cose, "_coerce_mldsa_public_key_bytes", _fake_coerce, raising=False)
    key = cls.from_cryptography_key(_raw_ec_public_key())

    assert key[3] == alg_id
    assert key[-1] == b"normalized"
    assert called["parameter_set"] == param_name


def test_curve_guard_branches_for_ec_and_eddsa_variants():
    with pytest.raises(ValueError, match="Unsupported elliptic curve"):
        cose.ES256({1: 2, 3: -7, -1: 2, -2: b"x", -3: b"y"}).verify(b"m", b"s")
    with pytest.raises(ValueError, match="Unsupported elliptic curve"):
        cose.ES384({1: 2, 3: -35, -1: 1, -2: b"x", -3: b"y"}).verify(b"m", b"s")
    with pytest.raises(ValueError, match="Unsupported elliptic curve"):
        cose.ES512({1: 2, 3: -36, -1: 2, -2: b"x", -3: b"y"}).verify(b"m", b"s")
    with pytest.raises(ValueError, match="Unsupported elliptic curve"):
        cose.ES256K({1: 2, 3: -47, -1: 1, -2: b"x", -3: b"y"}).verify(b"m", b"s")
    with pytest.raises(ValueError, match="Unsupported elliptic curve"):
        cose.EdDSA({1: 1, 3: -8, -1: 7, -2: b"x" * 32}).verify(b"m", b"s")
    with pytest.raises(ValueError, match="Unsupported elliptic curve"):
        cose.Ed448({1: 1, 3: -53, -1: 6, -2: b"x" * 57}).verify(b"m", b"s")


def test_ed25519_additional_guard_branches():
    key = cose.Ed25519({1: 1, 3: -19, -1: 6, -2: b"x" * 32})
    with pytest.raises(ValueError, match="64 bytes"):
        key.verify(b"m", b"short")

    wrong_curve = cose.Ed25519({1: 1, 3: -19, -1: 7, -2: b"x" * 32})
    with pytest.raises(ValueError, match="Unsupported elliptic curve"):
        wrong_curve.verify(b"m", b"y" * 64)

    missing_pk = cose.Ed25519({1: 1, 3: -19, -1: 6})
    with pytest.raises(ValueError, match="public key must be 32 bytes"):
        missing_pk.verify(b"m", b"y" * 64)


def test_from_cryptography_key_paths_for_remaining_rsa_and_ed_classes():
    rsa_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    assert cose.RS384.from_cryptography_key(rsa_pub)[3] == -258
    assert cose.RS512.from_cryptography_key(rsa_pub)[3] == -259
    assert cose.PS256.from_cryptography_key(rsa_pub)[3] == -37
    assert cose.PS384.from_cryptography_key(rsa_pub)[3] == -38
    assert cose.PS512.from_cryptography_key(rsa_pub)[3] == -39
    assert cose.RS1.from_cryptography_key(rsa_pub)[3] == -65535

    ed448_pub = ed448.Ed448PrivateKey.generate().public_key()
    assert cose.Ed448.from_cryptography_key(ed448_pub)[3] == -53
    ed25519_pub = ed25519.Ed25519PrivateKey.generate().public_key()
    assert cose.EdDSA.from_cryptography_key(ed25519_pub)[3] == -8


def test_require_oqs_message_when_missing(monkeypatch):
    monkeypatch.setattr(cose, "oqs", None, raising=False)
    monkeypatch.setattr(cose, "_oqs_import_error", RuntimeError("missing oqs"), raising=False)

    with pytest.raises(RuntimeError, match="ML-DSA verification requires"):
        cose._require_oqs()
