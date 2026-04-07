from types import SimpleNamespace

import pytest


def test_android_and_apple_attestation_reject_invalid_mobile_attestation_inputs(monkeypatch):
    android_module = pytest.importorskip("fido2.attestation.android")
    apple_module = pytest.importorskip("fido2.attestation.apple")
    base_module = pytest.importorskip("fido2.attestation.base")

    statement = {"response": b"header.payload.signature"}

    def _decode_cts_false(value):
        mapping = {
            b"header": b'{"x5c":["cert-der"],"alg":"ES256"}',
            b"payload": b'{"ctsProfileMatch":false,"nonce":"nonce-token"}',
            b"signature": b"signature-bytes",
        }
        return mapping[value]

    monkeypatch.setattr(android_module, "websafe_decode", _decode_cts_false, raising=False)
    with pytest.raises(base_module.InvalidData, match="ctsProfileMatch must be true"):
        android_module.AndroidSafetynetAttestation().verify(statement, b"auth", b"client")

    def _decode_nonce_mismatch(value):
        mapping = {
            b"header": b'{"x5c":["cert-der"],"alg":"ES256"}',
            b"payload": b'{"ctsProfileMatch":true,"nonce":"nonce-token"}',
            b"signature": b"signature-bytes",
            "nonce-token": b"unexpected-nonce",
        }
        return mapping[value]

    monkeypatch.setattr(android_module, "websafe_decode", _decode_nonce_mismatch, raising=False)
    monkeypatch.setattr(android_module, "sha256", lambda _data: b"expected-nonce", raising=False)
    with pytest.raises(base_module.InvalidData, match="Nonce does not match"):
        android_module.AndroidSafetynetAttestation().verify(statement, b"auth", b"client")

    def _decode_bad_cn(value):
        mapping = {
            b"header": b'{"x5c":["cert-der"],"alg":"ES256"}',
            b"payload": b'{"ctsProfileMatch":true,"nonce":"nonce-token"}',
            b"signature": b"signature-bytes",
            "nonce-token": b"expected-nonce",
            "cert-der": b"fake-der",
        }
        return mapping[value]

    fake_subject = SimpleNamespace(
        get_attributes_for_oid=lambda _oid: [SimpleNamespace(value="example.invalid")]
    )
    fake_cert = SimpleNamespace(subject=fake_subject)
    monkeypatch.setattr(android_module, "websafe_decode", _decode_bad_cn, raising=False)
    monkeypatch.setattr(android_module, "sha256", lambda _data: b"expected-nonce", raising=False)
    monkeypatch.setattr(
        android_module.x509,
        "load_der_x509_certificate",
        lambda *_args, **_kwargs: fake_cert,
        raising=False,
    )
    with pytest.raises(
        base_module.InvalidData,
        match=r"Certificate not issued to attest\.android\.com",
    ):
        android_module.AndroidSafetynetAttestation().verify(statement, b"auth", b"client")

    fake_extension = SimpleNamespace(value=SimpleNamespace(value=b"ABCDEF" + b"other-nonce"))
    fake_extensions = SimpleNamespace(get_extension_for_oid=lambda _oid: fake_extension)
    fake_apple_cert = SimpleNamespace(extensions=fake_extensions)
    monkeypatch.setattr(apple_module, "sha256", lambda _data: b"expected-nonce", raising=False)
    monkeypatch.setattr(
        apple_module.x509,
        "load_der_x509_certificate",
        lambda *_args, **_kwargs: fake_apple_cert,
        raising=False,
    )
    with pytest.raises(base_module.InvalidData, match="Nonce does not match"):
        apple_module.AppleAttestation().verify({"x5c": [b"fake-cert"]}, b"auth", b"client")