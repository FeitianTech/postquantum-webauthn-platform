from __future__ import annotations

import base64
import json
import pathlib
import sys
from types import SimpleNamespace

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from fido2.attestation.base import verify_x509_chain
from fido2.cose import extract_certificate_public_key_info


class DummySignature:
    def __init__(self, parameter_set: str) -> None:
        self.parameter_set = parameter_set
        self._calls: dict[str, bytes] = {}

    def __enter__(self) -> "DummySignature":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # pragma: no cover - no cleanup needed
        return False

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        self._calls = {
            "message": bytes(message),
            "signature": bytes(signature),
            "public_key": bytes(public_key),
        }
        return True


def test_verify_x509_chain_uses_ml_dsa(monkeypatch):
    metadata_path = "examples/server/server/static/feitian-pqc.json"
    with open(metadata_path, "r", encoding="utf-8") as fh:
        metadata = json.load(fh)

    root_der = base64.b64decode(metadata["attestationRootCertificates"][0])
    root_cert = x509.load_der_x509_certificate(root_der, default_backend())
    public_key_info = extract_certificate_public_key_info(root_der)

    signature_recorder: dict[str, bytes] = {}

    class RecorderSignature(DummySignature):
        def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
            signature_recorder.update(
                {
                    "parameter_set": self.parameter_set,
                    "message": bytes(message),
                    "signature": bytes(signature),
                    "public_key": bytes(public_key),
                }
            )
            return True

    monkeypatch.setitem(
        sys.modules,
        "oqs",
        SimpleNamespace(Signature=RecorderSignature),
    )

    verify_x509_chain([root_der, root_der])

    assert signature_recorder["parameter_set"] == "ML-DSA-44"
    assert signature_recorder["message"] == root_cert.tbs_certificate_bytes
    assert signature_recorder["signature"] == root_cert.signature
    assert signature_recorder["public_key"] == public_key_info["subject_public_key"]


def test_verify_x509_chain_prefers_mldsa_by_oid(monkeypatch):
    metadata_path = "examples/server/server/static/feitian-pqc.json"
    with open(metadata_path, "r", encoding="utf-8") as fh:
        metadata = json.load(fh)

    root_der = base64.b64decode(metadata["attestationRootCertificates"][0])
    original_loader = x509.load_der_x509_certificate
    original_cert = original_loader(root_der, default_backend())

    class FakeCertificate:
        def __init__(self, cert, fake_public_key):
            self._cert = cert
            self._fake_public_key = fake_public_key

        def __getattr__(self, item):
            return getattr(self._cert, item)

        def public_key(self):
            return self._fake_public_key

    fake_rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

    def fake_loader(der, backend):
        cert = original_loader(der, backend)
        return FakeCertificate(cert, fake_rsa_key)

    monkeypatch.setattr(x509, "load_der_x509_certificate", fake_loader)

    captured = {}

    def fake_verify(child_cert, issuer_der):
        captured["child"] = child_cert
        captured["issuer_der"] = issuer_der

    monkeypatch.setattr(
        "fido2.attestation.base._verify_mldsa_certificate_signature",
        fake_verify,
    )

    verify_x509_chain([root_der, root_der])

    assert captured["child"].signature == original_cert.signature
    assert captured["issuer_der"] == root_der
