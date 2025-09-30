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


def test_verify_x509_chain_prefers_mldsa_oid(monkeypatch):
    child_der = b"child-der"
    issuer_der = b"issuer-der"

    class FakeSignatureAlgorithm:
        dotted_string = "2.16.840.1.101.3.4.3.17"
        _name = "ML-DSA"

    child_cert = SimpleNamespace(
        signature_algorithm_oid=FakeSignatureAlgorithm,
        signature=b"sig",
        tbs_certificate_bytes=b"tbs",
        signature_hash_algorithm=None,
    )

    class FakeIssuerCert:
        @staticmethod
        def public_key():  # pragma: no cover - executed if ML-DSA detection regresses
            raise AssertionError("public_key() should not be invoked for ML-DSA certificates")

    certs = [child_cert, FakeIssuerCert()]

    def fake_load_certificate(der, backend):
        assert der in (child_der, issuer_der)
        return certs.pop(0)

    monkeypatch.setattr(x509, "load_der_x509_certificate", fake_load_certificate)

    captured: dict[str, tuple[object, bytes]] = {}

    def fake_verify(child, issuer_bytes):
        captured["call"] = (child, issuer_bytes)

    monkeypatch.setattr(
        "fido2.attestation.base._verify_mldsa_certificate_signature",
        fake_verify,
    )

    verify_x509_chain([child_der, issuer_der])

    assert captured["call"] == (child_cert, issuer_der)
