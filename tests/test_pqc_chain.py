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

import examples.server.server.x509_chain  # noqa: F401  # ensure custom verifier registration
from fido2.attestation import base as attestation_base
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


def test_default_chain_verifier_preserves_mldsa_oid(monkeypatch):
    ml_dsa_oid = "2.16.840.1.101.3.4.3.17"

    # Ensure the default verifier is exercised rather than the server override.
    monkeypatch.setattr(attestation_base, "_custom_x509_chain_verifier", None)

    child_der = b"child-cert"
    issuer_der = b"issuer-cert"
    ordered_chain = [child_der, issuer_der]

    monkeypatch.setattr(
        attestation_base,
        "_order_certificate_chain",
        lambda chain: ordered_chain,
    )

    child_parsed = SimpleNamespace(
        signature_algorithm_oid=ml_dsa_oid,
        subject_public_key_algorithm_oid=ml_dsa_oid,
        tbs_certificate=b"child-tbs",
        signature_value=b"child-signature",
    )
    issuer_parsed = SimpleNamespace(
        subject_public_key_algorithm_oid=ml_dsa_oid,
        subject_public_key=b"issuer-public-key",
    )

    def fake_get_parsed_certificate(der: bytes) -> SimpleNamespace:
        if der is child_der:
            return child_parsed
        if der is issuer_der:
            return issuer_parsed
        raise AssertionError("Unexpected certificate bytes encountered")

    monkeypatch.setattr(
        attestation_base,
        "_get_parsed_certificate",
        fake_get_parsed_certificate,
    )

    recorded_call: dict[str, bytes] = {}

    def fake_verify_mldsa_certificate_signature(tbs, signature, public_key, oid) -> None:
        recorded_call.update(
            {
                "tbs": tbs,
                "signature": signature,
                "public_key": public_key,
                "oid": oid,
            }
        )

    monkeypatch.setattr(
        attestation_base,
        "_verify_mldsa_certificate_signature",
        fake_verify_mldsa_certificate_signature,
    )

    attestation_base.verify_x509_chain([child_der, issuer_der])

    assert recorded_call["oid"] == ml_dsa_oid
    assert recorded_call["tbs"] == child_parsed.tbs_certificate
    assert recorded_call["signature"] == child_parsed.signature_value
    assert recorded_call["public_key"] == issuer_parsed.subject_public_key
