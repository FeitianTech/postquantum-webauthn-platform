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
import fido2.attestation.base as attestation_base
from fido2.attestation.base import (
    Attestation,
    AttestationResult,
    AttestationType,
    AttestationVerifier,
    verify_x509_chain,
)
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


def test_attestation_verifier_bypasses_x509_chain_for_mldsa(monkeypatch):
    metadata_path = "examples/server/server/static/feitian-pqc.json"
    with open(metadata_path, "r", encoding="utf-8") as fh:
        metadata = json.load(fh)

    root_der = base64.b64decode(metadata["attestationRootCertificates"][0])
    result = AttestationResult(AttestationType.BASIC, [root_der])

    recorded: dict[str, tuple[bytes, bytes, bytes, str]] = {}

    def fake_mldsa_verify(
        tbs_certificate: bytes,
        signature: bytes,
        issuer_public_key: bytes,
        signature_oid: str,
    ) -> None:
        recorded["call"] = (
            bytes(tbs_certificate),
            bytes(signature),
            bytes(issuer_public_key),
            signature_oid,
        )

    def fail_verify_x509_chain(chain):  # pragma: no cover - diagnostic safeguard
        raise AssertionError("verify_x509_chain should not run for ML-DSA chains")

    monkeypatch.setattr(
        attestation_base,
        "_verify_mldsa_certificate_signature",
        fake_mldsa_verify,
    )
    monkeypatch.setattr(attestation_base, "verify_x509_chain", fail_verify_x509_chain)

    class DummyAttestation(Attestation):
        FORMAT = "dummy"

        def verify(self, statement, auth_data, client_data_hash):
            return result

    class DummyVerifier(AttestationVerifier):
        def ca_lookup(self, attestation_result, auth_data):
            return root_der

    attestation_object = SimpleNamespace(
        fmt="dummy",
        att_stmt={},
        auth_data=SimpleNamespace(),
    )

    verifier = DummyVerifier(attestation_types=[DummyAttestation()])
    verifier.verify_attestation(attestation_object, b"\x00" * 32)

    assert "call" in recorded
    _, _, _, signature_oid = recorded["call"]
    assert signature_oid in attestation_base.MLDSA_OIDS
