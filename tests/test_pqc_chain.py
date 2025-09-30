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

from fido2.attestation.base import (
    Attestation,
    AttestationResult,
    AttestationType,
    AttestationVerifier,
    verify_x509_chain,
)
from fido2.mds3 import parse_blob
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


def test_attestation_verifier_skips_chain_for_pqc(monkeypatch, caplog):
    metadata_path = "examples/server/server/static/feitian-pqc.json"
    with open(metadata_path, "r", encoding="utf-8") as fh:
        metadata = json.load(fh)

    root_der = base64.b64decode(metadata["attestationRootCertificates"][0])
    root_cert = x509.load_der_x509_certificate(root_der, default_backend())

    recorded: dict[str, object] = {}

    def record_signature(child, issuer):
        recorded.update({"child": child, "issuer": issuer})

    def fail_chain(_chain):  # pragma: no cover - guard assertion for this test
        raise AssertionError("verify_x509_chain should not be called for PQC attestation")

    monkeypatch.setattr(
        "fido2.attestation.base._verify_mldsa_certificate_signature",
        record_signature,
    )
    monkeypatch.setattr("fido2.attestation.base.verify_x509_chain", fail_chain)

    class DummyAttestation(Attestation):
        FORMAT = "dummy"

        def verify(self, statement, auth_data, client_data_hash):
            return AttestationResult(AttestationType.BASIC, [root_der])

    class DummyVerifier(AttestationVerifier):
        def __init__(self, ca_bytes):
            super().__init__([DummyAttestation()])
            self._ca_bytes = ca_bytes

        def ca_lookup(self, attestation_result, auth_data):
            return self._ca_bytes

    attestation_object = SimpleNamespace(
        fmt="dummy",
        att_stmt={"x5c": [root_der]},
        auth_data=SimpleNamespace(credential_data=SimpleNamespace()),
    )

    caplog.set_level("INFO")

    DummyVerifier(root_der).verify_attestation(attestation_object, b"")

    assert recorded["issuer"] == root_der
    assert isinstance(recorded["child"], x509.Certificate)
    assert recorded["child"].tbs_certificate_bytes == root_cert.tbs_certificate_bytes
    assert (
        "Using PQC direct verification, bypassing x5c chain to avoid RSA overwrite"
        in caplog.text
    )


def test_attestation_verifier_detects_pqc_by_aaguid(monkeypatch, caplog):
    metadata_path = "examples/server/server/static/feitian-pqc.json"
    with open(metadata_path, "r", encoding="utf-8") as fh:
        metadata = json.load(fh)

    root_der = base64.b64decode(metadata["attestationRootCertificates"][0])
    root_cert = x509.load_der_x509_certificate(root_der, default_backend())
    aaguid_hex = metadata["aaguid"].replace("-", "")
    aaguid_bytes = bytes.fromhex(aaguid_hex)

    recorded: dict[str, object] = {}

    def record_signature(child, issuer):
        recorded.update({"child": child, "issuer": issuer})

    def fail_chain(_chain):  # pragma: no cover - guard assertion for this test
        raise AssertionError("verify_x509_chain should not be called for PQC attestation")

    monkeypatch.setattr(
        "fido2.attestation.base._verify_mldsa_certificate_signature",
        record_signature,
    )
    monkeypatch.setattr("fido2.attestation.base.verify_x509_chain", fail_chain)
    monkeypatch.setattr("fido2.attestation.base.describe_mldsa_oid", lambda _: {})

    class DummyAttestation(Attestation):
        FORMAT = "dummy"

        def verify(self, statement, auth_data, client_data_hash):
            return AttestationResult(AttestationType.BASIC, [root_der])

    class DummyVerifier(AttestationVerifier):
        def __init__(self, ca_bytes):
            super().__init__([DummyAttestation()])
            self._ca_bytes = ca_bytes

        def ca_lookup(self, attestation_result, auth_data):
            return self._ca_bytes

    attestation_object = SimpleNamespace(
        fmt="dummy",
        att_stmt={"x5c": [root_der]},
        auth_data=SimpleNamespace(
            credential_data=SimpleNamespace(aaguid=aaguid_bytes)
        ),
    )

    caplog.set_level("INFO")

    DummyVerifier(root_der).verify_attestation(attestation_object, b"")

    assert recorded["issuer"] == root_der
    assert isinstance(recorded["child"], x509.Certificate)
    assert recorded["child"].tbs_certificate_bytes == root_cert.tbs_certificate_bytes
    assert (
        "Using PQC direct verification, bypassing x5c chain to avoid RSA overwrite"
        in caplog.text
    )


def test_parse_blob_uses_direct_pqc_verification(monkeypatch):
    metadata_path = "examples/server/server/static/feitian-pqc.json"
    with open(metadata_path, "r", encoding="utf-8") as fh:
        metadata = json.load(fh)

    root_der = base64.b64decode(metadata["attestationRootCertificates"][0])

    recorded: dict[str, object] = {}

    def record_certificate(child, issuer):
        recorded["child"] = child
        recorded["issuer"] = issuer

    def fail_chain(_chain):  # pragma: no cover - guard assertion for this test
        raise AssertionError("verify_x509_chain should not be called for PQC metadata")

    monkeypatch.setattr(
        "fido2.mds3._verify_mldsa_certificate_signature",
        record_certificate,
    )
    monkeypatch.setattr("fido2.mds3.verify_x509_chain", fail_chain)

    class DummyKey:
        ALGORITHM = -48

        def __init__(self, params):
            self.params = params

        @classmethod
        def from_cryptography_key(cls, _):  # pragma: no cover - should not be used
            raise AssertionError("cryptography key path must not be used for PQC")

        def verify(self, message: bytes, signature: bytes) -> None:
            recorded["message"] = bytes(message)
            recorded["signature"] = bytes(signature)
            recorded["public_key"] = self.params.get(-1)

    monkeypatch.setattr("fido2.mds3.CoseKey.for_name", lambda _: DummyKey)

    header = {
        "alg": "MLDSA44",
        "x5c": [base64.b64encode(root_der).decode("ascii")],
    }
    payload = {
        "legalHeader": "",
        "no": 0,
        "nextUpdate": "2024-01-01",
        "entries": [],
    }

    def _urlsafe(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    header_segment = _urlsafe(json.dumps(header).encode("utf-8"))
    payload_segment = _urlsafe(json.dumps(payload).encode("utf-8"))
    signature_segment = _urlsafe(b"")
    blob = b".".join([header_segment, payload_segment, signature_segment])

    parse_blob(blob, root_der)

    assert recorded["issuer"] == root_der
    assert isinstance(recorded["child"], x509.Certificate)
    assert recorded["public_key"]
    assert recorded["message"] == blob.rsplit(b".", 1)[0]
    assert recorded["signature"] == b""
