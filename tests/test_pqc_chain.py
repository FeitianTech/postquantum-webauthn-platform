from __future__ import annotations

import base64
import json
import pathlib
import sys
from typing import Optional
from datetime import date
from types import SimpleNamespace

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from fido2.attestation import (
    AttestationResult,
    AttestationType,
    AttestationVerifier,
    InvalidSignature,
    verify_x509_chain,
    verify_mldsa_x509_chain,
)
from fido2.cose import extract_certificate_public_key_info
from fido2.mds3 import MetadataBlobPayload, MetadataBlobPayloadEntry, MdsAttestationVerifier
from fido2.webauthn import Aaguid


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


def test_verify_x509_chain_prefers_der_signature_oid(monkeypatch):
    metadata_path = "examples/server/server/static/feitian-pqc.json"
    with open(metadata_path, "r", encoding="utf-8") as fh:
        metadata = json.load(fh)

    root_der = base64.b64decode(metadata["attestationRootCertificates"][0])
    real_cert = x509.load_der_x509_certificate(root_der, default_backend())

    class FakeSignatureOid:
        dotted_string = "1.2.840.113549.1.1.11"
        _name = "sha256WithRSAEncryption"

    class PretendRsaCert:
        def __init__(self, delegate):
            self.signature = delegate.signature
            self.tbs_certificate_bytes = delegate.tbs_certificate_bytes
            self.signature_algorithm_oid = FakeSignatureOid
            self.signature_hash_algorithm = None

        def public_key(self):  # pragma: no cover - ML-DSA branch should bypass
            raise AssertionError("public_key() should not be called for ML-DSA certificates")

    certs = [PretendRsaCert(real_cert), PretendRsaCert(real_cert)]

    def fake_load_certificate(der, backend):
        assert der == root_der
        return certs.pop(0)

    monkeypatch.setattr(x509, "load_der_x509_certificate", fake_load_certificate)

    captured: dict[str, Optional[str]] = {}

    def fake_verify(child, issuer_bytes, *, signature_oid_override=None):
        captured["override"] = signature_oid_override

    monkeypatch.setattr(
        "fido2.attestation.base._verify_mldsa_certificate_signature",
        fake_verify,
    )

    verify_x509_chain([root_der, root_der])

    assert captured["override"] == "2.16.840.1.101.3.4.3.17"


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

    captured: dict[str, tuple[object, bytes, Optional[str]]] = {}

    def fake_verify(child, issuer_bytes, *, signature_oid_override=None):
        captured["call"] = (child, issuer_bytes, signature_oid_override)

    monkeypatch.setattr(
        "fido2.attestation.base._verify_mldsa_certificate_signature",
        fake_verify,
    )

    verify_x509_chain([child_der, issuer_der])

    assert captured["call"][0:2] == (child_cert, issuer_der)


def test_attestation_verifier_selects_mldsa_chain(monkeypatch):
    class DummyVerifier(AttestationVerifier):
        def ca_lookup(self, attestation_result, auth_data):  # pragma: no cover - unused
            raise NotImplementedError

    leaf_der = b"leaf"
    issuer_der = b"issuer"

    class DummyOid:
        def __init__(self, dotted: str):
            self.dotted_string = dotted

    class DummyCert:
        def __init__(self, oid: str):
            self.signature_algorithm_oid = DummyOid(oid)

    cert_map = {
        leaf_der: DummyCert("2.16.840.1.101.3.4.3.17"),
        issuer_der: DummyCert("1.2.840.113549.1.1.11"),
    }

    def fake_load_certificate(der_bytes, backend):
        return cert_map[der_bytes]

    monkeypatch.setattr(x509, "load_der_x509_certificate", fake_load_certificate)

    attestation_result = AttestationResult(AttestationType.BASIC, [leaf_der, issuer_der])
    auth_data = SimpleNamespace(credential_data=None)

    verifier = DummyVerifier(attestation_types=[])

    selected = verifier._select_chain_verifier(attestation_result, auth_data)

    assert selected is verify_mldsa_x509_chain


def test_attestation_verifier_defaults_without_mldsa(monkeypatch):
    class DummyVerifier(AttestationVerifier):
        def ca_lookup(self, attestation_result, auth_data):  # pragma: no cover - unused
            raise NotImplementedError

    leaf_der = b"leaf"

    class DummyOid:
        def __init__(self, dotted: str):
            self.dotted_string = dotted

    class DummyCert:
        def __init__(self, oid: str):
            self.signature_algorithm_oid = DummyOid(oid)

    cert_map = {leaf_der: DummyCert("1.2.840.113549.1.1.11")}

    def fake_load_certificate(der_bytes, backend):
        return cert_map[der_bytes]

    monkeypatch.setattr(x509, "load_der_x509_certificate", fake_load_certificate)

    attestation_result = AttestationResult(AttestationType.BASIC, [leaf_der])
    auth_data = SimpleNamespace(credential_data=None)

    verifier = DummyVerifier(attestation_types=[])

    selected = verifier._select_chain_verifier(attestation_result, auth_data)

    assert selected is verify_x509_chain


def test_verify_mldsa_chain_invokes_override(monkeypatch):
    child_der = b"child-der"
    issuer_der = b"issuer-der"

    class FakeSignatureAlgorithm:
        dotted_string = "2.16.840.1.101.3.4.3.17"
        _name = "ML-DSA"

    child_cert = SimpleNamespace(
        signature_algorithm_oid=FakeSignatureAlgorithm,
        signature=b"sig",
        tbs_certificate_bytes=b"tbs",
    )

    issuer_cert = SimpleNamespace(signature_algorithm_oid=FakeSignatureAlgorithm)

    certs = [child_cert, issuer_cert]

    def fake_load_certificate(der, backend):
        assert der in (child_der, issuer_der)
        return certs.pop(0)

    monkeypatch.setattr(x509, "load_der_x509_certificate", fake_load_certificate)

    captured: dict[str, tuple[object, bytes, Optional[str]]] = {}

    def fake_verify(child, issuer_bytes, *, signature_oid_override=None):
        captured["call"] = (child, issuer_bytes, signature_oid_override)

    monkeypatch.setattr(
        "fido2.attestation.base._verify_mldsa_certificate_signature",
        fake_verify,
    )

    verify_mldsa_x509_chain([child_der, issuer_der])

    assert captured["call"] == (
        child_cert,
        issuer_der,
        "2.16.840.1.101.3.4.3.17",
    )


def test_verify_mldsa_chain_requires_mldsa_signature(monkeypatch):
    child_der = b"child-der"
    issuer_der = b"issuer-der"

    class FakeSignatureAlgorithm:
        dotted_string = "1.2.840.113549.1.1.11"
        _name = "sha256WithRSAEncryption"

    child_cert = SimpleNamespace(
        signature_algorithm_oid=FakeSignatureAlgorithm,
        signature=b"sig",
        tbs_certificate_bytes=b"tbs",
    )

    issuer_cert = SimpleNamespace(signature_algorithm_oid=FakeSignatureAlgorithm)

    certs = [child_cert, issuer_cert]

    def fake_load_certificate(der, backend):
        assert der in (child_der, issuer_der)
        return certs.pop(0)

    monkeypatch.setattr(x509, "load_der_x509_certificate", fake_load_certificate)

    with pytest.raises(InvalidSignature):
        verify_mldsa_x509_chain([child_der, issuer_der])


def test_mds_verifier_selects_testing_chain_for_feitian():
    metadata_path = pathlib.Path(
        "examples/server/server/static/feitian-pqc.json"
    )
    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    feitian_roots = [
        base64.b64decode(cert) for cert in data["attestationRootCertificates"]
    ]

    entry = _build_metadata_entry(
        data,
        roots=feitian_roots,
        description=data["description"],
    )

    payload = MetadataBlobPayload(
        legal_header="",
        no=0,
        next_update=date(2024, 1, 1),
        entries=(entry,),
    )

    verifier = MdsAttestationVerifier(payload)

    attestation_result = AttestationResult(
        AttestationType.BASIC,
        [b"leaf"],
    )
    auth_data = SimpleNamespace(
        credential_data=SimpleNamespace(
            aaguid=Aaguid.parse("73b2b592-8829-4fb7-a199-cfb5e1e271b7")
        )
    )

    selected = verifier._select_chain_verifier(attestation_result, auth_data)

    assert selected is verify_mldsa_x509_chain


def test_mds_verifier_uses_default_chain_for_other_aaguid():
    metadata_path = pathlib.Path(
        "examples/server/server/static/feitian-pqc.json"
    )
    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    feitian_roots = [
        base64.b64decode(cert) for cert in data["attestationRootCertificates"]
    ]

    entry = _build_metadata_entry(
        data,
        roots=feitian_roots,
        description=data["description"],
    )

    payload = MetadataBlobPayload(
        legal_header="",
        no=0,
        next_update=date(2024, 1, 1),
        entries=(entry,),
    )

    verifier = MdsAttestationVerifier(payload)

    attestation_result = AttestationResult(
        AttestationType.BASIC,
        [b"leaf"],
    )
    auth_data = SimpleNamespace(
        credential_data=SimpleNamespace(
            aaguid=Aaguid.parse("00000000-0000-0000-0000-000000000000")
        )
    )

    selected = verifier._select_chain_verifier(attestation_result, auth_data)

    assert selected is verify_x509_chain


def _build_metadata_entry(source: dict, *, roots: list[bytes], description: str) -> MetadataBlobPayloadEntry:
    return MetadataBlobPayloadEntry.from_dict(
        {
            "statusReports": [
                {
                    "status": "FIDO_CERTIFIED",
                }
            ],
            "timeOfLastStatusChange": "2024-01-01",
            "aaguid": source["aaguid"],
            "metadataStatement": {
                "description": description,
                "authenticatorVersion": source["authenticatorVersion"],
                "schema": source["schema"],
                "upv": source["upv"],
                "attestationTypes": source["attestationTypes"],
                "authenticationAlgorithms": source["authenticationAlgorithms"],
                "publicKeyAlgAndEncodings": source["publicKeyAlgAndEncodings"],
                "userVerificationDetails": source["userVerificationDetails"],
                "keyProtection": source["keyProtection"],
                "matcherProtection": source["matcherProtection"],
                "cryptoStrength": source["cryptoStrength"],
                "attachmentHint": source["attachmentHint"],
                "tcDisplay": source["tcDisplay"],
                "attestationRootCertificates": [
                    base64.b64encode(root).decode("ascii") for root in roots
                ],
            },
        }
    )


def test_mds_verifier_prefers_feitian_entry_for_aaguid():
    metadata_path = pathlib.Path(
        "examples/server/server/static/feitian-pqc.json"
    )
    data = json.loads(metadata_path.read_text(encoding="utf-8"))
    feitian_roots = [
        base64.b64decode(cert) for cert in data["attestationRootCertificates"]
    ]
    feitian_entry = _build_metadata_entry(
        data,
        roots=feitian_roots,
        description=data["description"],
    )

    rsa_root = b"rsa-root-placeholder"
    rsa_entry = _build_metadata_entry(
        data,
        roots=[rsa_root],
        description="RSA override",
    )

    payload = MetadataBlobPayload(
        legal_header="",
        no=0,
        next_update=date(2024, 1, 1),
        entries=(feitian_entry, rsa_entry),
    )

    verifier = MdsAttestationVerifier(payload)

    matched = verifier.find_entry_by_aaguid(feitian_entry.aaguid)
    assert matched is feitian_entry


def test_mds_ca_lookup_prefers_mldsa_root(monkeypatch):
    metadata_path = pathlib.Path(
        "examples/server/server/static/feitian-pqc.json"
    )
    data = json.loads(metadata_path.read_text(encoding="utf-8"))

    feitian_roots = [
        base64.b64decode(cert) for cert in data["attestationRootCertificates"]
    ]
    rsa_root = b"rsa-root-placeholder"

    entry = _build_metadata_entry(
        data,
        roots=[rsa_root] + feitian_roots,
        description=data["description"],
    )

    payload = MetadataBlobPayload(
        legal_header="",
        no=0,
        next_update=date(2024, 1, 1),
        entries=(entry,),
    )

    verifier = MdsAttestationVerifier(payload)

    leaf_der = b"leaf-cert"
    issuer_der = b"issuer-cert"

    class DummyOid:
        def __init__(self, dotted: str):
            self.dotted_string = dotted

    class DummyCert:
        def __init__(self, *, subject: str, issuer: str, oid: str):
            self.subject = subject
            self.issuer = issuer
            self.signature_algorithm_oid = DummyOid(oid)

        def public_key(self):  # pragma: no cover - not exercised here
            raise NotImplementedError

    root_subject = "root-subject"
    cert_map = {
        leaf_der: DummyCert(
            subject="leaf-subject",
            issuer=root_subject,
            oid="2.16.840.1.101.3.4.3.17",
        ),
        issuer_der: DummyCert(
            subject=root_subject,
            issuer=root_subject,
            oid="2.16.840.1.101.3.4.3.17",
        ),
        rsa_root: DummyCert(
            subject=root_subject,
            issuer=root_subject,
            oid="1.2.840.113549.1.1.11",
        ),
    }

    for feitian_root in feitian_roots:
        cert_map[feitian_root] = DummyCert(
            subject=root_subject,
            issuer=root_subject,
            oid="2.16.840.1.101.3.4.3.17",
        )

    def fake_load_certificate(der_bytes, backend):
        return cert_map[der_bytes]

    monkeypatch.setattr(x509, "load_der_x509_certificate", fake_load_certificate)

    attestation_result = SimpleNamespace(trust_path=[leaf_der, issuer_der])
    auth_data = SimpleNamespace(
        credential_data=SimpleNamespace(aaguid=entry.aaguid)
    )

    selected_root = verifier.ca_lookup(attestation_result, auth_data)

    assert selected_root in feitian_roots
