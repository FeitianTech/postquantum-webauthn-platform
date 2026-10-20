"""An attestation chain forged to an MDS root's name is neither root valid nor verified.

The leaf names a root of its authenticator's metadata entry as its issuer and
carries the entry's AAGUID, but another key signed it: that of a root made for
the forgery with the same name. The attestation signature is the leaf key's own
and verifies. The entry is the packaged snapshot's (``fido_mds`` True), which
once made such a root valid whatever its chain said.

The Advanced tab reports the chain's failure as an error. The Simple tab asks for
no attestation and takes one it cannot trust as it takes a self attestation: it
registers the credential, the failure a warning and the root invalid. (Browsers
drop the attestation a "none" request gets; only a direct call sends one.)
"""
from __future__ import annotations

import base64
import json
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from server.app.mds import files as mds_files
from tests.app.characterization import material
from tests.app.entry_app import entry_app
from tests.app.metadata import mds_fixture

from .ceremony_helpers import (
    ORIGIN,
    Authenticator,
    advanced_public_key_options,
    complete_simple_registration,
    registration_payload,
    unb64u,
)

# A packaged entry of the fixture snapshot, with one root and no getInfo algorithms.
LISTED_AAGUID = uuid.UUID("f1d0f1d0-0000-4000-8000-000000000008")
FORGED_ROOT_CHECKS = {"trusted_ca": True, "chain": False, "fido_mds": True}


def _listed_root_name() -> x509.Name:
    snapshot = json.loads((mds_fixture.SNAPSHOT_DIR / mds_files.VERIFIED).read_text(encoding="utf-8"))
    entry = next(entry for entry in snapshot["entries"] if entry.get("aaguid") == str(LISTED_AAGUID))
    root = base64.b64decode(entry["metadataStatement"]["attestationRootCertificates"][0])
    return x509.load_der_x509_certificate(root).subject


def _forged_root(name: x509.Name, key: ec.EllipticCurvePrivateKey) -> bytes:
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0xF0)
        .not_valid_before(material.NOT_BEFORE)
        .not_valid_after(material.NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


@pytest.fixture(params=["leaf", "leaf-and-forged-root"])
def forged_attestation(request) -> dict:
    """``registration_payload``'s attestation arguments: a packed statement whose x5c is forged."""

    name = _listed_root_name()
    forger = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = material.certificate(
        leaf_key.public_key(),
        common_name="Forged Attestation Leaf",
        serial=0xF1,
        extensions=[
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (x509.UnrecognizedExtension(material.OID_AAGUID, material._octet_string(LISTED_AAGUID.bytes)), False),
        ],
        signing_key=forger,
        issuer=name,
        algorithm=hashes.SHA256(),
    )
    x5c = [leaf] if request.param == "leaf" else [leaf, _forged_root(name, forger)]
    return {"attestation": "packed", "attestation_key": leaf_key, "x5c": x5c}


def test_the_advanced_tab_reports_a_forged_chain_as_unverified(advanced_storage, mds_fixture_snapshot, forged_attestation):
    authenticator = Authenticator(aaguid=LISTED_AAGUID.bytes)
    client = entry_app().test_client()

    begin = client.post("/api/advanced/register/begin", json={"publicKey": advanced_public_key_options(challenge=b"\x54" * 32)})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    complete = client.post(
        "/api/advanced/register/complete",
        json={
            "publicKey": advanced_public_key_options(challenge=challenge),
            "__credential_response": registration_payload(authenticator, challenge=challenge, **forged_attestation),
        },
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
    payload = complete.get_json()
    assert payload["attestationErrors"] == ["certificate_chain_invalid"]
    assert payload["attestationVerified"] is False
    assert payload["attestationSummary"]["signatureValid"] is True
    assert payload["attestationSummary"]["rootValid"] is False
    assert payload["attestationSummary"]["verified"] is False


def test_the_simple_tab_registers_a_forged_chain_with_its_root_invalid(simple_storage, mds_fixture_snapshot, forged_attestation):
    authenticator = Authenticator(aaguid=LISTED_AAGUID.bytes)

    response = complete_simple_registration(entry_app().test_client(), authenticator, **forged_attestation)

    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    checks = body["relyingParty"]["registrationData"]["attestationChecks"]
    assert checks["signature_valid"] is True
    assert checks["root_valid"] is False
    assert checks["root_checks"] == FORGED_ROOT_CHECKS
    assert checks["errors"] == []
    assert checks["warnings"] == ["certificate_chain_invalid"]
    assert body["attestationSummary"]["rootValid"] is False
