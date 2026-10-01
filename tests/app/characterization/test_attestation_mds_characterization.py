"""``perform_attestation_checks`` with a real MDS verifier reports what it reported before.

The other attestation records run with no verifier. Here the checks meet an
``MdsAttestationVerifier`` over metadata built from the fixture's uploaded
entry: an entry for the authenticator's AAGUID whose root signed its
attestation certificate, one whose root has that root's name but another key,
and one found by the attestation certificate's key identifier alone. Every result must
equal ``golden/attestation-checks-mds.json``.
"""
from __future__ import annotations

import base64
import copy
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from fido2 import cbor
from fido2.mds3 import MdsAttestationVerifier, MetadataBlobPayload

from server.app.mds import verifier as mds_verifier
from server.app.webauthn.attestation import checks as attestation_checks

from ..metadata import mds_fixture
from ..security.ceremony_helpers import ORIGIN, RP_ID, b64u
from . import harness, material

CHALLENGE = b"\x5b" * 32
STATE = {"challenge": b64u(CHALLENGE), "user_verification": "preferred"}
AAGUID = bytes.fromhex("c0ffee00c0ffee00c0ffee00c0ffee00")
MLDSA_AAGUID = bytes.fromhex("c0ffee44c0ffee44c0ffee44c0ffee44")
WRONG_ROOT_AAGUID = bytes.fromhex("c0ffee99c0ffee99c0ffee99c0ffee99")
ROOT_NAME = material._name("Characterization MDS Root", packed=False)


def _root(label: str) -> bytes:
    """A self-signed P-256 root named ``ROOT_NAME``, with ``label``'s key."""

    key = material.ec_key(label)
    builder = (
        x509.CertificateBuilder()
        .subject_name(ROOT_NAME)
        .issuer_name(ROOT_NAME)
        .public_key(key.public_key())
        .serial_number(0xCA)
        .not_valid_before(material.NOT_BEFORE)
        .not_valid_after(material.NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    signed = builder.sign(key, hashes.SHA256(), ecdsa_deterministic=True)
    return signed.public_bytes(serialization.Encoding.DER)


def _leaf(aaguid: bytes) -> bytes:
    """``material``'s attestation certificate, issued by the ``mds-root`` root instead."""

    return material.certificate(
        material.ec_key("attestation-leaf").public_key(),
        common_name="Characterization Attestation Leaf",
        serial=0x1EAF,
        extensions=[
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (x509.UnrecognizedExtension(material.OID_AAGUID, material._octet_string(aaguid)), False),
        ],
        signing_key=material.ec_key("mds-root"),
        issuer=ROOT_NAME,
        algorithm=hashes.SHA256(),
        ecdsa_deterministic=True,
    )


def _issued_by_root(payload: dict, aaguid: bytes) -> dict:
    """``payload`` with its packed statement's certificate replaced by ``_leaf``; same key, same signature."""

    attestation_object = cbor.decode(base64.urlsafe_b64decode(payload["response"]["attestationObject"] + "=="))
    attestation_object["attStmt"]["x5c"] = [_leaf(aaguid)]
    payload["response"]["attestationObject"] = b64u(cbor.encode(attestation_object))
    return payload


def _entry(template, *, aaguid: bytes | None, roots: list[bytes], key_ids: list[bytes] = ()):
    entry = copy.deepcopy(template)
    statement = entry["metadataStatement"]
    statement["attestationRootCertificates"] = [base64.b64encode(root).decode() for root in roots]
    statement["description"] = f"Characterization {aaguid.hex() if aaguid else 'key identifier'}"
    if aaguid is None:
        entry.pop("aaguid")
        statement.pop("aaguid")
        statement["authenticatorGetInfo"].pop("aaguid")
        entry["attestationCertificateKeyIdentifiers"] = [key_id.hex() for key_id in key_ids]
        statement["attestationCertificateKeyIdentifiers"] = entry["attestationCertificateKeyIdentifiers"]
    else:
        text = str(__import__("uuid").UUID(bytes=aaguid))
        entry["aaguid"] = statement["aaguid"] = text
        statement["authenticatorGetInfo"]["aaguid"] = aaguid.hex()
    return entry


def _verifier() -> MdsAttestationVerifier:
    uploaded = json.loads(mds_fixture.CUSTOM_METADATA_PATH.read_text(encoding="utf-8"))
    template = uploaded["entries"][0]
    leaf = x509.load_der_x509_certificate(_leaf(b"\x00" * 16))
    leaf_key_id = x509.SubjectKeyIdentifier.from_public_key(leaf.public_key()).digest
    ca_root = _root("mds-root")
    payload = {
        "legalHeader": "Characterization metadata",
        "no": 1,
        "nextUpdate": "2099-12-31",
        "entries": [
            _entry(template, aaguid=AAGUID, roots=[ca_root]),
            _entry(template, aaguid=MLDSA_AAGUID, roots=[ca_root]),
            _entry(template, aaguid=WRONG_ROOT_AAGUID, roots=[_root("another-authority")]),
            _entry(template, aaguid=None, roots=[ca_root], key_ids=[leaf_key_id]),
        ],
    }
    return MdsAttestationVerifier(MetadataBlobPayload.from_dict(payload))


def _cases():
    listed = material.Authenticator("mds-listed", aaguid=AAGUID)
    wrong_root = material.Authenticator("mds-wrong-root", aaguid=WRONG_ROOT_AAGUID)
    unlisted = material.Authenticator("mds-unlisted", aaguid=b"\x13" * 16)
    no_aaguid = material.Authenticator("mds-no-aaguid")
    mldsa = material.Authenticator("mds-mldsa44", key_type="ML-DSA-44", aaguid=MLDSA_AAGUID)
    build = lambda authenticator, **kwargs: material.registration_payload(  # noqa: E731
        authenticator, challenge=CHALLENGE, **kwargs
    )
    return {
        "none-listed": build(listed),
        "self-listed": build(listed, attestation="self"),
        "x5c-listed": _issued_by_root(build(listed, attestation="x5c"), AAGUID),
        "x5c-listed-tampered": _issued_by_root(build(listed, attestation="x5c", tamper=True), AAGUID),
        "x5c-listed-ed25519-ca": build(listed, attestation="x5c"),
        "x5c-wrong-root": _issued_by_root(build(wrong_root, attestation="x5c"), WRONG_ROOT_AAGUID),
        "x5c-unlisted": _issued_by_root(build(unlisted, attestation="x5c"), b"\x13" * 16),
        "x5c-by-key-identifier": _issued_by_root(build(no_aaguid, attestation="x5c"), b"\x00" * 16),
        "self-by-key-identifier": build(no_aaguid, attestation="self"),
        "mldsa-self-listed": build(mldsa, attestation="self"),
    }


@pytest.fixture
def mds(monkeypatch):
    verifier = _verifier()
    monkeypatch.setattr(mds_verifier, "get_mds_verifier", lambda: verifier)
    return verifier


def test_attestation_checks_with_mds_match_their_golden_record(app, mds):
    with app.app_context():
        record = {
            name: harness.json_safe(attestation_checks.perform_attestation_checks(response, STATE, None, None, ORIGIN, RP_ID))
            for name, response in _cases().items()
        }
    harness.check_golden("attestation-checks-mds.json", record)
