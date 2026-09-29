"""``mds_blob``: the MDS BLOB's chain to the pinned root, its signature, and its payload.

The chains are real certificates in the shape the FIDO BLOB has: a signing
certificate, its CA, and a cross-certificate from the pinned root's older
sibling (R3 to R46), which the path to the pinned root does not need.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature as CryptographyInvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from fido2.attestation import InvalidSignature, verify_x509_chain
from fido2.utils import websafe_encode
from server.app import mds_blob

_NOW = datetime.now(timezone.utc)


def _certificate(*, subject: str, issuer: str, public_key, issuer_key) -> bytes:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(_NOW + timedelta(days=30))
    )
    return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _transition():
    """A signing chain whose x5c ends in the R3-to-R46 cross-certificate."""

    legacy, current, intermediate, leaf = _rsa(), _rsa(), _rsa(), ec.generate_private_key(ec.SECP256R1())
    unrelated = _rsa()
    return SimpleNamespace(
        leaf=_certificate(subject="mds.example.org", issuer="Intermediate CA", public_key=leaf.public_key(), issuer_key=intermediate),
        intermediate=_certificate(subject="Intermediate CA", issuer="Root R46", public_key=intermediate.public_key(), issuer_key=current),
        cross=_certificate(subject="Root R46", issuer="Root R3", public_key=current.public_key(), issuer_key=legacy),
        current_root=_certificate(subject="Root R46", issuer="Root R46", public_key=current.public_key(), issuer_key=current),
        legacy_root=_certificate(subject="Root R3", issuer="Root R3", public_key=legacy.public_key(), issuer_key=legacy),
        unrelated=_certificate(subject="Unrelated", issuer="Unrelated", public_key=unrelated.public_key(), issuer_key=unrelated),
        leaf_key=leaf,
    )


def _segment(value: dict) -> bytes:
    return websafe_encode(json.dumps(value).encode()).encode("ascii")


def _payload() -> dict:
    return {
        "legalHeader": "demo",
        "no": 1,
        "nextUpdate": "2099-01-01",
        "entries": [{"statusReports": [{"status": "FIDO_CERTIFIED"}], "timeOfLastStatusChange": "2020-01-01"}],
    }


def _blob(header: dict, payload: dict, key) -> bytes:
    message = _segment(header) + b"." + _segment(payload)
    return message + b"." + websafe_encode(key.sign(message, ec.ECDSA(hashes.SHA256()))).encode("ascii")


def _x5c(*certificates: bytes) -> list[str]:
    return [base64.b64encode(certificate).decode("ascii") for certificate in certificates]


def test_a_chain_ending_in_a_cross_certificate_reaches_either_root():
    certs = _transition()
    chain = [certs.leaf, certs.intermediate, certs.cross]

    # As one straight chain (fido2's parse_blob) the pinned root is refused.
    with pytest.raises(InvalidSignature):
        verify_x509_chain(chain + [certs.current_root])

    mds_blob.verify_chain_to_root(chain, certs.current_root)
    mds_blob.verify_chain_to_root(chain, certs.legacy_root)
    mds_blob.verify_chain_to_root([certs.leaf, certs.intermediate], certs.current_root)
    with pytest.raises(InvalidSignature):
        mds_blob.verify_chain_to_root(chain, certs.unrelated)


def test_each_shorter_path_is_tried_before_a_longer_one(monkeypatch):
    calls = []

    def _verify(chain):
        calls.append(list(chain))
        if len(chain) != 3:
            raise InvalidSignature("incomplete path")

    monkeypatch.setattr(mds_blob, "verify_x509_chain", _verify)
    mds_blob.verify_chain_to_root([b"leaf", b"ca", b"cross"], b"root")

    assert calls == [[b"leaf", b"root"], [b"leaf", b"ca", b"root"]]


def test_no_x5c_means_the_root_signed_the_blob():
    key = ec.generate_private_key(ec.SECP256R1())
    root = _certificate(subject="Signer", issuer="Signer", public_key=key.public_key(), issuer_key=key)

    assert mds_blob.verify_blob(_blob({"alg": "ES256"}, _payload(), key), root) == _payload()


def test_a_blob_with_the_cross_certificate_in_x5c_verifies_and_keeps_its_json():
    certs = _transition()
    payload = {**_payload(), "notModelled": {"kept": True}}
    header = {"alg": "ES256", "x5c": _x5c(certs.leaf, certs.intermediate, certs.cross)}

    assert mds_blob.verify_blob(_blob(header, payload, certs.leaf_key), certs.current_root) == payload


def test_a_blob_signed_by_another_key_is_refused():
    certs = _transition()
    header = {"alg": "ES256", "x5c": _x5c(certs.leaf, certs.intermediate)}

    with pytest.raises(CryptographyInvalidSignature):
        mds_blob.verify_blob(_blob(header, _payload(), ec.generate_private_key(ec.SECP256R1())), certs.current_root)


def test_a_payload_that_is_not_metadata_is_refused():
    certs = _transition()
    header = {"alg": "ES256", "x5c": _x5c(certs.leaf, certs.intermediate)}

    with pytest.raises(Exception):
        mds_blob.verify_blob(_blob(header, {"entries": "not a list"}, certs.leaf_key), certs.current_root)


def test_a_signing_certificate_whose_key_does_not_load_is_refused(monkeypatch):
    certs = _transition()
    header = {"alg": "ES256", "x5c": _x5c(certs.leaf, certs.intermediate)}
    blob = _blob(header, _payload(), certs.leaf_key)

    class _Unloadable:
        def public_key(self):
            raise ValueError("not a key")

    monkeypatch.setattr(mds_blob.x509, "load_der_x509_certificate", lambda _der: _Unloadable())
    monkeypatch.setattr(mds_blob, "verify_chain_to_root", lambda _chain, _root: None)
    with pytest.raises(ValueError, match="does not expose a supported public key"):
        mds_blob.verify_blob(blob, certs.current_root)
