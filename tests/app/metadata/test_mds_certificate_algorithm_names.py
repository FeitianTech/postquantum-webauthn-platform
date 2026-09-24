"""The MDS explorer and the certificate view spell a signature algorithm one way.

``mds_snapshot`` kept its own copies of the certificate view's algorithm-name
helpers, so the two could drift; they now share ``webauthn/signature_algorithms``.
The copy had drifted once already: an Ed25519-signed certificate, whose
signature has no separate hash, raised ``AttributeError`` in the MDS summary
while the certificate view named it ``ED25519_SHA512``.
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

import server.app.mds_snapshot as mds_snapshot
from server.app.webauthn.attestation import serialize_attestation_certificate


def _self_signed(key, algorithm, common_name) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2034, 1, 1))
        .sign(key, algorithm)
    )
    return certificate.public_bytes(serialization.Encoding.DER)


@pytest.mark.parametrize(
    ("key", "algorithm", "expected"),
    [
        (ec.generate_private_key(ec.SECP256R1()), hashes.SHA256(), "ECDSA_SHA256"),
        (ec.generate_private_key(ec.SECP384R1()), hashes.SHA384(), "ECDSA_SHA384"),
        (rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256(), "RSASSA-PKCS1-v1_5_SHA256"),
        (ed25519.Ed25519PrivateKey.generate(), None, "ED25519_SHA512"),
        (ed448.Ed448PrivateKey.generate(), None, "ED448_SHAKE256"),
    ],
    ids=["p256", "p384", "rsa", "ed25519", "ed448"],
)
def test_the_mds_summary_names_a_root_as_the_certificate_view_does(key, algorithm, expected):
    der = _self_signed(key, algorithm, "Root")

    algorithms, common_names = mds_snapshot._summarise_attestation_certificates([der])

    assert algorithms == [expected]
    assert serialize_attestation_certificate(der)["algorithmInfo"] == expected
    assert common_names == ["Root"]


def test_mds_snapshot_keeps_no_copy_of_the_helpers():
    for name in ("_normalise_signature_algorithm_name", "_format_hash_value", "_derive_certificate_algorithm_info"):
        assert not hasattr(mds_snapshot, name), name
