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
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    mldsa,
    padding,
    rsa,
)
from cryptography.x509.oid import NameOID

import server.app.mds_snapshot as mds_snapshot
from server.app.webauthn.attestation import serialize_attestation_certificate


def _self_signed(key, algorithm, common_name, rsa_padding=None) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2034, 1, 1))
        .sign(key, algorithm, rsa_padding=rsa_padding)
    )
    return certificate.public_bytes(serialization.Encoding.DER)


_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_DSA_KEY = dsa.generate_private_key(key_size=2048)


def _pss(hash_algorithm):
    return padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.DIGEST_LENGTH)


@pytest.mark.parametrize(
    ("key", "algorithm", "rsa_padding", "expected"),
    [
        (ec.generate_private_key(ec.SECP256R1()), hashes.SHA256(), None, "ECDSA_SHA256"),
        (ec.generate_private_key(ec.SECP384R1()), hashes.SHA384(), None, "ECDSA_SHA384"),
        (_RSA_KEY, hashes.SHA256(), None, "RSASSA-PKCS1-v1_5_SHA256"),
        # cryptography names the OID "rsassaPss"; both views used to read it as PKCS#1 v1.5.
        (_RSA_KEY, hashes.SHA256(), _pss(hashes.SHA256()), "RSASSA-PSS_SHA256"),
        (_RSA_KEY, hashes.SHA384(), _pss(hashes.SHA384()), "RSASSA-PSS_SHA384"),
        (ed25519.Ed25519PrivateKey.generate(), None, None, "ED25519_SHA512"),
        (ed448.Ed448PrivateKey.generate(), None, None, "ED448_SHAKE256"),
        # Both views used to spell ML-DSA "DSA", and SHA3 as the dotted OID plus "SHA3256".
        (mldsa.MLDSA44PrivateKey.generate(), None, None, "ML-DSA-44"),
        (mldsa.MLDSA65PrivateKey.generate(), None, None, "ML-DSA-65"),
        (ec.generate_private_key(ec.SECP256R1()), hashes.SHA3_256(), None, "ECDSA_SHA3-256"),
        (_RSA_KEY, hashes.SHA3_384(), padding.PKCS1v15(), "RSASSA-PKCS1-v1_5_SHA3-384"),
    ],
    ids=[
        "p256", "p384", "rsa", "rsa-pss-sha256", "rsa-pss-sha384", "ed25519", "ed448",
        "ml-dsa-44", "ml-dsa-65", "ecdsa-sha3-256", "rsa-sha3-384",
    ],
)
def test_the_mds_summary_names_a_root_as_the_certificate_view_does(key, algorithm, rsa_padding, expected):
    der = _self_signed(key, algorithm, "Root", rsa_padding)

    algorithms, common_names = mds_snapshot._summarise_attestation_certificates([der])

    assert algorithms == [expected]
    assert serialize_attestation_certificate(der)["algorithmInfo"] == expected
    assert common_names == ["Root"]


def test_mds_snapshot_keeps_no_copy_of_the_helpers():
    for name in ("_normalise_signature_algorithm_name", "_format_hash_value", "_derive_certificate_algorithm_info"):
        assert not hasattr(mds_snapshot, name), name


def _without_pss_parameters(der: bytes) -> bytes:
    """``der`` with both RSASSA-PSS AlgorithmIdentifiers' parameters emptied.

    cryptography only signs with explicit parameters; empty ones mean the RFC 4055
    defaults (SHA-1). The signature no longer verifies, which a name does not need.
    """

    oid = bytes.fromhex("06092a864886f70d01010a")
    start = der.index(oid) - 2
    identifier = der[start : start + 2 + der[start + 1]]
    shorter = b"\x30\x0d" + oid + b"\x30\x00"
    body = der.replace(identifier, shorter)
    shrink = len(identifier) - len(shorter)
    # Certificate and TBSCertificate both have two-byte long-form lengths here.
    outer = int.from_bytes(body[2:4], "big") - 2 * shrink
    tbs = int.from_bytes(body[6:8], "big") - shrink
    return body[:2] + outer.to_bytes(2, "big") + body[4:6] + tbs.to_bytes(2, "big") + body[8:]


def test_a_pss_signature_without_parameters_is_named_with_the_default_hash():
    der = _without_pss_parameters(_self_signed(_RSA_KEY, hashes.SHA256(), "Root", _pss(hashes.SHA256())))
    assert x509.load_der_x509_certificate(der).signature_hash_algorithm.name == "sha1"

    algorithms, _names = mds_snapshot._summarise_attestation_certificates([der])

    assert algorithms == ["RSASSA-PSS_SHA1"]
    assert serialize_attestation_certificate(der)["algorithmInfo"] == "RSASSA-PSS_SHA1"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("rsassaPss", "RSASSA-PSS"),
        ("RSASSA-PSS", "RSASSA-PSS"),
        ("rsassa_pss", "RSASSA-PSS"),
        ("1.2.840.113549.1.1.10", "RSASSA-PSS"),
        ("sha256WithRSAEncryption", "RSASSA-PKCS1-v1_5"),
        ("ML-DSA-87", "ML-DSA-87"),
        ("2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
        ("dsa-with-sha1", "DSA"),
        ("2.16.840.1.101.3.4.3.12", "ECDSA"),
        ("2.16.840.1.101.3.4.3.16", "RSASSA-PKCS1-v1_5"),
        ("some thing-else", "SOMETHINGELSE"),
    ],
)
def test_a_signature_algorithm_is_named_by_name_or_oid(name, expected):
    from server.app.webauthn import signature_algorithms

    assert signature_algorithms.normalise_signature_algorithm_name(name) == expected


def _spelled(name: str) -> str:
    """A signature algorithm's spelling from its name or dotted OID alone, as both views make it without a hash."""

    from server.app.webauthn import signature_algorithms

    return signature_algorithms.join_algorithm_info(
        signature_algorithms.normalise_signature_algorithm_name(name),
        signature_algorithms.implied_hash_name(name),
    )


# The names and OIDs cryptography 50 cannot name, or names some other way.
@pytest.mark.parametrize(
    ("name", "spelled"),
    [
        ("RSA-PSS", "RSASSA-PKCS1-v1_5"),
        ("rsaPSS", "RSASSA-PKCS1-v1_5"),
        # Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs-19).
        ("id-MLDSA44-ECDSA-P256-SHA256", "ECDSA"),
        ("MLDSA65-RSA3072-PSS-SHA512", "ML-DSA-65"),
        ("id-MLDSA87-Ed448-SHAKE256", "ML-DSA-87_SHAKE256"),
        ("1.3.6.1.5.5.7.6.40", "1.3.6.1.5.5.7.6.40"),
        ("1.3.6.1.5.5.7.6.51", "1.3.6.1.5.5.7.6.51"),
        # HashML-DSA (FIPS 204 section 5.4).
        ("HashML-DSA-65", "ML-DSA-65"),
        ("id-hash-ml-dsa-44-with-sha512", "ML-DSA-44"),
        ("2.16.840.1.101.3.4.3.32", "2.16.840.1.101.3.4.3.32"),
        # DSA with SHA-384, SHA-512 and SHA3.
        ("2.16.840.1.101.3.4.3.3", "2.16.840.1.101.3.4.3.3"),
        ("2.16.840.1.101.3.4.3.4", "2.16.840.1.101.3.4.3.4"),
        ("2.16.840.1.101.3.4.3.5", "2.16.840.1.101.3.4.3.5"),
        ("2.16.840.1.101.3.4.3.8", "2.16.840.1.101.3.4.3.8"),
        ("id-dsa-with-sha3-256", "DSA"),
        ("dsa-with-sha384", "DSA"),
        # SLH-DSA and HashSLH-DSA (FIPS 205).
        ("2.16.840.1.101.3.4.3.20", "2.16.840.1.101.3.4.3.20"),
        ("SLH-DSA-SHA2-128s", "DSA"),
        ("id-slh-dsa-shake-256f", "DSA"),
        ("2.16.840.1.101.3.4.3.35", "2.16.840.1.101.3.4.3.35"),
        ("2.16.840.1.101.3.4.3.46", "2.16.840.1.101.3.4.3.46"),
    ],
)
def test_how_a_signature_algorithm_without_a_hash_from_cryptography_is_spelled(name, spelled):
    assert _spelled(name) == spelled


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [(hashes.SHA384(), "2.16.840.1.101.3.4.3.3"), (hashes.SHA512(), "2.16.840.1.101.3.4.3.4")],
    ids=["dsa-sha384", "dsa-sha512"],
)
def test_a_dsa_certificate_signed_with_sha384_or_sha512_is_named_in_both_views(algorithm, expected):
    der = _self_signed(_DSA_KEY, algorithm, "Root")

    algorithms, _names = mds_snapshot._summarise_attestation_certificates([der])

    assert algorithms == [expected]
    assert serialize_attestation_certificate(der)["algorithmInfo"] == expected
