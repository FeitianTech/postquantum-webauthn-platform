"""ML-DSA certificates: what ``webauthn.mldsa`` reads from them and how ``attestation.chain`` verifies them.

Real certificates throughout: ``cryptography`` generates the ML-DSA keys and
signs the certificates (``tests/pqc/mldsa_helpers.py``), so nothing here stands
a fabricated byte string in for a key or a signature.
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    mldsa,
    padding,
    rsa,
)
from cryptography.x509.oid import NameOID
from fido2.attestation import InvalidSignature

from server.app.encoding import encode_base64
from server.app.webauthn import mldsa as mldsa_info
from server.app.webauthn.attestation import chain
from server.app.webauthn.attestation.certificates import (
    serialize_attestation_certificate,
)
from tests.pqc import mldsa_helpers

PARAMETER_SETS = [
    ("ML-DSA-44", mldsa.MLDSA44PrivateKey, 1312, 2420, "2.16.840.1.101.3.4.3.17"),
    ("ML-DSA-65", mldsa.MLDSA65PrivateKey, 1952, 3309, "2.16.840.1.101.3.4.3.18"),
    ("ML-DSA-87", mldsa.MLDSA87PrivateKey, 2592, 4627, "2.16.840.1.101.3.4.3.19"),
]
_NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


def _certificate(
    subject_key, *, issuer_key=None, name="subject", issuer_name=None, algorithm=None, rsa_padding=None
) -> bytes:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name or name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(7)
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=1))
    )
    signing = {"rsa_padding": rsa_padding} if rsa_padding is not None else {}
    signed = builder.sign(issuer_key or subject_key, algorithm, **signing)
    return signed.public_bytes(serialization.Encoding.DER)


# -- webauthn.mldsa -----------------------------------------------------------


@pytest.mark.parametrize("label,key_cls,key_len,sig_len,oid", PARAMETER_SETS)
def test_public_key_info_from_a_real_mldsa_certificate(label, key_cls, key_len, sig_len, oid):
    info = mldsa_info.extract_certificate_public_key_info(_certificate(key_cls.generate()))

    assert info["algorithm_oid"] == oid
    assert info["ml_dsa_parameter_set"] == label
    assert info["algorithm_name"] == "ML-DSA"
    assert info["algorithm_display_name"] == label
    # The raw key is unwrapped from SubjectPublicKeyInfo at its exact FIPS 204 size.
    assert len(info["subject_public_key"]) == key_len
    # FIPS 204 sizes, not the pre-standard Dilithium Round 3 values.
    assert info["ml_dsa_parameter_details"]["signature_length"] == sig_len
    assert info["ml_dsa_parameter_details"]["public_key_length"] == key_len


@pytest.mark.parametrize(
    "key, subject_public_key_length",
    [
        pytest.param(ec.generate_private_key(ec.SECP256R1()), 65, id="ec-uncompressed-point"),
        pytest.param(rsa.generate_private_key(public_exponent=65537, key_size=2048), None, id="rsa-pkcs1"),
        pytest.param(ed25519.Ed25519PrivateKey.generate(), 32, id="ed25519-raw"),
    ],
)
def test_public_key_info_for_classical_keys_has_no_mldsa_members(key, subject_public_key_length):
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    info = mldsa_info.extract_certificate_public_key_info(_certificate(key, algorithm=algorithm))

    assert info["subject_public_key_info"] == key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if subject_public_key_length is not None:
        assert len(info["subject_public_key"]) == subject_public_key_length
    else:
        assert info["subject_public_key"].startswith(b"\x30")
    assert not any(name.startswith(("ml_dsa", "algorithm_name", "algorithm_display")) for name in info)


def test_public_key_info_leaves_out_a_key_it_cannot_express_raw():
    # DSA has no raw public-key form; the SubjectPublicKeyInfo is still reported.
    subject = dsa.generate_private_key(key_size=2048)
    issuer = ec.generate_private_key(ec.SECP256R1())
    der = _certificate(subject, issuer_key=issuer, issuer_name="issuer", algorithm=hashes.SHA256())

    info = mldsa_info.extract_certificate_public_key_info(der)

    assert info["algorithm_oid"] == "1.2.840.10040.4.1"
    assert "subject_public_key_info" in info
    assert "subject_public_key" not in info


def test_public_key_info_of_a_key_algorithm_cryptography_does_not_know():
    ec_der = _certificate(ec.generate_private_key(ec.SECP256R1()), algorithm=hashes.SHA256())
    id_ec_public_key = bytes.fromhex("06072a8648ce3d0201")
    # The same length of OID, one arc off: 1.2.840.10045.2.9, which nothing defines.
    unknown = bytes.fromhex("06072a8648ce3d0209")
    assert ec_der.count(id_ec_public_key) == 1

    info = mldsa_info.extract_certificate_public_key_info(ec_der.replace(id_ec_public_key, unknown))

    assert info == {"algorithm_oid": "1.2.840.10045.2.9", "algorithm_parameters": None}


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"\x30", id="bare-sequence-tag"),
        pytest.param(b"\x30\x82\x01\x00", id="length-exceeds-data"),
        pytest.param(b"not a certificate at all", id="not-der"),
        pytest.param(b"\x30\x03\x02\x01\x00", id="well-formed-der-but-not-a-cert"),
    ],
)
def test_malformed_certificates_are_rejected(payload):
    """Garbage raises rather than being scanned for something key-shaped."""

    with pytest.raises(ValueError):
        mldsa_info.extract_certificate_public_key_info(payload)


@pytest.mark.parametrize("label,key_cls,key_len,sig_len,oid", PARAMETER_SETS)
def test_truncated_certificate_is_rejected(label, key_cls, key_len, sig_len, oid):
    der = _certificate(key_cls.generate())

    with pytest.raises(ValueError):
        mldsa_info.extract_certificate_public_key_info(der[: len(der) // 2])


def test_oid_descriptions_for_each_parameter_set():
    for label, _key_cls, _key_len, _sig_len, oid in PARAMETER_SETS:
        assert mldsa_info.describe_mldsa_oid(oid) == {
            "name": "ML-DSA", "mlDsaParameterSet": label, "display": label, "oid": oid,
        }
    for other in ("1.2.840.113549.1.1.11", "", None):
        assert mldsa_info.describe_mldsa_oid(other) is None


@pytest.mark.parametrize("label,key_cls,key_len,sig_len,oid", PARAMETER_SETS)
def test_an_mldsa_signature_is_named_for_its_parameter_set(label, key_cls, key_len, sig_len, oid):
    key = key_cls.generate()
    signature = serialize_attestation_certificate(_certificate(key, issuer_key=key))["signature"]

    assert signature["algorithm"] == label
    assert signature["oid"] == oid


def test_parameter_details_are_the_fips_204_sizes():
    assert mldsa_info.parameter_details("ML-DSA-44") == {
        "public_key_length": 1312, "signature_length": 2420, "claimed_nist_level": 2,
    }
    assert mldsa_info.parameter_details("ML-DSA-65")["signature_length"] == 3309
    assert mldsa_info.parameter_details("ML-DSA-87")["signature_length"] == 4627
    assert mldsa_info.parameter_details(None) == {}
    assert mldsa_info.parameter_details("Not-A-Parameter-Set") == {}
    # A copy: changing it leaves the table alone.
    mldsa_info.parameter_details("ML-DSA-44")["public_key_length"] = 0
    assert mldsa_info.parameter_details("ML-DSA-44")["public_key_length"] == 1312


# -- attestation.chain --------------------------------------------------------


def _ec_certificate_der() -> bytes:
    return _certificate(ec.generate_private_key(ec.SECP256R1()), name="classical", algorithm=hashes.SHA256())


@pytest.mark.parametrize("parameter_set", mldsa_helpers.PARAMETER_SETS)
def test_mldsa_chains_verify_only_against_the_real_issuer(parameter_set):
    issued = mldsa_helpers.certificate(parameter_set, label="leaf", issuer_label="ca", common_name=f"{parameter_set} leaf")
    real_issuer = mldsa_helpers.certificate(parameter_set, label="ca", ca=True)
    other_issuer = mldsa_helpers.certificate(parameter_set, label="impostor", ca=True)

    chain.verify_certificate_chain([issued, real_issuer])

    with pytest.raises(InvalidSignature):
        chain.verify_certificate_chain([issued, other_issuer])

    # A single flipped bit anywhere in the signed certificate is refused.
    tampered = bytearray(issued)
    tampered[-1] ^= 0x01
    with pytest.raises(InvalidSignature):
        chain.verify_certificate_chain([bytes(tampered), real_issuer])


@pytest.mark.parametrize(
    "issuer_key",
    [
        pytest.param(ec.generate_private_key(ec.SECP256R1()), id="ecdsa"),
        pytest.param(rsa.generate_private_key(public_exponent=65537, key_size=2048), id="rsa"),
    ],
)
def test_classical_chains_verify_only_against_the_real_issuer(issuer_key):
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    root = _certificate(issuer_key, name="root", algorithm=hashes.SHA256())
    leaf = _certificate(leaf_key, issuer_key=issuer_key, name="leaf", issuer_name="root", algorithm=hashes.SHA256())
    impostor = _certificate(ec.generate_private_key(ec.SECP256R1()), name="root", algorithm=hashes.SHA256())

    chain.verify_certificate_chain([leaf, root])
    chain.verify_certificate_chain([root])
    with pytest.raises(InvalidSignature):
        chain.verify_certificate_chain([leaf, impostor])


def test_rsa_pss_and_eddsa_signed_chains_verify():
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    rsa_root = _certificate(rsa_key, name="root", algorithm=hashes.SHA256())
    pss_leaf = _certificate(
        leaf_key, issuer_key=rsa_key, name="leaf", issuer_name="root", algorithm=hashes.SHA256(), rsa_padding=pss
    )
    ed_key = ed25519.Ed25519PrivateKey.generate()
    ed_root = _certificate(ed_key, name="root")
    ed_leaf = _certificate(leaf_key, issuer_key=ed_key, name="leaf", issuer_name="root")

    chain.verify_certificate_chain([pss_leaf, rsa_root])
    chain.verify_certificate_chain([ed_leaf, ed_root])
    with pytest.raises(InvalidSignature):
        chain.verify_certificate_chain([ed_leaf, _certificate(ed25519.Ed25519PrivateKey.generate(), name="root")])
    with pytest.raises(ValueError):
        chain.verify_certificate_chain([ed_leaf, b"not a certificate"])


def test_an_issuer_of_another_name_or_key_type_did_not_issue_the_certificate():
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    root = _certificate(issuer_key, name="root", algorithm=hashes.SHA256())
    elsewhere = _certificate(ec.generate_private_key(ec.SECP256R1()), issuer_key=issuer_key, name="leaf", issuer_name="other", algorithm=hashes.SHA256())
    rsa_root = _certificate(rsa.generate_private_key(public_exponent=65537, key_size=2048), name="root", algorithm=hashes.SHA256())
    ec_signed = _certificate(ec.generate_private_key(ec.SECP256R1()), issuer_key=issuer_key, name="leaf", issuer_name="root", algorithm=hashes.SHA256())

    with pytest.raises(InvalidSignature):
        chain.verify_certificate_chain([elsewhere, root])
    with pytest.raises(InvalidSignature):
        chain.verify_certificate_chain([ec_signed, rsa_root])


def test_an_issuer_whose_key_does_not_load_is_refused():
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    root = _certificate(issuer_key, name="root", algorithm=hashes.SHA256())
    leaf = _certificate(issuer_key, name="leaf", issuer_name="root", algorithm=hashes.SHA256())
    point = issuer_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    # Not a point on P-256: the certificate parses, its key does not.
    off_curve = root.replace(point, b"\x04" + b"\x01" * 64)

    with pytest.raises(ValueError, match="Unsupported issuer key"):
        chain.verify_certificate_chain([leaf, off_curve])


# -- the certificate views ------------------------------------------------------


@pytest.mark.parametrize(("label", "key_cls", "key_len", "sig_len", "oid"), PARAMETER_SETS)
def test_a_certificates_mldsa_key_is_shown_with_its_parameter_set_and_raw_key(label, key_cls, key_len, sig_len, oid):
    der = mldsa_helpers.certificate(label)
    raw = x509.load_der_x509_certificate(der).public_key().public_bytes_raw()

    view = serialize_attestation_certificate(der)
    info = view["publicKeyInfo"]

    assert info["type"] == "ML-DSA"
    assert info["mechanismName"] == label
    assert info["keySize"] == key_len * 8
    assert info["publicKeyBase64"] == encode_base64(raw)
    assert info["algorithm"] == {
        "name": "ML-DSA",
        "oid": oid,
        "mlDsaParameterSet": label,
        "claimedNistLevel": mldsa_info.parameter_details(label)["claimed_nist_level"],
        "signatureLengthBytes": sig_len,
    }
    assert f"ML-DSA parameter set: {label}" in view["summary"]
