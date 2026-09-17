"""Real ML-DSA key material for the post-quantum tests.

Everything here uses ``cryptography``'s native ML-DSA: real key generation,
real signatures and real ML-DSA-signed X.509 certificates.  Nothing in this
module fabricates key bytes or stands a digest in for a signature.
"""

from __future__ import annotations

import datetime
from functools import lru_cache
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.x509.oid import NameOID

from fido2 import cose

PARAMETER_SETS: tuple[str, str, str] = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")

COSE_KEY_CLASSES = {
    "ML-DSA-44": cose.MLDSA44,
    "ML-DSA-65": cose.MLDSA65,
    "ML-DSA-87": cose.MLDSA87,
}

COSE_ALGORITHMS = {
    name: cls.ALGORITHM for name, cls in COSE_KEY_CLASSES.items()
}

PRIVATE_KEY_CLASSES = {
    "ML-DSA-44": mldsa.MLDSA44PrivateKey,
    "ML-DSA-65": mldsa.MLDSA65PrivateKey,
    "ML-DSA-87": mldsa.MLDSA87PrivateKey,
}

PUBLIC_KEY_CLASSES = {
    "ML-DSA-44": mldsa.MLDSA44PublicKey,
    "ML-DSA-65": mldsa.MLDSA65PublicKey,
    "ML-DSA-87": mldsa.MLDSA87PublicKey,
}

# FIPS 204 final sizes.
PUBLIC_KEY_LENGTHS = {"ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592}
SIGNATURE_LENGTHS = {"ML-DSA-44": 2420, "ML-DSA-65": 3309, "ML-DSA-87": 4627}

# The OID a packed attestation certificate uses to carry the AAGUID.
OID_AAGUID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")


@lru_cache(maxsize=None)
def private_key(parameter_set: str, label: str = "default"):
    """Return a cached real ML-DSA private key.

    Distinct ``label`` values give independent keypairs, which is how the
    tests build "a public key from a different keypair".
    """

    return PRIVATE_KEY_CLASSES[parameter_set].generate()


def public_key(parameter_set: str, label: str = "default"):
    return private_key(parameter_set, label).public_key()


def public_key_bytes(parameter_set: str, label: str = "default") -> bytes:
    return public_key(parameter_set, label).public_bytes_raw()


def spki_der(parameter_set: str, label: str = "default") -> bytes:
    return public_key(parameter_set, label).public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def cose_key(
    parameter_set: str,
    label: str = "default",
    *,
    key_bytes: bytes | None = None,
    kty: int = 7,
) -> cose.CoseKey:
    """Return a COSE key holding a real ML-DSA public key."""

    cls = COSE_KEY_CLASSES[parameter_set]
    return cls(
        {
            1: kty,
            3: cls.ALGORITHM,
            -1: public_key_bytes(parameter_set, label) if key_bytes is None else key_bytes,
        }
    )


def sign(parameter_set: str, message: bytes, label: str = "default") -> bytes:
    """Produce a real ML-DSA signature over *message*."""

    return private_key(parameter_set, label).sign(bytes(message))


def flip_bit(data: bytes, index: int = 0, bit: int = 0) -> bytes:
    """Return *data* with a single bit flipped."""

    mutated = bytearray(data)
    mutated[index] ^= 1 << bit
    return bytes(mutated)


def _subject_name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PQC WebAuthn Test"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def certificate(
    parameter_set: str,
    *,
    label: str = "attestation",
    common_name: str | None = None,
    aaguid: bytes | None = None,
    ca: bool = False,
    basic_constraints: bool = True,
    issuer_parameter_set: str | None = None,
    issuer_label: str | None = None,
    issuer_common_name: str | None = None,
    not_valid_before: datetime.datetime | None = None,
    not_valid_after: datetime.datetime | None = None,
    serial_number: int = 0x5EC0DE,
) -> bytes:
    """Build a real ML-DSA-signed certificate and return its DER encoding.

    The subject carries everything packed attestation requires: C, O,
    OU="Authenticator Attestation" and CN, plus (by default) a non-critical
    AAGUID extension and Basic Constraints with CA=false.
    """

    common_name = common_name or f"{parameter_set} {label}"
    subject = _subject_name(common_name)

    issuer_parameter_set = issuer_parameter_set or parameter_set
    issuer_label = issuer_label if issuer_label is not None else label
    signing_key = private_key(issuer_parameter_set, issuer_label)
    if issuer_label == label and issuer_parameter_set == parameter_set:
        issuer = subject
    else:
        issuer = _subject_name(
            issuer_common_name or f"{issuer_parameter_set} {issuer_label}"
        )

    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key(parameter_set, label))
        .serial_number(serial_number)
        .not_valid_before(not_valid_before or now - datetime.timedelta(days=1))
        .not_valid_after(not_valid_after or now + datetime.timedelta(days=365))
    )
    if basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True
        )
    if aaguid is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                OID_AAGUID,
                # DER OCTET STRING wrapping the 16 AAGUID bytes.
                bytes([0x04, len(aaguid)]) + aaguid,
            ),
            critical=False,
        )

    cert = builder.sign(signing_key, None)
    return cert.public_bytes(serialization.Encoding.DER)


def certificate_and_key(parameter_set: str, **kwargs: Any) -> tuple[bytes, Any]:
    """Return ``(der, private_key)`` for a certificate built by :func:`certificate`."""

    label = kwargs.get("label", "attestation")
    return certificate(parameter_set, **kwargs), private_key(parameter_set, label)
