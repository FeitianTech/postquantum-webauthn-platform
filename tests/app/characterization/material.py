"""Deterministic key material, credentials and certificates for the characterization tests.

Everything the recorded responses echo back has to come out byte-identical on
every run: EC keys are derived from labels and sign with RFC 6979 deterministic
ECDSA, Ed25519/Ed448 keys come from fixed seeds, RSA signs with PKCS#1 v1.5, and
every certificate is signed by a fixed Ed25519 key; RSA keys are built from primes
derived from a label. The one thing that cannot be derived is an ML-DSA signature
(ML-DSA signing is hedged, so randomised): an ML-DSA signature a response echoes is
generated once and kept in ``inputs/frozen.json``; ``CHARACTERIZATION_WRITE=1``
adds a missing one. No private key is stored anywhere.
"""
from __future__ import annotations

import datetime
import functools
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    mldsa,
    padding,
    rsa,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fido2 import cbor, cose

from ..security import ceremony_helpers

FROZEN_PATH = Path(__file__).parent / "inputs" / "frozen.json"
WRITE_ENV = "CHARACTERIZATION_WRITE"

NOT_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2099, 12, 31, tzinfo=datetime.timezone.utc)

OID_AAGUID = x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")
OID_TRANSPORTS = x509.ObjectIdentifier("1.3.6.1.4.1.45724.2.1.1")
OID_FIRMWARE = x509.ObjectIdentifier("1.3.6.1.4.1.41482.13.1")
OID_YUBICO_DEVICE = x509.ObjectIdentifier("1.3.6.1.4.1.41482.2")
OID_YUBICO_VALUE = x509.ObjectIdentifier("1.3.6.1.4.1.41482.1.1")

MLDSA_PRIVATE = {"ML-DSA-44": mldsa.MLDSA44PrivateKey, "ML-DSA-65": mldsa.MLDSA65PrivateKey}
MLDSA_COSE = {"ML-DSA-44": cose.MLDSA44, "ML-DSA-65": cose.MLDSA65}


# -- frozen inputs -----------------------------------------------------------


def _load_frozen() -> dict[str, Any]:
    try:
        return json.loads(FROZEN_PATH.read_text())
    except FileNotFoundError:
        return {}


def _frozen(key: str, make) -> str:
    """The frozen value ``key``; generated and saved by ``make`` only in write mode."""

    frozen = _load_frozen()
    if key not in frozen:
        if os.environ.get(WRITE_ENV) != "1":
            raise KeyError(f"{key} is not in {FROZEN_PATH.name}; run with {WRITE_ENV}=1 to add it")
        frozen[key] = make()
        FROZEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        FROZEN_PATH.write_text(json.dumps(frozen, indent=1, sort_keys=True) + "\n")
    return frozen[key]


# -- keys ----------------------------------------------------------------------


def _seed(label: str, size: int = 32) -> bytes:
    return hashlib.shake_256(label.encode("utf-8")).digest(size)


def ec_key(label: str, curve: ec.EllipticCurve | None = None) -> ec.EllipticCurvePrivateKey:
    curve = curve or ec.SECP256R1()
    # One byte short of the curve size, so the scalar is always below the order.
    scalar = int.from_bytes(_seed(label, curve.key_size // 8 - 1), "big") or 1
    return ec.derive_private_key(scalar, curve)


def ed25519_key(label: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(_seed(label))


def ed448_key(label: str) -> ed448.Ed448PrivateKey:
    return ed448.Ed448PrivateKey.from_private_bytes(_seed(label, 57))


def mldsa_key(parameter_set: str, label: str):
    return MLDSA_PRIVATE[parameter_set].from_seed_bytes(_seed(f"{parameter_set}:{label}"))


_SMALL_PRIMES = [p for p in range(3, 2000) if all(p % q for q in range(2, int(p**0.5) + 1))]


def _probable_prime(candidate: int, label: str) -> bool:
    if any(candidate % p == 0 for p in _SMALL_PRIMES):
        return False
    d, r = candidate - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for round_ in range(40):
        base = 2 + int.from_bytes(_seed(f"{label}:base:{round_}", 128), "big") % (candidate - 3)
        x = pow(base, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _derived_prime(label: str, bits: int) -> int:
    counter = 0
    while True:
        candidate = int.from_bytes(_seed(f"{label}:{counter}", bits // 8), "big")
        candidate |= (3 << (bits - 2)) | 1  # top two bits set, so p*q has 2*bits bits; odd
        if _probable_prime(candidate, label):
            return candidate
        counter += 1


@functools.lru_cache(maxsize=None)
def rsa_key(label: str) -> rsa.RSAPrivateKey:
    """A 2048-bit RSA key derived from ``label`` (``cryptography`` only generates at random)."""

    e = 65537
    p = _derived_prime(f"rsa-p:{label}", 1024)
    q = _derived_prime(f"rsa-q:{label}", 1024)
    d = pow(e, -1, (p - 1) * (q - 1))
    public = rsa.RSAPublicNumbers(e, p * q)
    return rsa.RSAPrivateNumbers(
        p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q), public
    ).private_key()


def ecdsa_sign(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    return key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))


def mldsa_sign_frozen(parameter_set: str, label: str, message: bytes) -> bytes:
    """An ML-DSA signature that is echoed in a response: generated once, then frozen."""

    key = f"mldsa-signature:{parameter_set}:{label}:{hashlib.sha256(message).hexdigest()}"
    return bytes.fromhex(_frozen(key, lambda: mldsa_key(parameter_set, label).sign(message).hex()))


# -- credentials ---------------------------------------------------------------


class Authenticator(ceremony_helpers.Authenticator):
    """``ceremony_helpers.Authenticator`` with keys derived from ``label``."""

    def __init__(
        self,
        label: str,
        *,
        key_type: str = "es256",
        aaguid: bytes = b"\x00" * 16,
        credential_id: bytes | None = None,
    ) -> None:
        self.label = label
        self.key_type = key_type
        self.aaguid = aaguid
        self.credential_id = credential_id or hashlib.sha256(f"credential:{label}".encode()).digest()
        if key_type == "es256":
            self._private_key = ec_key(label)
            self.cose_key = cose.ES256.from_cryptography_key(self._private_key.public_key())
        elif key_type == "ed25519":
            self._private_key = ed25519_key(label)
            self.cose_key = cose.EdDSA.from_cryptography_key(self._private_key.public_key())
        elif key_type == "rs256":
            self._private_key = rsa_key(label)
            self.cose_key = cose.RS256.from_cryptography_key(self._private_key.public_key())
        elif key_type in MLDSA_PRIVATE:
            self._private_key = mldsa_key(key_type, label)
            cls = MLDSA_COSE[key_type]
            self.cose_key = cls({1: 7, 3: cls.ALGORITHM, -1: self._private_key.public_key().public_bytes_raw()})
        else:  # pragma: no cover - a typo in a scenario
            raise ValueError(key_type)

    @property
    def algorithm(self) -> int:
        return self.cose_key[3]

    def sign(self, message: bytes) -> bytes:
        if self.key_type == "es256":
            return ecdsa_sign(self._private_key, message)
        if self.key_type == "rs256":
            return self._private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        if self.key_type in MLDSA_PRIVATE:
            # Only assertions sign at run time; nothing echoes an assertion signature.
            return self._private_key.sign(message)
        return self._private_key.sign(message)

    def sign_echoed(self, message: bytes) -> bytes:
        """Sign something a response will echo (a self-attestation statement)."""

        if self.key_type in MLDSA_PRIVATE:
            return mldsa_sign_frozen(self.key_type, self.label, message)
        return self.sign(message)


def registration_payload(
    authenticator: Authenticator,
    *,
    challenge: bytes,
    fmt: str = "none",
    attestation: str = "none",
    origin: str = ceremony_helpers.ORIGIN,
    rp_id: str = ceremony_helpers.RP_ID,
    counter: int = 0,
    extension_results: dict[str, Any] | None = None,
    attachment: str | None = None,
    transports: list[str] | None = None,
    cross_origin: bool = False,
    ceremony_type: str = "webauthn.create",
    user_verified: bool = True,
    cose_key_bytes: bytes | None = None,
    x5c_aaguid: bytes | None = None,
    tamper: bool = False,
) -> dict[str, Any]:
    """A registration response; ``attestation`` is ``none``, ``self`` or ``x5c``.

    ``tamper`` flips a bit of the attestation signature after signing.
    """

    client_data = ceremony_helpers.client_data(
        challenge=challenge, ceremony_type=ceremony_type, origin=origin, cross_origin=cross_origin
    )
    auth_data = authenticator.authenticator_data(
        rp_id=rp_id, counter=counter, user_verified=user_verified, cose_key_bytes=cose_key_bytes
    )
    statement: dict[str, Any] = {}
    if attestation == "self":
        fmt = "packed"
        signed = auth_data + hashlib.sha256(client_data).digest()
        statement = {"alg": authenticator.algorithm, "sig": authenticator.sign_echoed(signed)}
    elif attestation == "x5c":
        fmt = "packed"
        leaf_key = ec_key("attestation-leaf")
        signed = auth_data + hashlib.sha256(client_data).digest()
        statement = {
            "alg": -7,
            "sig": ecdsa_sign(leaf_key, signed),
            "x5c": [attestation_leaf_certificate(authenticator.aaguid if x5c_aaguid is None else x5c_aaguid)],
        }
    if tamper and "sig" in statement:
        signature = bytearray(statement["sig"])
        signature[len(signature) // 2] ^= 0x01
        statement["sig"] = bytes(signature)
    response: dict[str, Any] = {
        "clientDataJSON": ceremony_helpers.b64u(client_data),
        "attestationObject": ceremony_helpers.b64u(ceremony_helpers.attestation_object(auth_data, fmt=fmt, att_stmt=statement)),
    }
    if transports is not None:
        response["transports"] = transports
    payload: dict[str, Any] = {
        "id": ceremony_helpers.b64u(authenticator.credential_id),
        "rawId": ceremony_helpers.b64u(authenticator.credential_id),
        "type": "public-key",
        "response": response,
        "clientExtensionResults": extension_results or {},
    }
    if transports is not None:
        payload["transports"] = transports
    if attachment is not None:
        payload["authenticatorAttachment"] = attachment
    return payload


def assertion_payload(
    authenticator: Authenticator,
    *,
    challenge: bytes,
    counter: int = 1,
    valid_signature: bool = True,
    origin: str = ceremony_helpers.ORIGIN,
    attachment: str | None = None,
) -> dict[str, Any]:
    payload = ceremony_helpers.assertion_payload(
        authenticator, challenge=challenge, counter=counter, valid_signature=valid_signature, origin=origin
    )
    if attachment is not None:
        payload["authenticatorAttachment"] = attachment
    return payload


# -- certificates --------------------------------------------------------------


def _name(common_name: str, *, packed: bool = True) -> x509.Name:
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if packed:
        attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Characterization Test"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
            *attributes,
        ]
    return x509.Name(attributes)


CA_NAME = _name("Characterization Test CA", packed=False)


def ca_key() -> ed25519.Ed25519PrivateKey:
    return ed25519_key("certificate-authority")


def certificate(
    public_key: Any,
    *,
    common_name: str,
    serial: int,
    extensions: list[tuple[Any, bool]] = (),
    signing_key: Any = None,
    issuer: x509.Name = CA_NAME,
    algorithm: Any = None,
    rsa_padding: Any = None,
    ecdsa_deterministic: bool | None = None,
) -> bytes:
    """A certificate for ``public_key``, signed by the fixed Ed25519 CA unless told otherwise.

    ``algorithm`` (the hash), ``rsa_padding`` and ``ecdsa_deterministic`` go to
    cryptography's ``sign`` for an RSA or EC signing key; an EC signature is only
    byte-stable with ``ecdsa_deterministic=True``.
    """

    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
    )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    signed = builder.sign(
        signing_key or ca_key(), algorithm, rsa_padding=rsa_padding, ecdsa_deterministic=ecdsa_deterministic
    )
    return signed.public_bytes(serialization.Encoding.DER)


def _octet_string(payload: bytes) -> bytes:
    return bytes([0x04, len(payload)]) + payload


def attestation_leaf_certificate(aaguid: bytes) -> bytes:
    return certificate(
        ec_key("attestation-leaf").public_key(),
        common_name="Characterization Attestation Leaf",
        serial=0x1EAF,
        extensions=[
            (x509.BasicConstraints(ca=False, path_length=None), True),
            (x509.UnrecognizedExtension(OID_AAGUID, _octet_string(aaguid)), False),
        ],
    )


def _many_extensions(public_key: Any) -> list[tuple[Any, bool]]:
    return [
        (x509.BasicConstraints(ca=True, path_length=1), True),
        (x509.SubjectKeyIdentifier.from_public_key(public_key), False),
        (
            x509.AuthorityKeyIdentifier(
                key_identifier=hashlib.sha1(b"authority").digest(),
                authority_cert_issuer=[x509.DirectoryName(CA_NAME)],
                authority_cert_serial_number=4242,
            ),
            False,
        ),
        (
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            True,
        ),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.SubjectAlternativeName([x509.DNSName("authenticator.example")]), False),
        (x509.UnrecognizedExtension(OID_FIRMWARE, _octet_string(bytes([5, 4, 3]))), False),
        (x509.UnrecognizedExtension(OID_YUBICO_DEVICE, _octet_string(b"1.3.6.1.4.1.41482.1.7")), False),
        (x509.UnrecognizedExtension(OID_YUBICO_VALUE, _octet_string(b"serial-0042")), False),
        (x509.UnrecognizedExtension(OID_AAGUID, _octet_string(bytes(range(16)))), False),
        (x509.UnrecognizedExtension(OID_TRANSPORTS, bytes([0x03, 0x02, 0x04, 0x30])), False),
        (x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"\x05\x00"), False),
    ]


def generated_certificates() -> dict[str, bytes]:
    """Byte-stable certificates for every public-key type and extension branch."""

    subjects = {
        "ec-p256": ec_key("subject-p256").public_key(),
        "ec-p384": ec_key("subject-p384", ec.SECP384R1()).public_key(),
        "rsa-2048": rsa_key("subject-rsa").public_key(),
        "ed25519": ed25519_key("subject-ed25519").public_key(),
        "ed448": ed448_key("subject-ed448").public_key(),
        "ml-dsa-44": mldsa_key("ML-DSA-44", "subject").public_key(),
        "ml-dsa-65": mldsa_key("ML-DSA-65", "subject").public_key(),
    }
    certificates = {
        f"generated-{name}": certificate(key, common_name=f"Subject {name}", serial=1000 + index)
        for index, (name, key) in enumerate(subjects.items())
    }
    many_key = ec_key("subject-many-extensions").public_key()
    certificates["generated-many-extensions"] = certificate(
        many_key, common_name="Many Extensions", serial=0x0E47, extensions=_many_extensions(many_key)
    )
    certificates["generated-attestation-leaf"] = attestation_leaf_certificate(bytes(range(16)))

    def _mldsa_signed() -> str:
        issuer_key = mldsa_key("ML-DSA-44", "issuer")
        return certificate(
            ec_key("subject-under-mldsa").public_key(),
            common_name="Signed With ML-DSA-44",
            serial=0x44,
            signing_key=issuer_key,
            issuer=_name("ML-DSA-44 Issuer"),
        ).hex()

    certificates["frozen-mldsa-44-signed"] = bytes.fromhex(_frozen("certificate:mldsa-44-signed", _mldsa_signed))
    certificates["malformed-der"] = certificates["generated-ec-p256"][:40]
    certificates["generated-rsa-pss-sha256"] = certificate(
        ec_key("subject-under-rsa-pss").public_key(),
        common_name="Signed With RSASSA-PSS",
        serial=0x55,
        signing_key=rsa_key("issuer-rsa"),
        issuer=_name("RSA Issuer"),
        algorithm=hashes.SHA256(),
        # A zero-length salt keeps the signature, and so the record, byte-stable.
        rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0),
    )
    certificates["generated-ecdsa-sha3-256"] = certificate(
        ec_key("subject-under-ecdsa-sha3").public_key(),
        common_name="Signed With ECDSA-SHA3-256",
        serial=0x53,
        signing_key=ec_key("issuer-ec"),
        issuer=_name("EC Issuer"),
        algorithm=hashes.SHA3_256(),
        ecdsa_deterministic=True,
    )
    certificates["generated-rsa-sha3-256"] = certificate(
        ec_key("subject-under-rsa-sha3").public_key(),
        common_name="Signed With RSA-SHA3-256",
        serial=0x54,
        signing_key=rsa_key("issuer-rsa"),
        issuer=_name("RSA Issuer"),
        algorithm=hashes.SHA3_256(),
        rsa_padding=padding.PKCS1v15(),
    )
    return certificates


def captured_certificates() -> dict[str, bytes]:
    """The byte-stable device captures already in the test tree."""

    import base64

    from tests.app.decoder import real_vectors
    from tests.fido2.attestation.test_attestation import _GSR2_DER

    found = {"gsr2-root": _GSR2_DER}
    for name, statement in (
        ("tpm", real_vectors.TPM_WINDOWS_HELLO_ATT_STMT),
        ("fido-u2f", real_vectors.FIDO_U2F_ATT_STMT),
        ("packed", real_vectors.PACKED_ATT_STMT),
        ("apple", real_vectors.APPLE_ATT_STMT),
    ):
        for index, der in enumerate(statement["x5c"]):
            found[f"{name}-{index}"] = bytes(der)

    jws = bytes(real_vectors.ANDROID_SAFETYNET_ATT_STMT["response"]).decode("ascii")
    header_b64 = jws.split(".")[0]
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    for index, entry in enumerate(header["x5c"]):
        found[f"safetynet-{index}"] = base64.b64decode(entry)

    android_key = cbor.decode(real_vectors.WEBAUTHN_L3_ANDROID_KEY_ATTESTATION_OBJECT)
    for index, der in enumerate(android_key["attStmt"]["x5c"]):
        found[f"android-key-{index}"] = bytes(der)

    make_credential = cbor.decode(real_vectors.MAKE_CREDENTIAL_RESPONSE)
    for index, der in enumerate(make_credential[3]["x5c"]):
        found[f"ctap-make-credential-{index}"] = bytes(der)
    return found


def captured_attestation_objects() -> dict[str, bytes]:
    """Attestation objects built from captured statements, for ``extract_attestation_details``."""

    from tests.app.decoder import real_vectors

    objects = {
        "tpm": real_vectors.attestation_object(
            "tpm", real_vectors.TPM_WINDOWS_HELLO_ATT_STMT, real_vectors.TPM_WINDOWS_HELLO_AUTH_DATA
        ),
        "fido-u2f": real_vectors.attestation_object(
            "fido-u2f", real_vectors.FIDO_U2F_ATT_STMT, real_vectors.FIDO_U2F_AUTH_DATA
        ),
        "packed": real_vectors.attestation_object("packed", real_vectors.PACKED_ATT_STMT, real_vectors.PACKED_AUTH_DATA),
        "apple": real_vectors.attestation_object("apple", real_vectors.APPLE_ATT_STMT, real_vectors.APPLE_AUTH_DATA),
        "android-safetynet": real_vectors.attestation_object(
            "android-safetynet", real_vectors.ANDROID_SAFETYNET_ATT_STMT, real_vectors.ANDROID_SAFETYNET_AUTH_DATA
        ),
        "android-key": real_vectors.WEBAUTHN_L3_ANDROID_KEY_ATTESTATION_OBJECT,
        "packed-self": real_vectors.WEBAUTHN_L3_PACKED_SELF_ATTESTATION_OBJECT,
        "none": real_vectors.attestation_object("none", real_vectors.NONE_ATT_STMT, real_vectors.NONE_AUTH_DATA),
    }
    return objects
