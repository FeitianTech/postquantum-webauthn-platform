# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import annotations

import abc

from dataclasses import dataclass
from enum import IntEnum, unique
from functools import wraps
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Type

from asn1crypto import core as asn1_core
from asn1crypto import parser as asn1_parser
from cryptography import x509
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from ..cose import describe_mldsa_oid
from ..utils import ByteBuffer
from ..webauthn import AttestationObject, AuthenticatorData


class InvalidAttestation(Exception):
    """Base exception for attestation-related errors."""


class InvalidData(InvalidAttestation):
    """Attestation contains invalid data."""


class InvalidSignature(InvalidAttestation):
    """The signature of the attestation could not be verified."""


class UntrustedAttestation(InvalidAttestation):
    """The CA of the attestation is not trusted."""


class UnsupportedType(InvalidAttestation):
    """The attestation format is not supported."""

    def __init__(self, auth_data, fmt=None):
        super().__init__(
            f'Attestation format "{fmt}" is not supported'
            if fmt
            else "This attestation format is not supported!"
        )
        self.auth_data = auth_data
        self.fmt = fmt


@unique
class AttestationType(IntEnum):
    """Supported attestation types."""

    BASIC = 1
    SELF = 2
    ATT_CA = 3
    ANON_CA = 4
    NONE = 0


@dataclass
class AttestationResult:
    """The result of verifying an attestation."""

    attestation_type: AttestationType
    trust_path: List[bytes]

    def __post_init__(self) -> None:
        normalized: List[bytes] = []
        for index, entry in enumerate(self.trust_path):
            der_bytes = _coerce_der_bytes(entry)
            parsed = _get_parsed_certificate(der_bytes)
            print(
                "AttestationResult: trust_path[%d] signatureAlgorithm OID %s"
                % (index, parsed.signature_algorithm_oid)
            )
            print(
                "AttestationResult: trust_path[%d] SubjectPublicKeyInfo algorithm OID %s"
                % (index, parsed.subject_public_key_algorithm_oid)
            )
            normalized.append(der_bytes)

        self.trust_path = normalized


def catch_builtins(f):
    """Utility decoractor to wrap common exceptions related to InvalidData."""

    @wraps(f)
    def inner(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (ValueError, KeyError, IndexError) as e:
            raise InvalidData(e)

    return inner


@dataclass
class _ParsedCertificate:
    tbs_certificate: bytes
    signature_algorithm_oid: str
    signature_value: bytes
    subject_public_key_algorithm_oid: str
    subject_public_key: bytes


X509ChainVerifier = Callable[[List[bytes]], None]


MLDSA_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}


RSA_PUBLIC_KEY_OIDS = {
    "1.2.840.113549.1.1.1",
}

EC_PUBLIC_KEY_OIDS = {
    "1.2.840.10045.2.1",
}


SIGNATURE_ALGORITHM_OIDS = {
    # ML-DSA parameter set OIDs are reused for their signatures.
    "2.16.840.1.101.3.4.3.17": "MLDSA",
    "2.16.840.1.101.3.4.3.18": "MLDSA",
    "2.16.840.1.101.3.4.3.19": "MLDSA",
    # RSA signature algorithms
    "1.2.840.113549.1.1.5": "RSA",  # sha1WithRSAEncryption
    "1.2.840.113549.1.1.11": "RSA",  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": "RSA",  # sha384WithRSAEncryption
    "1.2.840.113549.1.1.13": "RSA",  # sha512WithRSAEncryption
    # ECDSA signature algorithms
    "1.2.840.10045.4.3.2": "EC",  # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": "EC",  # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4": "EC",  # ecdsa-with-SHA512
}


RSA_SIGNATURE_HASHES = {
    "1.2.840.113549.1.1.5": hashes.SHA1,
    "1.2.840.113549.1.1.11": hashes.SHA256,
    "1.2.840.113549.1.1.12": hashes.SHA384,
    "1.2.840.113549.1.1.13": hashes.SHA512,
}


EC_SIGNATURE_HASHES = {
    "1.2.840.10045.4.3.2": hashes.SHA256,
    "1.2.840.10045.4.3.3": hashes.SHA384,
    "1.2.840.10045.4.3.4": hashes.SHA512,
}


def _hash_for_signature_oid(signature_oid: str) -> hashes.HashAlgorithm:
    if signature_oid in RSA_SIGNATURE_HASHES:
        return RSA_SIGNATURE_HASHES[signature_oid]()
    if signature_oid in EC_SIGNATURE_HASHES:
        return EC_SIGNATURE_HASHES[signature_oid]()
    raise ValueError(f"Unsupported hash mapping for signature OID: {signature_oid}")


_custom_x509_chain_verifier: Optional[X509ChainVerifier] = None


_PARSED_CERTIFICATE_CACHE: Dict[bytes, _ParsedCertificate] = {}


def _get_parsed_certificate(cert_der: bytes) -> _ParsedCertificate:
    cached = _PARSED_CERTIFICATE_CACHE.get(cert_der)
    if cached is None:
        cached = _parse_certificate(cert_der)
        _PARSED_CERTIFICATE_CACHE[cert_der] = cached
    return cached


def _coerce_der_bytes(value: Any) -> bytes:
    if isinstance(value, ByteBuffer):
        return value.getvalue()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(
        "Certificate chain entries must be DER-encoded bytes, "
        f"not {type(value).__name__}"
    )


def _parsed_length(info: tuple[Any, ...]) -> int:
    """Return the encoded length for a parsed ASN.1 element."""

    header, content, trailer = info[3], info[4], info[5]
    return len(header) + len(content) + len(trailer)


def _parse_subject_public_key_info_from_tbs(tbs_certificate: bytes) -> tuple[str, bytes]:
    tbs_info = asn1_parser.parse(tbs_certificate)
    if tbs_info[0] != 0 or tbs_info[1] != 1 or tbs_info[2] != 16:
        raise ValueError("TBSCertificate must be a DER SEQUENCE")

    tbs_content = tbs_info[4]
    offset = 0

    # Optional version field is [0] EXPLICIT
    version_info = asn1_parser.parse(tbs_content[offset:])
    if version_info[0] == 2 and version_info[2] == 0:
        offset += _parsed_length(version_info)

    # serialNumber, signature, issuer, validity, subject
    for _ in range(5):
        field_info = asn1_parser.parse(tbs_content[offset:])
        offset += _parsed_length(field_info)

    spki_info = asn1_parser.parse(tbs_content[offset:])
    if spki_info[0] != 0 or spki_info[1] != 1 or spki_info[2] != 16:
        raise ValueError("TBSCertificate missing SubjectPublicKeyInfo")

    spki_content = spki_info[4]

    algorithm_info = asn1_parser.parse(spki_content)
    if algorithm_info[0] != 0 or algorithm_info[1] != 1 or algorithm_info[2] != 16:
        raise ValueError("SubjectPublicKeyInfo missing AlgorithmIdentifier")
    oid_info = asn1_parser.parse(algorithm_info[4])
    if oid_info[2] != 6:
        raise ValueError("AlgorithmIdentifier missing OBJECT IDENTIFIER")
    algorithm_oid = asn1_core.ObjectIdentifier.load(oid_info[3] + oid_info[4]).dotted

    algorithm_len = _parsed_length(algorithm_info)
    bitstring_info = asn1_parser.parse(spki_content[algorithm_len:])
    if bitstring_info[2] != 3:
        raise ValueError("SubjectPublicKeyInfo missing public key BIT STRING")
    if not bitstring_info[4]:
        raise ValueError("Invalid BIT STRING length")
    unused_bits = bitstring_info[4][0]
    if unused_bits != 0:
        raise ValueError("Unsupported BIT STRING with unused bits")
    public_key_bytes = bitstring_info[4][1:]

    return algorithm_oid, bytes(public_key_bytes)


def _parse_certificate(cert_der: bytes) -> _ParsedCertificate:
    cert_info = asn1_parser.parse(cert_der)
    if cert_info[0] != 0 or cert_info[1] != 1 or cert_info[2] != 16:
        raise ValueError("Certificate must be a DER SEQUENCE")

    remaining = cert_info[4]

    tbs_info = asn1_parser.parse(remaining)
    if tbs_info[0] != 0 or tbs_info[1] != 1 or tbs_info[2] != 16:
        raise ValueError("Certificate missing TBSCertificate")
    tbs_len = _parsed_length(tbs_info)
    tbs_certificate = remaining[:tbs_len]
    remaining = remaining[tbs_len:]

    subject_public_key_algorithm_oid, subject_public_key = (
        _parse_subject_public_key_info_from_tbs(tbs_certificate)
    )

    sig_alg_info = asn1_parser.parse(remaining)
    if sig_alg_info[0] != 0 or sig_alg_info[1] != 1 or sig_alg_info[2] != 16:
        raise ValueError("Certificate missing signature AlgorithmIdentifier")
    sig_alg_len = _parsed_length(sig_alg_info)
    sig_alg_content = sig_alg_info[4]

    oid_info = asn1_parser.parse(sig_alg_content)
    if oid_info[2] != 6:
        raise ValueError("AlgorithmIdentifier missing OBJECT IDENTIFIER")
    signature_algorithm_oid = asn1_core.ObjectIdentifier.load(
        oid_info[3] + oid_info[4]
    ).dotted

    remaining = remaining[sig_alg_len:]

    signature_info = asn1_parser.parse(remaining)
    if signature_info[2] != 3:
        raise ValueError("Certificate missing signature BIT STRING")
    if not signature_info[4]:
        raise ValueError("Invalid BIT STRING length")
    unused_bits = signature_info[4][0]
    if unused_bits != 0:
        raise ValueError("Unsupported BIT STRING with unused bits")
    signature_value = signature_info[4][1:]

    remaining = remaining[_parsed_length(signature_info) :]
    if remaining:
        raise ValueError("Certificate parsing did not consume full structure")

    return _ParsedCertificate(
        tbs_certificate=bytes(tbs_certificate),
        signature_algorithm_oid=signature_algorithm_oid,
        signature_value=bytes(signature_value),
        subject_public_key_algorithm_oid=subject_public_key_algorithm_oid,
        subject_public_key=subject_public_key,
    )


def _extract_subject_public_key_info(cert_der: bytes) -> tuple[str, bytes]:
    parsed = _get_parsed_certificate(cert_der)
    return parsed.subject_public_key_algorithm_oid, parsed.subject_public_key


@catch_builtins
def _verify_mldsa_certificate_signature(
    tbs_certificate: bytes, signature: bytes, issuer_public_key: bytes, signature_oid: str
) -> None:
    """Verify an ML-DSA signed certificate using liboqs."""

    mldsa_details = describe_mldsa_oid(signature_oid)
    if not mldsa_details:
        raise InvalidSignature(
            f"Unsupported signature algorithm OID for ML-DSA verification: {signature_oid}"
        )

    parameter_set = mldsa_details.get("mlDsaParameterSet") or mldsa_details.get(
        "ml_dsa_parameter_set"
    )
    if not parameter_set:
        raise InvalidSignature(
            "Unable to determine ML-DSA parameter set for certificate signature"
        )
    print("_verify_mldsa_certificate_signature: ML-DSA parameter set", parameter_set)

    try:  # pragma: no cover - optional dependency
        import oqs  # type: ignore
    except (ImportError, SystemExit) as exc:  # pragma: no cover - handled by caller
        raise InvalidSignature(
            "ML-DSA certificate verification requires the 'oqs' package"
        ) from exc

    message = bytes(tbs_certificate)
    signature_bytes = bytes(signature)
    public_key_bytes = bytes(issuer_public_key)

    try:  # pragma: no cover - depends on oqs runtime availability
        with oqs.Signature(parameter_set) as verifier:  # type: ignore[attr-defined]
            if not verifier.verify(message, signature_bytes, public_key_bytes):
                raise InvalidSignature("ML-DSA certificate signature verification failed")
    except InvalidSignature:
        raise
    except Exception as exc:  # pragma: no cover - defensive guard
        raise InvalidSignature(f"ML-DSA certificate verification error: {exc}") from exc


def set_x509_chain_verifier(verifier: Optional[X509ChainVerifier]) -> None:
    """Register a custom verifier invoked by :func:`verify_x509_chain`."""

    global _custom_x509_chain_verifier
    _custom_x509_chain_verifier = verifier


def verify_x509_chain(chain: List[bytes]) -> None:
    """Verifies a chain of certificates.

    Checks that the first item in the chain is signed by the next, and so on.
    The first item is the leaf, the last is the root.
    """

    if _custom_x509_chain_verifier is not None:
        _custom_x509_chain_verifier(chain)
        return

    _default_verify_x509_chain(chain)


def _default_verify_x509_chain(chain: List[bytes]) -> None:
    if not chain:
        return

    remaining = [_coerce_der_bytes(cert) for cert in chain]
    child_der = remaining.pop(0)

    while remaining:
        issuer_der = remaining.pop(0)
        child_parsed = _get_parsed_certificate(child_der)
        child_signature_oid = child_parsed.signature_algorithm_oid
        print(
            "verify_x509_chain: cached child signatureAlgorithm OID from DER",
            child_signature_oid,
        )
        signature_class = SIGNATURE_ALGORITHM_OIDS.get(child_signature_oid)
        if signature_class is None:
            raise ValueError(f"Unsupported signature algorithm OID: {child_signature_oid}")
        print(
            "verify_x509_chain: classified child signature algorithm",
            signature_class,
        )

        issuer_parsed = _get_parsed_certificate(issuer_der)
        issuer_spki_oid = issuer_parsed.subject_public_key_algorithm_oid
        issuer_public_key = issuer_parsed.subject_public_key
        print(
            "verify_x509_chain: cached issuer SubjectPublicKeyInfo algorithm OID",
            issuer_spki_oid,
        )

        try:
            if signature_class == "MLDSA":
                print(
                    "verify_x509_chain: using ML-DSA verifier for signature OID",
                    child_signature_oid,
                )
                if issuer_spki_oid not in MLDSA_OIDS:
                    raise ValueError(
                        "Issuer public key OID does not match ML-DSA parameter set"
                    )
                print(
                    "verify_x509_chain: issuer SPKI recognized as ML-DSA OID",
                    issuer_spki_oid,
                )
                _verify_mldsa_certificate_signature(
                    child_parsed.tbs_certificate,
                    child_parsed.signature_value,
                    issuer_public_key,
                    child_signature_oid,
                )
            elif signature_class == "RSA":
                if issuer_spki_oid not in RSA_PUBLIC_KEY_OIDS:
                    raise ValueError(
                        "Issuer public key OID does not match RSA algorithm"
                    )
                print(
                    "verify_x509_chain: issuer SPKI recognized as RSA OID",
                    issuer_spki_oid,
                )
                print(
                    "verify_x509_chain: using RSA verifier for signature OID",
                    child_signature_oid,
                )
                issuer_cert = x509.load_der_x509_certificate(
                    issuer_der, default_backend()
                )
                pub = issuer_cert.public_key()
                if not isinstance(pub, rsa.RSAPublicKey):
                    raise ValueError("Issuer public key is not RSA")
                print(
                    "verify_x509_chain: cryptography issuer public key type",
                    type(pub).__name__,
                )
                hash_algorithm = _hash_for_signature_oid(child_signature_oid)
                child_cert_for_debug = x509.load_der_x509_certificate(
                    child_der, default_backend()
                )
                cryptography_sig_oid = getattr(
                    getattr(child_cert_for_debug, "signature_algorithm_oid", None),
                    "dotted_string",
                    None,
                )
                if cryptography_sig_oid:
                    print(
                        "verify_x509_chain: cryptography reported child signatureAlgorithm OID",
                        cryptography_sig_oid,
                    )
                pub.verify(
                    child_parsed.signature_value,
                    child_parsed.tbs_certificate,
                    padding.PKCS1v15(),
                    hash_algorithm,
                )
            elif signature_class == "EC":
                if issuer_spki_oid not in EC_PUBLIC_KEY_OIDS:
                    raise ValueError(
                        "Issuer public key OID does not match EC algorithm"
                    )
                print(
                    "verify_x509_chain: issuer SPKI recognized as EC OID",
                    issuer_spki_oid,
                )
                print(
                    "verify_x509_chain: using EC verifier for signature OID",
                    child_signature_oid,
                )
                issuer_cert = x509.load_der_x509_certificate(
                    issuer_der, default_backend()
                )
                pub = issuer_cert.public_key()
                if not isinstance(pub, ec.EllipticCurvePublicKey):
                    raise ValueError("Issuer public key is not EC")
                print(
                    "verify_x509_chain: cryptography issuer public key type",
                    type(pub).__name__,
                )
                hash_algorithm = _hash_for_signature_oid(child_signature_oid)
                child_cert_for_debug = x509.load_der_x509_certificate(
                    child_der, default_backend()
                )
                cryptography_sig_oid = getattr(
                    getattr(child_cert_for_debug, "signature_algorithm_oid", None),
                    "dotted_string",
                    None,
                )
                if cryptography_sig_oid:
                    print(
                        "verify_x509_chain: cryptography reported child signatureAlgorithm OID",
                        cryptography_sig_oid,
                    )
                pub.verify(
                    child_parsed.signature_value,
                    child_parsed.tbs_certificate,
                    ec.ECDSA(hash_algorithm),
                )
            else:  # pragma: no cover - exhaustive safeguard
                raise ValueError(
                    f"Unhandled signature classification for OID: {child_signature_oid}"
                )
        except _InvalidSignature:
            raise InvalidSignature()

        child_der = issuer_der


class Attestation(abc.ABC):
    """Implements verification of a specific attestation type."""

    @abc.abstractmethod
    def verify(
        self,
        statement: Mapping[str, Any],
        auth_data: AuthenticatorData,
        client_data_hash: bytes,
    ) -> AttestationResult:
        """Verifies attestation statement.

        :return: An AttestationResult if successful.
        """

    @staticmethod
    def for_type(fmt: str) -> Type[Attestation]:
        """Get an Attestation subclass type for the given format."""
        for cls in Attestation.__subclasses__():
            if getattr(cls, "FORMAT", None) == fmt:
                return cls

        class TypedUnsupportedAttestation(UnsupportedAttestation):
            def __init__(self):
                super().__init__(fmt)

        return TypedUnsupportedAttestation


class UnsupportedAttestation(Attestation):
    def __init__(self, fmt=None):
        self.fmt = fmt

    def verify(self, statement, auth_data, client_data_hash):
        raise UnsupportedType(auth_data, self.fmt)


class NoneAttestation(Attestation):
    FORMAT = "none"

    def verify(self, statement, auth_data, client_data_hash):
        if statement != {}:
            raise InvalidData("None Attestation requires empty statement.")
        return AttestationResult(AttestationType.NONE, [])


def _validate_cert_common(cert):
    if cert.version != x509.Version.v3:
        raise InvalidData("Attestation certificate must use version 3!")

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            raise InvalidData("Attestation certificate must have CA=false!")
    except x509.ExtensionNotFound:
        raise InvalidData("Attestation certificate must have Basic Constraints!")


def _default_attestations():
    return [
        cls()  # type: ignore
        for cls in Attestation.__subclasses__()
        if getattr(cls, "FORMAT", "none") != "none"
    ]


class AttestationVerifier(abc.ABC):
    """Base class for verifying attestation.

    Override the ca_lookup method to provide a trusted root certificate used
    to verify the trust path from the attestation.
    """

    def __init__(self, attestation_types: Optional[Sequence[Attestation]] = None):
        self._attestation_types = attestation_types or _default_attestations()

    @abc.abstractmethod
    def ca_lookup(
        self, attestation_result: AttestationResult, auth_data: AuthenticatorData
    ) -> Optional[bytes]:
        """Lookup a CA certificate to be used to verify a trust path.

        :param attestation_result: The result of the attestation
        :param auth_data: The AuthenticatorData from the registration
        """
        raise NotImplementedError()

    def verify_attestation(
        self, attestation_object: AttestationObject, client_data_hash: bytes
    ) -> None:
        """Verify attestation.

        :param attestation_object: dict containing attestation data.
        :param client_data_hash: SHA256 hash of the ClientData bytes.
        """
        att_verifier: Attestation = UnsupportedAttestation(attestation_object.fmt)
        for at in self._attestation_types:
            if getattr(at, "FORMAT", None) == attestation_object.fmt:
                att_verifier = at
                break
        # An unsupported format causes an exception to be thrown, which
        # includes the auth_data. The caller may choose to handle this case
        # and allow the registration.
        result = att_verifier.verify(
            attestation_object.att_stmt,
            attestation_object.auth_data,
            client_data_hash,
        )

        # Lookup CA to use for trust path verification
        ca = self.ca_lookup(result, attestation_object.auth_data)
        if not ca:
            raise UntrustedAttestation("No root found for Authenticator")

        # Validate the trust chain
        try:
            verify_x509_chain(result.trust_path + [ca])
        except InvalidSignature as e:
            raise UntrustedAttestation(e)

    def __call__(self, *args):
        """Allows passing an instance to Fido2Server as verify_attestation"""
        self.verify_attestation(*args)
