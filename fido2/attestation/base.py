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
from typing import Any, List, Mapping, Optional, Sequence, Type

from cryptography import x509
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from ..cose import describe_mldsa_oid
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


def _parse_der_length(data: memoryview, idx: int) -> tuple[int, int]:
    if idx >= len(data):
        raise ValueError("Invalid DER length: truncated data")
    first = data[idx]
    idx += 1
    if first & 0x80 == 0:
        return first, idx
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("Indefinite length DER encodings are not supported")
    if idx + num_bytes > len(data):
        raise ValueError("Invalid DER length: truncated data")
    length = int.from_bytes(data[idx : idx + num_bytes], "big")
    idx += num_bytes
    return length, idx


def _skip_der_value(data: memoryview, idx: int) -> int:
    if idx >= len(data):
        raise ValueError("Truncated DER element")
    idx += 1
    length, idx = _parse_der_length(data, idx)
    end = idx + length
    if end > len(data):
        raise ValueError("DER element overruns buffer")
    return end


def _decode_oid_body(body: bytes) -> str:
    if not body:
        raise ValueError("OBJECT IDENTIFIER body is empty")
    first = body[0]
    oid_numbers = [str(first // 40), str(first % 40)]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80:
            continue
        oid_numbers.append(str(value))
        value = 0
    if body[-1] & 0x80:
        raise ValueError("Invalid OBJECT IDENTIFIER continuation byte")
    if value:
        oid_numbers.append(str(value))
    return ".".join(oid_numbers)


def _parse_bit_string(data: memoryview, idx: int) -> tuple[bytes, int]:
    if idx >= len(data) or data[idx] != 0x03:
        raise ValueError("Expected BIT STRING tag")
    idx += 1
    length, idx = _parse_der_length(data, idx)
    end = idx + length
    if end > len(data) or length == 0:
        raise ValueError("Invalid BIT STRING length")
    unused_bits = data[idx]
    if unused_bits != 0:
        raise ValueError("Unsupported BIT STRING with unused bits")
    value = bytes(data[idx + 1 : end])
    return value, end


def _parse_algorithm_identifier(
    data: memoryview, idx: int
) -> tuple[str, int]:
    if idx >= len(data) or data[idx] != 0x30:
        raise ValueError("AlgorithmIdentifier must be a SEQUENCE")
    idx += 1
    seq_len, idx = _parse_der_length(data, idx)
    end = idx + seq_len
    if end > len(data):
        raise ValueError("AlgorithmIdentifier overruns buffer")
    if idx >= end or data[idx] != 0x06:
        raise ValueError("AlgorithmIdentifier missing OBJECT IDENTIFIER")
    idx += 1
    oid_len, idx = _parse_der_length(data, idx)
    oid_end = idx + oid_len
    if oid_end > end or oid_len <= 0:
        raise ValueError("Invalid OBJECT IDENTIFIER length")
    oid = _decode_oid_body(bytes(data[idx:oid_end]))
    idx = oid_end
    # Skip optional parameters if present.
    idx = end
    return oid, idx


def _parse_certificate(cert_der: bytes) -> _ParsedCertificate:
    view = memoryview(cert_der)
    idx = 0
    if not view or view[idx] != 0x30:
        raise ValueError("Certificate must be a DER SEQUENCE")
    idx += 1
    cert_len, idx = _parse_der_length(view, idx)
    end = idx + cert_len
    if end > len(view):
        raise ValueError("Certificate length exceeds buffer size")

    if idx >= end or view[idx] != 0x30:
        raise ValueError("Certificate missing TBSCertificate")
    tbs_start = idx
    tbs_end = _skip_der_value(view, idx)
    tbs_certificate = bytes(view[tbs_start:tbs_end])
    idx = tbs_end

    signature_algorithm_oid, idx = _parse_algorithm_identifier(view, idx)
    signature_value, idx = _parse_bit_string(view, idx)

    if idx != end:
        raise ValueError("Certificate parsing did not consume full structure")

    return _ParsedCertificate(
        tbs_certificate=tbs_certificate,
        signature_algorithm_oid=signature_algorithm_oid,
        signature_value=signature_value,
    )


def _extract_subject_public_key_info(cert_der: bytes) -> tuple[str, bytes]:
    parsed = _parse_certificate(cert_der)
    view = memoryview(parsed.tbs_certificate)
    idx = 0
    if not view or view[idx] != 0x30:
        raise ValueError("TBSCertificate must be a DER SEQUENCE")
    idx += 1
    seq_len, idx = _parse_der_length(view, idx)
    end = idx + seq_len
    if end > len(view):
        raise ValueError("TBSCertificate length exceeds buffer size")

    if idx < end and view[idx] == 0xA0:
        idx = _skip_der_value(view, idx)

    for _ in range(5):
        idx = _skip_der_value(view, idx)

    if idx >= end or view[idx] != 0x30:
        raise ValueError("TBSCertificate missing SubjectPublicKeyInfo")
    idx += 1
    spki_len, idx = _parse_der_length(view, idx)
    spki_end = idx + spki_len
    if spki_end > end:
        raise ValueError("SubjectPublicKeyInfo overruns TBSCertificate")

    algorithm_oid, idx = _parse_algorithm_identifier(view, idx)
    public_key_bytes, idx = _parse_bit_string(view, idx)

    if idx != spki_end:
        raise ValueError("SubjectPublicKeyInfo parsing did not consume structure")

    return algorithm_oid, public_key_bytes


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


def verify_x509_chain(chain: List[bytes]) -> None:
    """Verifies a chain of certificates.

    Checks that the first item in the chain is signed by the next, and so on.
    The first item is the leaf, the last is the root.
    """

    if not chain:
        return

    remaining = list(chain)
    child_der = remaining.pop(0)

    while remaining:
        issuer_der = remaining.pop(0)
        child_parsed = _parse_certificate(child_der)
        child_signature_oid = child_parsed.signature_algorithm_oid
        print(
            "verify_x509_chain: raw child signatureAlgorithm OID from DER",
            child_signature_oid,
        )
        signature_class = SIGNATURE_ALGORITHM_OIDS.get(child_signature_oid)
        if signature_class is None:
            raise ValueError(f"Unsupported signature algorithm OID: {child_signature_oid}")
        print(
            "verify_x509_chain: classified child signature algorithm",
            signature_class,
        )

        issuer_spki_oid, issuer_public_key = _extract_subject_public_key_info(issuer_der)
        print(
            "verify_x509_chain: raw issuer SubjectPublicKeyInfo algorithm OID",
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
                child_cert = x509.load_der_x509_certificate(
                    child_der, default_backend()
                )
                cryptography_sig_oid = getattr(
                    getattr(child_cert, "signature_algorithm_oid", None),
                    "dotted_string",
                    None,
                )
                if cryptography_sig_oid:
                    print(
                        "verify_x509_chain: cryptography reported child signatureAlgorithm OID",
                        cryptography_sig_oid,
                    )
                hash_algorithm = child_cert.signature_hash_algorithm
                if hash_algorithm is None:
                    raise ValueError("Child certificate missing signature hash algorithm")
                pub.verify(
                    child_cert.signature,
                    child_cert.tbs_certificate_bytes,
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
                child_cert = x509.load_der_x509_certificate(
                    child_der, default_backend()
                )
                cryptography_sig_oid = getattr(
                    getattr(child_cert, "signature_algorithm_oid", None),
                    "dotted_string",
                    None,
                )
                if cryptography_sig_oid:
                    print(
                        "verify_x509_chain: cryptography reported child signatureAlgorithm OID",
                        cryptography_sig_oid,
                    )
                hash_algorithm = child_cert.signature_hash_algorithm
                if hash_algorithm is None:
                    raise ValueError("Child certificate missing signature hash algorithm")
                pub.verify(
                    child_cert.signature,
                    child_cert.tbs_certificate_bytes,
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
