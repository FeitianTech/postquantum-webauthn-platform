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

from asn1crypto import core as asn1_core
from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from dataclasses import dataclass
from enum import IntEnum, unique
from functools import wraps
from typing import Any, List, Mapping, Optional, Sequence, Type

from ..cose import describe_mldsa_oid, extract_certificate_public_key_info
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


MLDSA_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}


if not hasattr(asn1_keys.PublicKeyInfo, "_fido2_original_public_key_spec"):
    asn1_keys.PublicKeyInfo._fido2_original_public_key_spec = (
        asn1_keys.PublicKeyInfo._public_key_spec
    )

    def _public_key_spec_with_mldsa(self):  # type: ignore[override]
        try:
            return asn1_keys.PublicKeyInfo._fido2_original_public_key_spec(self)
        except KeyError:
            algorithm_oid = self["algorithm"]["algorithm"].dotted
            if algorithm_oid in MLDSA_OIDS:
                return asn1_core.BitString, None
            raise

    asn1_keys.PublicKeyInfo._public_key_spec = _public_key_spec_with_mldsa
    asn1_keys.PublicKeyInfo._spec_callbacks["public_key"] = _public_key_spec_with_mldsa

RSA_PUBLIC_KEY_OIDS = {
    "1.2.840.113549.1.1.1",
}

EC_PUBLIC_KEY_OIDS = {
    "1.2.840.10045.2.1",
}


def _extract_certificate_oids(cert_der: bytes) -> tuple[str, str]:
    cert = asn1_x509.Certificate.load(cert_der)
    signature_algorithm_oid = cert["signature_algorithm"]["algorithm"].dotted
    subject_public_key_algorithm_oid = (
        cert["tbs_certificate"]["subject_public_key_info"]["algorithm"]["algorithm"].dotted
    )
    return signature_algorithm_oid, subject_public_key_algorithm_oid


@catch_builtins
def _verify_mldsa_certificate_signature(
    child_cert: x509.Certificate, issuer_der: bytes, signature_oid: str
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

    try:
        info = extract_certificate_public_key_info(issuer_der)
    except Exception as exc:  # pragma: no cover - defensive guard
        raise InvalidSignature(f"Unable to parse issuer public key: {exc}") from exc

    public_key = info.get("subject_public_key")
    if not isinstance(public_key, (bytes, bytearray, memoryview)):
        raise InvalidSignature("Issuer subject public key missing from certificate")

    try:  # pragma: no cover - optional dependency
        import oqs  # type: ignore
    except (ImportError, SystemExit) as exc:  # pragma: no cover - handled by caller
        raise InvalidSignature(
            "ML-DSA certificate verification requires the 'oqs' package"
        ) from exc

    message = bytes(child_cert.tbs_certificate_bytes)
    signature = bytes(child_cert.signature)
    public_key_bytes = bytes(public_key)

    try:  # pragma: no cover - depends on oqs runtime availability
        with oqs.Signature(parameter_set) as verifier:  # type: ignore[attr-defined]
            if not verifier.verify(message, signature, public_key_bytes):
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
    certs = [
        (x509.load_der_x509_certificate(der, default_backend()), der)
        for der in chain
    ]
    cert, cert_der = certs.pop(0)
    while certs:
        child_cert, child_der = cert, cert_der
        cert, cert_der = certs.pop(0)
        issuer_cert, issuer_der = cert, cert_der

        child_signature_oid, _ = _extract_certificate_oids(child_der)
        _, issuer_spki_oid = _extract_certificate_oids(issuer_der)

        try:
            if (
                child_signature_oid in MLDSA_OIDS
                and issuer_spki_oid in MLDSA_OIDS
            ):
                print("ML-DSA is used")
                _verify_mldsa_certificate_signature(
                    child_cert, issuer_der, child_signature_oid
                )
            else:
                try:
                    pub = issuer_cert.public_key()
                except ValueError:
                    pub = None

                if issuer_spki_oid in RSA_PUBLIC_KEY_OIDS and isinstance(
                    pub, rsa.RSAPublicKey
                ):
                    print("RSA is used")
                    assert child_cert.signature_hash_algorithm is not None  # nosec
                    pub.verify(
                        child_cert.signature,
                        child_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        child_cert.signature_hash_algorithm,
                    )
                elif issuer_spki_oid in EC_PUBLIC_KEY_OIDS and isinstance(
                    pub, ec.EllipticCurvePublicKey
                ):
                    print("ec is used")
                    assert child_cert.signature_hash_algorithm is not None  # nosec
                    pub.verify(
                        child_cert.signature,
                        child_cert.tbs_certificate_bytes,
                        ec.ECDSA(child_cert.signature_hash_algorithm),
                    )
                else:
                    raise ValueError("Unsupported OID")
        except _InvalidSignature:
            raise InvalidSignature()

        cert, cert_der = issuer_cert, issuer_der


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
