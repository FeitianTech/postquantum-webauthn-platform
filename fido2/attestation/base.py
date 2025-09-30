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

from ..cose import describe_mldsa_oid, extract_certificate_public_key_info
from ..webauthn import AuthenticatorData, AttestationObject
from enum import IntEnum, unique
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from dataclasses import dataclass
from functools import wraps
from typing import Callable, List, Type, Mapping, Sequence, Optional, Any

import abc
import logging
from typing import Iterable


logger = logging.getLogger(__name__)


def _emit_signature_trace(message: str, *, extra: Iterable[object] = ()) -> None:
    """Emit signature tracing output through both logging and stdout."""

    if extra:
        formatted = message % tuple(extra)
    else:
        formatted = message
    print(formatted)
    logger.info(formatted)


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


@catch_builtins
def _verify_mldsa_certificate_signature(
    child_cert: x509.Certificate, issuer_der: bytes
) -> None:
    """Verify an ML-DSA signed certificate using liboqs."""

    _log_certificate_signature("verify-mldsa.child", child_cert)

    signature_oid = child_cert.signature_algorithm_oid.dotted_string
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

    _emit_signature_trace(
        "ML-DSA certificate verification uses parameter set %s at stage verify-mldsa",
        extra=(parameter_set,),
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

    for index, (loaded_cert, _) in enumerate(certs):
        _log_certificate_signature(f"chain.load[{index}]", loaded_cert)

    cert_index = 0
    cert, cert_der = certs.pop(0)
    while certs:
        child = cert
        child_stage = f"chain.child[{cert_index}]"
        issuer_stage = f"chain.issuer[{cert_index + 1}]"
        _log_certificate_signature(child_stage, child)

        cert, cert_der = certs.pop(0)
        _log_certificate_signature(f"{issuer_stage}.loaded", cert)

        signature_oid = child.signature_algorithm_oid.dotted_string

        if describe_mldsa_oid(signature_oid):
            _emit_signature_trace("%s detected ML-DSA signature", extra=(child_stage,))
            _verify_mldsa_certificate_signature(child, cert_der)
            cert_index += 1
            continue

        try:
            pub = cert.public_key()
        except ValueError:
            _emit_signature_trace(
                "%s issuer public key could not be parsed; falling back to ML-DSA",
                extra=(issuer_stage,),
            )
            pub = None
        try:
            if isinstance(pub, rsa.RSAPublicKey):
                _emit_signature_trace(
                    "%s verifying with RSA issuer key",
                    extra=(child_stage,),
                )
                assert child.signature_hash_algorithm is not None  # nosec
                pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,
                )
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                _emit_signature_trace(
                    "%s verifying with EC issuer key",
                    extra=(child_stage,),
                )
                assert child.signature_hash_algorithm is not None  # nosec
                pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm),
                )
            elif pub is None:
                _emit_signature_trace(
                    "%s issuer public key unavailable; invoking ML-DSA verifier",
                    extra=(child_stage,),
                )
                _verify_mldsa_certificate_signature(child, cert_der)
            else:
                raise ValueError("Unsupported signature key type")
        except _InvalidSignature:
            raise InvalidSignature()

        cert_index += 1


def verify_mldsa_x509_chain(chain: List[bytes]) -> None:
    """Verifies a chain of certificates using ML-DSA for each hop.

    This variant is intended for attestation chains where every signature is
    expected to use an ML-DSA algorithm and classical issuer verification would
    incorrectly downgrade the signature metadata. The caller is responsible for
    supplying the appropriate trust anchor as the final element in ``chain``.
    """

    _emit_signature_trace(
        "Using ML-DSA-only certificate chain verifier for attestation",
    )

    certs = [
        (x509.load_der_x509_certificate(der, default_backend()), der)
        for der in chain
    ]

    for index, (loaded_cert, _) in enumerate(certs):
        _log_certificate_signature(f"chain.load[{index}]", loaded_cert)

    cert_index = 0
    cert, cert_der = certs.pop(0)
    while certs:
        child = cert
        child_stage = f"chain.child[{cert_index}]"
        issuer_stage = f"chain.issuer[{cert_index + 1}]"
        _log_certificate_signature(child_stage, child)

        cert, cert_der = certs.pop(0)
        _log_certificate_signature(f"{issuer_stage}.loaded", cert)

        signature_oid = child.signature_algorithm_oid.dotted_string
        if not describe_mldsa_oid(signature_oid):
            raise InvalidSignature(
                f"Expected ML-DSA signature for {child_stage}, got {signature_oid}"
            )

        _emit_signature_trace(
            "%s verifying with ML-DSA issuer key (testing override)",
            extra=(child_stage,),
        )
        _verify_mldsa_certificate_signature(child, cert_der)
        cert_index += 1


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
        logger.info(
            "Registration start: attestation format=%s", attestation_object.fmt
        )
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

        logger.info(
            "Attestation statement verified for format %s; trust_path length=%d",
            attestation_object.fmt,
            len(result.trust_path),
        )

        for index, cert_bytes in enumerate(result.trust_path):
            try:
                cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
            except Exception as exc:  # pragma: no cover - defensive guard
                logger.info(
                    "registration.trust_path[%d]: unable to load certificate (%s)",
                    index,
                    exc,
                )
                continue
            _log_certificate_signature(f"registration.trust_path[{index}]", cert)

        # Lookup CA to use for trust path verification
        ca = self.ca_lookup(result, attestation_object.auth_data)
        if not ca:
            raise UntrustedAttestation("No root found for Authenticator")

        try:
            ca_cert = x509.load_der_x509_certificate(ca, default_backend())
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.info("registration.ca: unable to load certificate (%s)", exc)
        else:
            _log_certificate_signature("registration.ca", ca_cert)

        # Validate the trust chain
        chain_verifier = self._select_chain_verifier(
            result, attestation_object.auth_data
        )
        try:
            chain_verifier(result.trust_path + [ca])
        except InvalidSignature as e:
            raise UntrustedAttestation(e)
        else:
            logger.info("Registration complete for format %s", attestation_object.fmt)

    def __call__(self, *args):
        """Allows passing an instance to Fido2Server as verify_attestation"""
        self.verify_attestation(*args)

    def _select_chain_verifier(
        self,
        attestation_result: AttestationResult,
        auth_data: AuthenticatorData,
    ) -> Callable[[List[bytes]], None]:
        """Select the function that should verify the certificate chain."""

        return verify_x509_chain


def _log_certificate_signature(stage: str, certificate: x509.Certificate) -> None:
    """Log signature metadata for a certificate at a specific pipeline stage."""

    try:
        signature_oid = certificate.signature_algorithm_oid.dotted_string
    except Exception as exc:  # pragma: no cover - defensive guard
        _emit_signature_trace(
            "Certificate signature [%s]: unable to read signature algorithm (%s)",
            extra=(stage, exc),
        )
        return

    algorithm_name = getattr(certificate.signature_algorithm_oid, "_name", "unknown")
    mldsa_details = describe_mldsa_oid(signature_oid)
    parameter_set = None
    if mldsa_details:
        parameter_set = mldsa_details.get("mlDsaParameterSet") or mldsa_details.get(
            "ml_dsa_parameter_set"
        )

    extra = f", parameter_set={parameter_set}" if parameter_set else ""
    _emit_signature_trace(
        "Certificate signature [%s]: oid=%s, name=%s%s",
        extra=(stage, signature_oid, algorithm_name, extra),
    )

