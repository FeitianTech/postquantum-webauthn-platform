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
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Type

from asn1crypto import core as asn1_core
from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
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
    issuer_name: bytes
    subject_name: bytes
    serial_number: bytes
    authority_key_identifier: Optional[bytes]
    subject_key_identifier: Optional[bytes]
    is_ca: Optional[bool]
    has_aaguid_extension: bool


X509ChainVerifier = Callable[[List[bytes]], None]


MLDSA_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

_MLDSA_ASN1_NAMES = {oid: name.lower().replace("-", "_") for oid, name in MLDSA_OIDS.items()}


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

_PARSED_CERTIFICATE_IDENTITIES: Dict[Tuple[bytes, bytes, bytes], _ParsedCertificate] = {}

_PARSED_CERTIFICATE_DER_IDENTITIES: Dict[bytes, Tuple[bytes, bytes, bytes]] = {}

_ASN1CRYPTO_MLDSA_PATCHED = False


def _ensure_asn1crypto_supports_mldsa() -> None:
    global _ASN1CRYPTO_MLDSA_PATCHED
    if _ASN1CRYPTO_MLDSA_PATCHED:
        return

    for oid, name in _MLDSA_ASN1_NAMES.items():
        asn1_keys.PublicKeyAlgorithmId._map.setdefault(oid, name)
        asn1_keys.PublicKeyAlgorithm._oid_specs.setdefault(name, None)

    original_spec = asn1_keys.PublicKeyInfo._public_key_spec

    def _public_key_spec_with_mldsa(self):  # type: ignore[override]
        algorithm_name = self['algorithm']['algorithm'].native
        if algorithm_name in _MLDSA_ASN1_NAMES.values():
            return (asn1_core.OctetBitString, None)
        return original_spec(self)

    asn1_keys.PublicKeyInfo._public_key_spec = _public_key_spec_with_mldsa  # type: ignore[assignment]
    asn1_keys.PublicKeyInfo._spec_callbacks['public_key'] = _public_key_spec_with_mldsa

    _ASN1CRYPTO_MLDSA_PATCHED = True


def _bit_string_value(bit_string: asn1_core.Asn1Value) -> bytes:
    """Return the raw bytes for a BIT STRING-like ASN.1 value."""

    native = getattr(bit_string, "native", None)
    if isinstance(native, (bytes, bytearray, memoryview)):
        return bytes(native)

    contents = bit_string.contents
    if not contents:
        return b""

    # BIT STRING values (including OctetBitString) encode the number of unused bits
    # as the first content byte. Tag 0x03 identifies the BIT STRING universal tag.
    tag = getattr(bit_string, "tag", None)
    if tag == 3:
        unused_bits = contents[0]
        if unused_bits:
            raise ValueError("Unexpected unused bits in BIT STRING value")
        return bytes(contents[1:])

    return bytes(contents)


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


def _update_cached_identity(
    identity: Tuple[bytes, bytes, bytes],
    parsed: _ParsedCertificate,
) -> None:
    for der, der_identity in list(_PARSED_CERTIFICATE_DER_IDENTITIES.items()):
        if der_identity == identity:
            _PARSED_CERTIFICATE_CACHE[der] = parsed


def _register_parsed_certificate(
    cert_der: bytes,
    identity: Tuple[bytes, bytes, bytes],
    parsed: _ParsedCertificate,
) -> _ParsedCertificate:
    cert_der_key = bytes(cert_der)
    _PARSED_CERTIFICATE_DER_IDENTITIES[cert_der_key] = identity

    existing = _PARSED_CERTIFICATE_IDENTITIES.get(identity)
    if existing is None:
        _PARSED_CERTIFICATE_IDENTITIES[identity] = parsed
        return parsed

    def _is_mldsa_certificate(cert: _ParsedCertificate) -> bool:
        return (
            cert.signature_algorithm_oid in MLDSA_OIDS
            or cert.subject_public_key_algorithm_oid in MLDSA_OIDS
        )

    existing_is_mldsa = _is_mldsa_certificate(existing)
    parsed_is_mldsa = _is_mldsa_certificate(parsed)

    if parsed_is_mldsa and not existing_is_mldsa:
        print("[DEBUG] Replacing cached certificate metadata with ML-DSA identity match")
        _PARSED_CERTIFICATE_IDENTITIES[identity] = parsed
        _update_cached_identity(identity, parsed)
        return parsed

    if existing_is_mldsa and not parsed_is_mldsa:
        print("[DEBUG] Preserving ML-DSA metadata for certificate identity")
        _update_cached_identity(identity, existing)
        return existing

    if (
        existing.signature_algorithm_oid != parsed.signature_algorithm_oid
        or existing.subject_public_key_algorithm_oid
        != parsed.subject_public_key_algorithm_oid
    ):
        print(
            "[DEBUG] Certificate identity encountered with differing OIDs;",
            " keeping existing metadata",
        )
        _update_cached_identity(identity, existing)
        return existing

    _update_cached_identity(identity, existing)
    return existing


def _select_parent_candidate(
    child_parsed: _ParsedCertificate,
    candidates: List[bytes],
    parsed_map: Mapping[bytes, _ParsedCertificate],
    normalized_order: Sequence[bytes],
) -> Optional[bytes]:
    if not candidates:
        return None

    authority_key_identifier = child_parsed.authority_key_identifier
    if authority_key_identifier is not None:
        aki_matches = [
            candidate
            for candidate in candidates
            if parsed_map[candidate].subject_key_identifier == authority_key_identifier
        ]
        if aki_matches:
            candidates = aki_matches

    ca_candidates = [
        candidate for candidate in candidates if parsed_map[candidate].is_ca is not False
    ]
    if ca_candidates:
        candidates = ca_candidates

    for der in normalized_order:
        if der in candidates:
            return der
    return candidates[0]


def _build_chain_from_leaf(
    leaf: bytes,
    normalized_order: Sequence[bytes],
    parsed_map: Mapping[bytes, _ParsedCertificate],
    subject_to_ders: Mapping[bytes, List[bytes]],
) -> List[bytes]:
    ordered = [leaf]
    used = {leaf}
    current = leaf

    while True:
        current_parsed = parsed_map[current]
        issuer_name = current_parsed.issuer_name
        if issuer_name == current_parsed.subject_name:
            break

        parent_candidates = [
            candidate
            for candidate in subject_to_ders.get(issuer_name, [])
            if candidate not in used
        ]
        parent = _select_parent_candidate(
            current_parsed, parent_candidates, parsed_map, normalized_order
        )
        if parent is None:
            break

        ordered.append(parent)
        used.add(parent)
        current = parent

    return ordered


def _order_certificate_chain(chain: Sequence[bytes]) -> List[bytes]:
    normalized = [_coerce_der_bytes(cert) for cert in chain]
    if not normalized:
        return []

    parsed_map = {der: _get_parsed_certificate(der) for der in normalized}
    subject_to_ders: Dict[bytes, List[bytes]] = {}
    for der, parsed in parsed_map.items():
        subject_to_ders.setdefault(parsed.subject_name, []).append(der)

    leaf_candidates = [
        der
        for der, parsed in parsed_map.items()
        if parsed.is_ca is False or parsed.has_aaguid_extension
    ]
    if not leaf_candidates:
        issuer_names = {parsed.issuer_name for parsed in parsed_map.values()}
        leaf_candidates = [
            der for der, parsed in parsed_map.items() if parsed.subject_name not in issuer_names
        ]
    if not leaf_candidates:
        leaf_candidates = [normalized[0]]

    best_chain: Optional[List[bytes]] = None
    for leaf in leaf_candidates:
        candidate_chain = _build_chain_from_leaf(
            leaf, normalized, parsed_map, subject_to_ders
        )
        if best_chain is None or len(candidate_chain) > len(best_chain):
            best_chain = candidate_chain
        if len(candidate_chain) == len(parsed_map):
            return candidate_chain

    if best_chain is None or len(best_chain) != len(parsed_map):
        raise ValueError("Unable to determine certificate chain order")

    return best_chain


def _parse_certificate(cert_der: bytes) -> _ParsedCertificate:
    _ensure_asn1crypto_supports_mldsa()

    cert = asn1_x509.Certificate.load(cert_der)
    tbs = cert['tbs_certificate']

    tbs_certificate = tbs.dump()
    signature_algorithm_oid = tbs['signature']['algorithm'].dotted

    signature_value = _bit_string_value(cert['signature_value'])

    spki = tbs['subject_public_key_info']
    subject_public_key_algorithm_oid = spki['algorithm']['algorithm'].dotted
    subject_public_key = _bit_string_value(spki['public_key'])

    issuer_name = tbs['issuer'].dump()
    subject_name = tbs['subject'].dump()
    serial_number = bytes(tbs['serial_number'].contents)

    identity: Tuple[bytes, bytes, bytes] = (issuer_name, subject_name, serial_number)

    authority_key_identifier: Optional[bytes] = None
    subject_key_identifier: Optional[bytes] = None
    is_ca: Optional[bool] = None
    has_aaguid = False

    extensions = tbs['extensions'] if 'extensions' in tbs else None
    if extensions is not None:
        for extension in extensions:
            oid = extension['extn_id'].dotted
            if oid == '2.5.29.14':
                subject_key_identifier = bytes(extension['extn_value'].parsed.native)
            elif oid == '2.5.29.35':
                aki_data = extension['extn_value'].parsed.native
                key_identifier = aki_data.get('key_identifier') if aki_data else None
                if key_identifier is not None:
                    authority_key_identifier = bytes(key_identifier)
            elif oid == '2.5.29.19':
                basic_constraints = extension['extn_value'].parsed.native
                if not basic_constraints:
                    is_ca = False
                else:
                    is_ca = bool(basic_constraints.get('ca', False))
            elif oid == '1.3.6.1.4.1.45724.1.1.4':
                has_aaguid = True

    parsed = _ParsedCertificate(
        tbs_certificate=bytes(tbs_certificate),
        signature_algorithm_oid=signature_algorithm_oid,
        signature_value=bytes(signature_value),
        subject_public_key_algorithm_oid=subject_public_key_algorithm_oid,
        subject_public_key=bytes(subject_public_key),
        issuer_name=bytes(issuer_name),
        subject_name=bytes(subject_name),
        serial_number=serial_number,
        authority_key_identifier=authority_key_identifier,
        subject_key_identifier=subject_key_identifier,
        is_ca=is_ca,
        has_aaguid_extension=has_aaguid,
    )

    return _register_parsed_certificate(cert_der, identity, parsed)


def _verify_ordered_chain(ordered_chain: Sequence[bytes], *, log_prefix: str) -> None:
    if len(ordered_chain) <= 1:
        return

    for child_der, issuer_der in zip(ordered_chain, ordered_chain[1:]):
        child_parsed = _get_parsed_certificate(child_der)
        child_signature_oid = child_parsed.signature_algorithm_oid
        print(
            f"{log_prefix}: cached child signatureAlgorithm OID from DER",
            child_signature_oid,
        )
        signature_class = SIGNATURE_ALGORITHM_OIDS.get(child_signature_oid)
        if signature_class is None:
            raise ValueError(f"Unsupported signature algorithm OID: {child_signature_oid}")
        print(
            f"{log_prefix}: classified child signature algorithm",
            signature_class,
        )

        issuer_parsed = _get_parsed_certificate(issuer_der)
        issuer_spki_oid = issuer_parsed.subject_public_key_algorithm_oid
        print(
            f"{log_prefix}: cached issuer SubjectPublicKeyInfo algorithm OID",
            issuer_spki_oid,
        )

        if signature_class == "MLDSA":
            print(f"[DEBUG] Saved OID from DER: {child_signature_oid}")
            if issuer_spki_oid not in MLDSA_OIDS:
                raise ValueError("Issuer public key OID does not match ML-DSA parameter set")
            print(
                f"{log_prefix}: issuer SPKI recognized as ML-DSA OID",
                issuer_spki_oid,
            )
            print(
                f"{log_prefix}: using ML-DSA verifier for signature OID",
                child_signature_oid,
            )
            print("[DEBUG] Routing directly to ML-DSA verifier")
            _verify_mldsa_certificate_signature(
                child_parsed.tbs_certificate,
                child_parsed.signature_value,
                issuer_parsed.subject_public_key,
                child_signature_oid,
            )
        elif signature_class == "RSA":
            if issuer_spki_oid not in RSA_PUBLIC_KEY_OIDS:
                raise ValueError("Issuer public key OID does not match RSA algorithm")
            print(
                f"{log_prefix}: issuer SPKI recognized as RSA OID",
                issuer_spki_oid,
            )
            print(
                f"{log_prefix}: using RSA verifier for signature OID",
                child_signature_oid,
            )
            issuer_cert = x509.load_der_x509_certificate(issuer_der, default_backend())
            pub = issuer_cert.public_key()
            if not isinstance(pub, rsa.RSAPublicKey):
                raise ValueError("Issuer public key is not RSA")
            print(
                f"{log_prefix}: cryptography issuer public key type",
                type(pub).__name__,
            )
            hash_algorithm = _hash_for_signature_oid(child_signature_oid)
            child_cert_for_debug = x509.load_der_x509_certificate(child_der, default_backend())
            cryptography_sig_oid = getattr(
                getattr(child_cert_for_debug, "signature_algorithm_oid", None),
                "dotted_string",
                None,
            )
            if cryptography_sig_oid:
                print(
                    f"{log_prefix}: cryptography reported child signatureAlgorithm OID",
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
                raise ValueError("Issuer public key OID does not match EC algorithm")
            print(
                f"{log_prefix}: issuer SPKI recognized as EC OID",
                issuer_spki_oid,
            )
            print(
                f"{log_prefix}: using EC verifier for signature OID",
                child_signature_oid,
            )
            issuer_cert = x509.load_der_x509_certificate(issuer_der, default_backend())
            pub = issuer_cert.public_key()
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                raise ValueError("Issuer public key is not EC")
            print(
                f"{log_prefix}: cryptography issuer public key type",
                type(pub).__name__,
            )
            hash_algorithm = _hash_for_signature_oid(child_signature_oid)
            child_cert_for_debug = x509.load_der_x509_certificate(child_der, default_backend())
            cryptography_sig_oid = getattr(
                getattr(child_cert_for_debug, "signature_algorithm_oid", None),
                "dotted_string",
                None,
            )
            if cryptography_sig_oid:
                print(
                    f"{log_prefix}: cryptography reported child signatureAlgorithm OID",
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
    ordered_chain = _order_certificate_chain(chain)
    try:
        _verify_ordered_chain(ordered_chain, log_prefix="verify_x509_chain")
    except _InvalidSignature:
        raise InvalidSignature()



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

        chain: List[bytes] = result.trust_path + [ca]

        try:
            verify_x509_chain(chain)
        except (InvalidSignature, ValueError) as e:
            raise UntrustedAttestation(e)

    def __call__(self, *args):
        """Allows passing an instance to Fido2Server as verify_attestation"""
        self.verify_attestation(*args)
