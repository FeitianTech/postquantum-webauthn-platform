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
    issuer_name: bytes
    subject_name: bytes
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


def _parsed_length(info: tuple[Any, ...]) -> int:
    """Return the encoded length for a parsed ASN.1 element."""

    header, content, trailer = info[3], info[4], info[5]
    return len(header) + len(content) + len(trailer)


def _encoded_value(info: tuple[Any, ...]) -> bytes:
    """Return the full encoding (header+content+trailer) of an ASN.1 element."""

    return bytes(info[3] + info[4] + info[5])


def _parse_extension_value(
    oid: str,
    value_bytes: bytes,
    *,
    current_is_ca: Optional[bool],
    current_has_aaguid: bool,
    current_subject_key_identifier: Optional[bytes],
    current_authority_key_identifier: Optional[bytes],
) -> tuple[Optional[bool], bool, Optional[bytes], Optional[bytes]]:
    is_ca = current_is_ca
    has_aaguid = current_has_aaguid
    subject_key_identifier = current_subject_key_identifier
    authority_key_identifier = current_authority_key_identifier

    if oid == "2.5.29.19":  # BasicConstraints
        info = asn1_parser.parse(value_bytes)
        if info[2] != 16:
            raise ValueError("BasicConstraints extension must be a SEQUENCE")
        content = info[4]
        if not content:
            is_ca = False
        else:
            offset = 0
            field_info = asn1_parser.parse(content[offset:])
            if field_info[2] == 1:
                is_ca = field_info[4] != b"\x00"
            else:
                is_ca = False
    elif oid == "2.5.29.14":  # SubjectKeyIdentifier
        info = asn1_parser.parse(value_bytes)
        if info[2] != 4:
            raise ValueError("SubjectKeyIdentifier must be an OCTET STRING")
        subject_key_identifier = bytes(info[4])
    elif oid == "2.5.29.35":  # AuthorityKeyIdentifier
        info = asn1_parser.parse(value_bytes)
        if info[2] != 16:
            raise ValueError("AuthorityKeyIdentifier must be a SEQUENCE")
        content = info[4]
        offset = 0
        while offset < len(content):
            field_info = asn1_parser.parse(content[offset:])
            offset += _parsed_length(field_info)
            if field_info[0] == 2 and field_info[2] == 0:
                authority_key_identifier = bytes(field_info[4])
                break
    elif oid == "1.3.6.1.4.1.45724.1.1.4":  # AAGUID extension
        info = asn1_parser.parse(value_bytes)
        if info[2] != 4:
            raise ValueError("AAGUID extension must be an OCTET STRING")
        has_aaguid = True

    return is_ca, has_aaguid, subject_key_identifier, authority_key_identifier


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

    tbs_content = tbs_info[4]
    offset = 0

    version_info = asn1_parser.parse(tbs_content[offset:])
    if version_info[0] == 2 and version_info[2] == 0:
        offset += _parsed_length(version_info)

    # serialNumber
    serial_info = asn1_parser.parse(tbs_content[offset:])
    offset += _parsed_length(serial_info)

    # signature
    signature_field_info = asn1_parser.parse(tbs_content[offset:])
    offset += _parsed_length(signature_field_info)

    issuer_info = asn1_parser.parse(tbs_content[offset:])
    issuer_name = _encoded_value(issuer_info)
    offset += _parsed_length(issuer_info)

    # validity
    validity_info = asn1_parser.parse(tbs_content[offset:])
    offset += _parsed_length(validity_info)

    subject_info = asn1_parser.parse(tbs_content[offset:])
    subject_name = _encoded_value(subject_info)
    offset += _parsed_length(subject_info)

    spki_info = asn1_parser.parse(tbs_content[offset:])
    if spki_info[0] != 0 or spki_info[1] != 1 or spki_info[2] != 16:
        raise ValueError("TBSCertificate missing SubjectPublicKeyInfo")
    offset += _parsed_length(spki_info)

    spki_content = spki_info[4]
    algorithm_info = asn1_parser.parse(spki_content)
    if algorithm_info[0] != 0 or algorithm_info[1] != 1 or algorithm_info[2] != 16:
        raise ValueError("SubjectPublicKeyInfo missing AlgorithmIdentifier")
    oid_info = asn1_parser.parse(algorithm_info[4])
    if oid_info[2] != 6:
        raise ValueError("AlgorithmIdentifier missing OBJECT IDENTIFIER")
    subject_public_key_algorithm_oid = asn1_core.ObjectIdentifier.load(
        oid_info[3] + oid_info[4]
    ).dotted

    algorithm_len = _parsed_length(algorithm_info)
    bitstring_info = asn1_parser.parse(spki_content[algorithm_len:])
    if bitstring_info[2] != 3:
        raise ValueError("SubjectPublicKeyInfo missing public key BIT STRING")
    if not bitstring_info[4]:
        raise ValueError("Invalid BIT STRING length")
    if bitstring_info[4][0] != 0:
        raise ValueError("Unsupported BIT STRING with unused bits")
    subject_public_key = bytes(bitstring_info[4][1:])

    authority_key_identifier: Optional[bytes] = None
    subject_key_identifier: Optional[bytes] = None
    is_ca: Optional[bool] = None
    has_aaguid = False

    while offset < len(tbs_content):
        field_info = asn1_parser.parse(tbs_content[offset:])
        tag_class, tag_number = field_info[0], field_info[2]
        if tag_class == 2 and tag_number in (1, 2):
            offset += _parsed_length(field_info)
            continue
        if tag_class == 2 and tag_number == 3:
            extensions_info = asn1_parser.parse(field_info[4])
            if extensions_info[0] != 0 or extensions_info[1] != 1 or extensions_info[2] != 16:
                raise ValueError("Extensions must be a DER SEQUENCE")
            extensions_content = extensions_info[4]
            ext_offset = 0
            while ext_offset < len(extensions_content):
                extension_info = asn1_parser.parse(extensions_content[ext_offset:])
                ext_offset += _parsed_length(extension_info)
                extension_sequence = extension_info[4]
                entry_offset = 0
                oid_info = asn1_parser.parse(extension_sequence[entry_offset:])
                if oid_info[2] != 6:
                    raise ValueError("Extension missing OBJECT IDENTIFIER")
                extension_oid = asn1_core.ObjectIdentifier.load(
                    oid_info[3] + oid_info[4]
                ).dotted
                entry_offset += _parsed_length(oid_info)
                value_info = asn1_parser.parse(extension_sequence[entry_offset:])
                if value_info[2] == 1:  # critical boolean
                    entry_offset += _parsed_length(value_info)
                    value_info = asn1_parser.parse(extension_sequence[entry_offset:])
                if value_info[2] != 4:
                    raise ValueError("Extension extnValue must be an OCTET STRING")
                (
                    is_ca,
                    has_aaguid,
                    subject_key_identifier,
                    authority_key_identifier,
                ) = _parse_extension_value(
                    extension_oid,
                    value_info[4],
                    current_is_ca=is_ca,
                    current_has_aaguid=has_aaguid,
                    current_subject_key_identifier=subject_key_identifier,
                    current_authority_key_identifier=authority_key_identifier,
                )
            offset += _parsed_length(field_info)
            continue
        raise ValueError("Unexpected field in TBSCertificate")

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
        issuer_name=issuer_name,
        subject_name=subject_name,
        authority_key_identifier=authority_key_identifier,
        subject_key_identifier=subject_key_identifier,
        is_ca=is_ca,
        has_aaguid_extension=has_aaguid,
    )


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
