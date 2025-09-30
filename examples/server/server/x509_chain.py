"""Server-specific X.509 chain verification utilities."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Sequence, Tuple

from asn1crypto import core as asn1_core
from asn1crypto import parser as asn1_parser
from cryptography import x509
from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from fido2.attestation.base import InvalidSignature, set_x509_chain_verifier
from fido2.cose import describe_mldsa_oid
from fido2.utils import ByteBuffer


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

SIGNATURE_ALGORITHM_OIDS = {
    "2.16.840.1.101.3.4.3.17": "MLDSA",
    "2.16.840.1.101.3.4.3.18": "MLDSA",
    "2.16.840.1.101.3.4.3.19": "MLDSA",
    "1.2.840.113549.1.1.5": "RSA",
    "1.2.840.113549.1.1.11": "RSA",
    "1.2.840.113549.1.1.12": "RSA",
    "1.2.840.113549.1.1.13": "RSA",
    "1.2.840.10045.4.3.2": "EC",
    "1.2.840.10045.4.3.3": "EC",
    "1.2.840.10045.4.3.4": "EC",
}

RSA_PUBLIC_KEY_OIDS = {"1.2.840.113549.1.1.1"}
EC_PUBLIC_KEY_OIDS = {"1.2.840.10045.2.1"}
MLDSA_PUBLIC_KEY_OIDS = set(MLDSA_OIDS)


def _coerce_der_bytes(value: Any) -> bytes:
    if isinstance(value, ByteBuffer):
        return value.getvalue()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(
        "Certificate chain entries must be DER-encoded bytes, "
        f"not {type(value).__name__}"
    )


def _parsed_length(info: Tuple[Any, ...]) -> int:
    header, content, trailer = info[3], info[4], info[5]
    return len(header) + len(content) + len(trailer)


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
    )


def _extract_subject_public_key_info(cert_der: bytes) -> Tuple[str, bytes]:
    parsed = _parse_certificate(cert_der)
    tbs_info = asn1_parser.parse(parsed.tbs_certificate)
    if tbs_info[0] != 0 or tbs_info[1] != 1 or tbs_info[2] != 16:
        raise ValueError("TBSCertificate must be a DER SEQUENCE")

    tbs_content = tbs_info[4]
    offset = 0

    version_info = asn1_parser.parse(tbs_content[offset:])
    if version_info[0] == 2 and version_info[2] == 0:
        offset += _parsed_length(version_info)

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


def _verify_mldsa_certificate_signature(
    tbs_certificate: bytes, signature: bytes, issuer_public_key: bytes, signature_oid: str
) -> None:
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


def _hash_for_signature_oid(signature_oid: str):
    if signature_oid in RSA_SIGNATURE_HASHES:
        return RSA_SIGNATURE_HASHES[signature_oid]()
    if signature_oid in EC_SIGNATURE_HASHES:
        return EC_SIGNATURE_HASHES[signature_oid]()
    raise ValueError(f"Unsupported hash mapping for signature OID: {signature_oid}")


def _server_verify_x509_chain(chain: Sequence[bytes]) -> None:
    if not chain:
        return

    remaining: List[bytes] = [_coerce_der_bytes(cert) for cert in chain]
    child_der = remaining.pop(0)

    while remaining:
        issuer_der = remaining.pop(0)
        child_parsed = _parse_certificate(child_der)
        child_signature_oid = child_parsed.signature_algorithm_oid
        print(
            "server verify_x509_chain: raw child signatureAlgorithm OID from DER",
            child_signature_oid,
        )
        signature_class = SIGNATURE_ALGORITHM_OIDS.get(child_signature_oid)
        if signature_class is None:
            raise ValueError(f"Unsupported signature algorithm OID: {child_signature_oid}")
        print(
            "server verify_x509_chain: classified child signature algorithm",
            signature_class,
        )

        issuer_spki_oid, issuer_public_key = _extract_subject_public_key_info(issuer_der)
        print(
            "server verify_x509_chain: raw issuer SubjectPublicKeyInfo algorithm OID",
            issuer_spki_oid,
        )

        try:
            if signature_class == "MLDSA":
                print(
                    "server verify_x509_chain: using ML-DSA verifier for signature OID",
                    child_signature_oid,
                )
                if issuer_spki_oid not in MLDSA_PUBLIC_KEY_OIDS:
                    raise ValueError(
                        "Issuer public key OID does not match ML-DSA parameter set"
                    )
                print(
                    "server verify_x509_chain: issuer SPKI recognized as ML-DSA OID",
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
                    "server verify_x509_chain: issuer SPKI recognized as RSA OID",
                    issuer_spki_oid,
                )
                print(
                    "server verify_x509_chain: using RSA verifier for signature OID",
                    child_signature_oid,
                )
                issuer_cert = x509.load_der_x509_certificate(issuer_der, default_backend())
                pub = issuer_cert.public_key()
                if not isinstance(pub, rsa.RSAPublicKey):
                    raise ValueError("Issuer public key is not RSA")
                print(
                    "server verify_x509_chain: cryptography issuer public key type",
                    type(pub).__name__,
                )
                hash_algorithm = _hash_for_signature_oid(child_signature_oid)
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
                    "server verify_x509_chain: issuer SPKI recognized as EC OID",
                    issuer_spki_oid,
                )
                print(
                    "server verify_x509_chain: using EC verifier for signature OID",
                    child_signature_oid,
                )
                issuer_cert = x509.load_der_x509_certificate(issuer_der, default_backend())
                pub = issuer_cert.public_key()
                if not isinstance(pub, ec.EllipticCurvePublicKey):
                    raise ValueError("Issuer public key is not EC")
                print(
                    "server verify_x509_chain: cryptography issuer public key type",
                    type(pub).__name__,
                )
                hash_algorithm = _hash_for_signature_oid(child_signature_oid)
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


set_x509_chain_verifier(_server_verify_x509_chain)


def verify_x509_chain(chain: Sequence[bytes]) -> None:
    """Expose the server-specific verifier for direct use in tests."""

    _server_verify_x509_chain(chain)


__all__ = [
    "MLDSA_OIDS",
    "SIGNATURE_ALGORITHM_OIDS",
    "verify_x509_chain",
]
