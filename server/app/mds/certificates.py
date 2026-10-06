"""What an MDS entry's attestation root certificates say, for its explorer row:
their signature algorithms and their subjects' common names."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.x509.oid import NameOID

from .. import encoding
from ..webauthn import signature_algorithms


def decode_der_certificate(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if not isinstance(value, str):
        return None

    if not value.strip():
        return None

    return encoding.try_decode_base64(value)


def summarise_attestation_certificates(certificates: Sequence[Any]) -> tuple[list[str], list[str]]:
    algorithm_infos: list[str] = []
    common_names: list[str] = []
    seen_algorithms = set()
    seen_common_names = set()

    for certificate_value in certificates:
        certificate_bytes = decode_der_certificate(certificate_value)
        if not certificate_bytes:
            continue

        try:
            certificate = x509.load_der_x509_certificate(certificate_bytes)
        except Exception:  # A root that cannot be loaded contributes no summary.
            continue

        try:
            hash_algorithm = certificate.signature_hash_algorithm
        except (UnsupportedAlgorithm, ValueError):
            hash_algorithm = None

        oid = getattr(certificate.signature_algorithm_oid, "_name", None)
        if not isinstance(oid, str) or oid.lower() == "unknown oid":
            oid = getattr(certificate.signature_algorithm_oid, "dotted_string", "") or ""

        # An EdDSA signature has no separate hash: cryptography answers None.
        hash_name = hash_algorithm.name if hash_algorithm is not None else signature_algorithms.implied_hash_name(oid)
        algorithm_info = signature_algorithms.join_algorithm_info(
            signature_algorithms.normalise_signature_algorithm_name(oid), hash_name
        )
        if algorithm_info and algorithm_info.lower() not in seen_algorithms:
            seen_algorithms.add(algorithm_info.lower())
            algorithm_infos.append(algorithm_info)

        try:
            attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        except (TypeError, ValueError):
            # cryptography reads a name only when asked, and refuses one it
            # cannot type (a common name that is not a string).
            attributes = []
        for attribute in attributes:
            common_name = attribute.value.strip()
            if not common_name:
                continue
            key = common_name.lower()
            if key in seen_common_names:
                continue
            seen_common_names.add(key)
            common_names.append(common_name)

    return algorithm_infos, common_names


def certificate_fields(attestation_certificates: list[Any]) -> dict[str, Any]:
    algorithm_info_list, common_name_list = summarise_attestation_certificates(attestation_certificates)
    algorithm_info = ", ".join(algorithm_info_list) if algorithm_info_list else "—"
    common_names = ", ".join(common_name_list) if common_name_list else "—"
    return {
        "certificateAlgorithmInfo": algorithm_info,
        "certificateAlgorithmInfoList": algorithm_info_list,
        "certificateCommonNames": common_names,
        "certificateCommonNameList": common_name_list,
        "algorithmInfo": algorithm_info,
        "commonName": common_names,
    }
