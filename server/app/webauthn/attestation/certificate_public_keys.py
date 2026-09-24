"""How the certificate views describe a certificate's public key.

``_serialize_public_key_info`` covers the key types cryptography loads (EC, RSA,
Ed25519, Ed448; anything else by class name). ``_build_unknown_public_key_info``
is the best effort for a key it will not load, read from the SubjectPublicKeyInfo
by fido2, with ML-DSA's parameter set, NIST level and sizes.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from fido2.cose import extract_certificate_public_key_info

from ...encoding import encode_base64
from . import formatting


def _unknown_key_algorithm(parsed: Mapping[str, Any]) -> tuple[dict[str, Any], Mapping[str, Any] | None, Any]:
    """The algorithm fido2 read from the SPKI, the ML-DSA details, and the ML-DSA parameter set."""

    algorithm_details: dict[str, Any] = {"name": "Unknown"}
    if isinstance(parsed.get("algorithm_name"), str):
        algorithm_details["name"] = parsed["algorithm_name"]
    if isinstance(parsed.get("algorithm_oid"), str):
        algorithm_details["oid"] = parsed["algorithm_oid"]

    mldsa_details: Mapping[str, Any] | None = None
    parameter_set = parsed.get("ml_dsa_parameter_set")
    if isinstance(parameter_set, str):
        algorithm_details["mlDsaParameterSet"] = parameter_set
        candidate = parsed.get("ml_dsa_parameter_details")
        if isinstance(candidate, Mapping):
            mldsa_details = candidate
            claimed_level = candidate.get("claimed_nist_level")
            if claimed_level is not None:
                algorithm_details["claimedNistLevel"] = claimed_level
            length_signature = candidate.get("signature_length")
            if isinstance(length_signature, int):
                algorithm_details["signatureLengthBytes"] = length_signature
    parameters = parsed.get("algorithm_parameters")
    if isinstance(parameters, (bytes, bytearray)) and parameters:
        algorithm_details["parametersHex"] = bytes(parameters).hex()
    return algorithm_details, mldsa_details, parameter_set


def _unknown_key_material(parsed: Mapping[str, Any], info: dict[str, Any]) -> int | None:
    """Add the SPKI, the raw and the wrapped key to ``info``; the raw key's size in bits."""

    public_key_bytes = parsed.get("subject_public_key")
    wrapped_public_key_bytes = parsed.get("wrapped_subject_public_key")
    spki_bytes = parsed.get("subject_public_key_info")

    if isinstance(spki_bytes, (bytes, bytearray)) and spki_bytes:
        info["subjectPublicKeyInfoBase64"] = encode_base64(bytes(spki_bytes))

    key_size_bits: int | None = None
    raw_bytes: bytes | None = None
    if isinstance(public_key_bytes, (bytes, bytearray)):
        candidate = bytes(public_key_bytes)
        if candidate:
            raw_bytes = candidate
            info["publicKeyBase64"] = encode_base64(raw_bytes)
            info["publicKeyHex"] = formatting.colon_hex(raw_bytes)
            info["publicKeyHexLines"] = formatting.format_hex_bytes_lines(raw_bytes)
            key_size_bits = len(raw_bytes) * 8

    if isinstance(wrapped_public_key_bytes, (bytes, bytearray)):
        wrapped_bytes = bytes(wrapped_public_key_bytes)
        if wrapped_bytes and (raw_bytes is None or wrapped_bytes != raw_bytes):
            info["wrappedPublicKeyBase64"] = encode_base64(wrapped_bytes)
            info["wrappedPublicKeyHexLines"] = formatting.format_hex_bytes_lines(wrapped_bytes)
    return key_size_bits


def _unknown_key_summary(
    info: Mapping[str, Any], algorithm_details: Mapping[str, Any], key_size_bits: int | None
) -> list[tuple[str, Any]]:
    summary_entries: list[tuple[str, Any]] = []

    def _append_summary(label: str, value: Any) -> None:
        if value in (None, ""):
            return
        if isinstance(value, list) and not value:
            return
        summary_entries.append((label, value))

    _append_summary("Type", info.get("type"))
    algorithm_name = algorithm_details.get("name")
    if algorithm_name and algorithm_name != info.get("type"):
        _append_summary("Algorithm", algorithm_name)
    _append_summary("Algorithm OID", algorithm_details.get("oid"))
    _append_summary("ML-DSA parameter set", algorithm_details.get("mlDsaParameterSet"))
    _append_summary("Claimed NIST level", algorithm_details.get("claimedNistLevel"))
    _append_summary("Signature length (bytes)", algorithm_details.get("signatureLengthBytes"))
    if key_size_bits:
        _append_summary("Public key size (bits)", key_size_bits)
    _append_summary("Public Key (base64)", info.get("publicKeyBase64"))
    hex_lines = info.get("publicKeyHexLines")
    if isinstance(hex_lines, list) and hex_lines:
        _append_summary("Public Key (hex)", hex_lines)
    wrapped_hex_lines = info.get("wrappedPublicKeyHexLines")
    if isinstance(wrapped_hex_lines, list) and wrapped_hex_lines:
        _append_summary("Wrapped Public Key (hex)", wrapped_hex_lines)
    return summary_entries


def _build_unknown_public_key_info(cert_bytes: bytes, error: Exception) -> tuple[dict[str, Any], list[tuple[str, Any]]]:
    try:
        parsed = extract_certificate_public_key_info(cert_bytes)
    except Exception:
        parsed = {}

    algorithm_details, mldsa_details, parameter_set = _unknown_key_algorithm(parsed)
    info: dict[str, Any] = {
        "type": algorithm_details.get("name", "Unsupported"),
        "algorithm": algorithm_details,
    }
    key_size_bits = _unknown_key_material(parsed, info)

    if isinstance(mldsa_details, Mapping):
        length_public_key = mldsa_details.get("public_key_length")
        if isinstance(length_public_key, int) and length_public_key > 0:
            key_size_bits = length_public_key * 8
        info["mechanismName"] = parameter_set
        info["mechanismFamily"] = "ML-DSA"

    if key_size_bits:
        info["keySize"] = key_size_bits

    summary_entries = _unknown_key_summary(info, algorithm_details, key_size_bits)
    if not summary_entries and "error" not in info:
        info["error"] = str(error)
        summary_entries.append(("Error", str(error)))

    return info, summary_entries


def _serialize_public_key_info(public_key: Any) -> dict[str, Any]:
    info = {
        "type": public_key.__class__.__name__,
        "keySize": getattr(public_key, "key_size", None),
        "subjectPublicKeyInfoBase64": encode_base64(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ),
        "algorithm": {
            "name": None,
        },
    }

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = getattr(public_key.curve, "name", "unknown")
        info.update(
            {
                "type": "ECC",
                "curve": curve_name,
                "uncompressedPoint": formatting.colon_hex(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint,
                    )
                ),
            }
        )
        info["algorithm"].update(
            {
                "name": "ECDSA",
                "namedCurve": curve_name,
            }
        )
    elif isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        modulus_hex = f"0x{numbers.n:x}"
        key_size = getattr(public_key, "key_size", None)
        info.update(
            {
                "type": "RSA",
                "publicExponent": numbers.e,
                "modulusHex": modulus_hex,
            }
        )
        info["algorithm"].update(
            {
                "name": "RSASSA-PKCS1-v1_5",
                "modulusLength": key_size,
            }
        )
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        info.update(
            {
                "type": public_key.__class__.__name__,
                "publicKeyHex": formatting.colon_hex(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                ),
            }
        )
        info["algorithm"].update(
            {
                "name": "EdDSA",
            }
        )

    if not info["algorithm"].get("name"):
        info["algorithm"]["name"] = info.get("type") or public_key.__class__.__name__

    return info
