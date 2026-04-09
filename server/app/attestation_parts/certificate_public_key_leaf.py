from __future__ import annotations

import base64
from typing import Any, Dict, List, Mapping, Optional, Tuple


def _load_oqs_signature_details(mechanism: str) -> Optional[Dict[str, Any]]:
    """Retrieve signature metadata for *mechanism* from liboqs when available."""

    try:  # pragma: no cover - exercised when oqs bindings are installed
        import oqs  # type: ignore
    except (ImportError, SystemExit):  # pragma: no cover - absence handled by caller
        return None

    try:  # pragma: no cover - defensive handling around oqs interaction
        with oqs.Signature(mechanism) as signature:  # type: ignore[attr-defined]
            details = getattr(signature, "details", None)
    except BaseException:
        return None

    if not isinstance(details, Mapping):
        return None

    normalized: Dict[str, Any] = {str(key): value for key, value in details.items()}
    normalized["mechanism"] = mechanism
    return normalized


def _build_unknown_public_key_info(cert_bytes: bytes, error: Exception) -> Tuple[Dict[str, Any], List[Tuple[str, Any]]]:
    try:
        parsed = extract_certificate_public_key_info(cert_bytes)
    except Exception:
        parsed = {}

    algorithm_details: Dict[str, Any] = {"name": "Unknown"}
    public_key_bytes = parsed.get("subject_public_key")
    wrapped_public_key_bytes = parsed.get("wrapped_subject_public_key")
    spki_bytes = parsed.get("subject_public_key_info")

    if isinstance(parsed.get("algorithm_name"), str):
        algorithm_details["name"] = parsed["algorithm_name"]
    if isinstance(parsed.get("algorithm_oid"), str):
        algorithm_details["oid"] = parsed["algorithm_oid"]

    oqs_details: Optional[Mapping[str, Any]] = None
    parameter_set = parsed.get("ml_dsa_parameter_set")
    if isinstance(parameter_set, str):
        algorithm_details["mlDsaParameterSet"] = parameter_set
        oqs_details = _load_oqs_signature_details(parameter_set)
        if isinstance(oqs_details, Mapping):
            claimed_level = oqs_details.get("claimed-nist-level")
            if claimed_level is not None:
                algorithm_details["claimedNistLevel"] = claimed_level
            length_signature = oqs_details.get("length-signature")
            if isinstance(length_signature, int):
                algorithm_details["signatureLengthBytes"] = length_signature
    parameters = parsed.get("algorithm_parameters")
    if isinstance(parameters, (bytes, bytearray)) and parameters:
        algorithm_details["parametersHex"] = bytes(parameters).hex()

    info: Dict[str, Any] = {
        "type": algorithm_details.get("name", "Unsupported"),
        "algorithm": algorithm_details,
    }

    if isinstance(spki_bytes, (bytes, bytearray)) and spki_bytes:
        info["subjectPublicKeyInfoBase64"] = base64.b64encode(bytes(spki_bytes)).decode("ascii")

    key_size_bits: Optional[int] = None
    raw_bytes: Optional[bytes] = None
    if isinstance(public_key_bytes, (bytes, bytearray)):
        candidate = bytes(public_key_bytes)
        if candidate:
            raw_bytes = candidate
            info["publicKeyBase64"] = base64.b64encode(raw_bytes).decode("ascii")
            info["publicKeyHex"] = colon_hex(raw_bytes)
            info["publicKeyHexLines"] = format_hex_bytes_lines(raw_bytes)
            key_size_bits = len(raw_bytes) * 8

    if isinstance(wrapped_public_key_bytes, (bytes, bytearray)):
        wrapped_bytes = bytes(wrapped_public_key_bytes)
        if wrapped_bytes and (raw_bytes is None or wrapped_bytes != raw_bytes):
            info["wrappedPublicKeyBase64"] = base64.b64encode(wrapped_bytes).decode("ascii")
            info["wrappedPublicKeyHexLines"] = format_hex_bytes_lines(wrapped_bytes)

    if isinstance(oqs_details, Mapping):
        length_public_key = oqs_details.get("length-public-key")
        if isinstance(length_public_key, int) and length_public_key > 0:
            key_size_bits = length_public_key * 8
        for field in ("description", "sig-name", "sig-family"):
            value = oqs_details.get(field)
            if value:
                info_key = {
                    "description": "mechanismDescription",
                    "sig-name": "mechanismName",
                    "sig-family": "mechanismFamily",
                }.get(field)
                if info_key:
                    info[info_key] = value

    if key_size_bits:
        info["keySize"] = key_size_bits

    summary_entries: List[Tuple[str, Any]] = []

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

    if not summary_entries and "error" not in info:
        info["error"] = str(error)
        summary_entries.append(("Error", str(error)))

    return info, summary_entries


def _serialize_public_key_info(public_key: Any) -> Dict[str, Any]:
    info = {
        "type": public_key.__class__.__name__,
        "keySize": getattr(public_key, "key_size", None),
        "subjectPublicKeyInfoBase64": base64.b64encode(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode("ascii"),
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
                "uncompressedPoint": colon_hex(
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
                "publicKeyHex": colon_hex(
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
