from __future__ import annotations

import base64
import binascii
from typing import Any, Dict, List, Mapping, Optional, Tuple


def _coerce_attestation_certificate_bytes(value: Any) -> Optional[bytes]:
    """Return raw certificate bytes for attestation payload *value*."""

    if value in (None, ""):
        return None

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)

    if isinstance(value, ByteBuffer):
        return value.getvalue()

    if isinstance(value, str):
        cleaned = "".join(value.split())
        if not cleaned:
            return None
        padding = (-len(cleaned)) % 4
        padded = cleaned + ("=" * padding)
        try:
            return base64.b64decode(padded)
        except (binascii.Error, ValueError):
            try:
                return websafe_decode(cleaned)
            except Exception:
                return None

    if isinstance(value, Mapping):
        raw_value = value.get("raw")
        if isinstance(raw_value, str):
            cleaned = "".join(raw_value.split())
            try:
                return bytes.fromhex(cleaned)
            except ValueError:
                pass

        der_base64 = value.get("derBase64") or value.get("der_base64")
        if isinstance(der_base64, str):
            cleaned = "".join(der_base64.split())
            padding = (-len(cleaned)) % 4
            try:
                return base64.b64decode(cleaned + ("=" * padding))
            except (binascii.Error, ValueError):
                pass

        pem_value = value.get("pem")
        if isinstance(pem_value, str):
            lines = [
                line.strip()
                for line in pem_value.splitlines()
                if "-----" not in line
            ]
            body = "".join(lines)
            if body:
                padding = (-len(body)) % 4
                try:
                    return base64.b64decode(body + ("=" * padding))
                except (binascii.Error, ValueError):
                    pass

    try:
        return bytes(value)
    except (TypeError, ValueError):
        return None


def extract_attestation_details(
    response: Any,
) -> Tuple[
    str,
    Dict[str, Any],
    Optional[str],
    Optional[str],
    Dict[str, Any],
    Optional[Dict[str, Any]],
    List[Dict[str, Any]],
]:
    """Parse attestation information from a registration response structure."""
    attestation_format = "none"
    attestation_statement: Dict[str, Any] = {}
    attestation_object_b64: Optional[str] = None
    client_data_b64: Optional[str] = None
    client_extension_results: Dict[str, Any] = {}
    attestation_certificate: Optional[Dict[str, Any]] = None
    attestation_certificates: List[Dict[str, Any]] = []

    if not isinstance(response, dict):
        return (
            attestation_format,
            attestation_statement,
            attestation_object_b64,
            client_data_b64,
            client_extension_results,
            attestation_certificate,
            attestation_certificates,
        )

    try:
        registration = RegistrationResponse.from_dict(response)
    except Exception as exc:  # pragma: no cover - debugging aid
        print(f"[DEBUG] Failed to parse registration response for attestation: {exc}")
        return (
            attestation_format,
            attestation_statement,
            attestation_object_b64,
            client_data_b64,
            client_extension_results,
            attestation_certificate,
            attestation_certificates,
        )

    attestation_object = registration.response.attestation_object
    attestation_format = getattr(attestation_object, "fmt", None) or "none"
    attestation_statement = attestation_object.att_stmt or {}
    attestation_object_b64 = encode_base64url(bytes(attestation_object))

    if isinstance(attestation_statement, Mapping):
        cert_chain = attestation_statement.get("x5c") or []
        if isinstance(cert_chain, (list, tuple)) and cert_chain:
            for entry in cert_chain:
                certificate_bytes = _coerce_attestation_certificate_bytes(entry)
                if certificate_bytes is None:
                    attestation_certificates.append({
                        "error": "Unable to decode attestation certificate bytes.",
                    })
                    continue

                try:
                    certificate_details = serialize_attestation_certificate(certificate_bytes)
                except Exception as cert_error:  # pragma: no cover - defensive
                    certificate_details = {"error": str(cert_error)}
                else:
                    if certificate_details is None:
                        certificate_details = {
                            "error": "Unable to parse attestation certificate.",
                        }

                attestation_certificates.append(certificate_details)

            if attestation_certificates:
                attestation_certificate = attestation_certificates[0]

    client_data = registration.response.client_data
    client_data_b64 = getattr(client_data, "b64", None)
    if client_data_b64 is None:
        client_data_b64 = encode_base64url(bytes(client_data))

    extension_outputs = registration.client_extension_results
    if extension_outputs:
        if isinstance(extension_outputs, dict):
            client_extension_results = extension_outputs
        elif isinstance(extension_outputs, Mapping):
            client_extension_results = dict(extension_outputs)
        else:
            client_extension_results = extension_outputs  # type: ignore[assignment]

    return (
        attestation_format,
        attestation_statement,
        attestation_object_b64,
        client_data_b64,
        client_extension_results,
        attestation_certificate,
        attestation_certificates,
    )
