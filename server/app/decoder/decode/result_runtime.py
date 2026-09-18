"""Decoder payload and result conversion helpers."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ...attestation import make_json_safe, serialize_attestation_certificate
from . import binary, conversion_leaf, summary
from .certificates import (
    _convert_attestation_entry_impl,
    _convert_attestation_statement_impl,
    _convert_certificate_bytes_impl,
    _convert_certificate_chain_impl,
    _convert_certificate_payload_impl,
)
from .keys import hex_json_safe as _hex_json_safe
from .keys import stringify_mapping_keys as _stringify_mapping_keys


def _prepare_decoder_response(result: dict[str, Any]) -> dict[str, Any]:
    return _build_decoder_payload(result)


def _build_decoder_payload(result: dict[str, Any]) -> dict[str, Any]:
    base_type = summary._base_type(result.get("format"))
    data = _convert_result_to_data(base_type, result)
    malformed = result.get("malformed")
    if not isinstance(malformed, list):
        malformed = []

    type_label = base_type
    if base_type == "CBOR":
        decoded = result.get("decoded")
        qualifiers: list[str] = []
        if isinstance(decoded, Mapping):
            ctap_info = decoded.get("ctap")
            if isinstance(ctap_info, Mapping):
                meaning = ctap_info.get("meaning") or ctap_info.get("description")
                if isinstance(meaning, str) and meaning:
                    qualifiers.append(meaning)
            ctap_decoded = decoded.get("ctapDecoded")
            if isinstance(ctap_decoded, Mapping):
                if "makeCredentialResponse" in ctap_decoded:
                    qualifiers.append("MakeCredential response")
                if "getAssertionResponse" in ctap_decoded:
                    qualifiers.append("GetAssertion response")
                if "makeCredentialRequest" in ctap_decoded:
                    qualifiers.append("MakeCredential request")
                if "getAssertionRequest" in ctap_decoded:
                    qualifiers.append("GetAssertion request")
            expanded_json = decoded.get("expandedJson")
            if isinstance(expanded_json, Mapping):
                if "attStmt" in expanded_json and "MakeCredential response" not in qualifiers:
                    qualifiers.append("MakeCredential response")
                if "signature" in expanded_json and "GetAssertion response" not in qualifiers:
                    qualifiers.append("GetAssertion response")
        if qualifiers:
            unique = []
            for qualifier in qualifiers:
                if qualifier not in unique:
                    unique.append(qualifier)
            type_label = f"{base_type} ({'; '.join(unique)})"

    return {
        "success": True,
        "type": type_label,
        "data": data,
        "malformed": malformed,
    }


def _convert_result_to_data(base_type: str, result: dict[str, Any]) -> Any:
    if base_type == "PublicKeyCredential":
        return _convert_public_key_credential_data(result)
    if base_type == "Attestation object":
        return _convert_attestation_object_data(result)
    if base_type == "Authenticator data":
        return _convert_authenticator_data_result(result)
    if base_type == "WebAuthn client data":
        return _convert_client_data_result(result)
    if base_type == "X.509 certificate":
        return _convert_certificate_result(result)
    if base_type == "JSON":
        return {"json": make_json_safe(result.get("decoded"))}
    if base_type == "CBOR":
        decoded = result.get("decoded")
        if isinstance(decoded, Mapping):
            payload: dict[str, Any] = {}
            if "ctapDecoded" in decoded:
                payload["ctapDecoded"] = _stringify_mapping_keys(
                    _hex_json_safe(decoded["ctapDecoded"])
                )
            if "expandedJson" in decoded:
                payload["expandedJson"] = _stringify_mapping_keys(
                    _hex_json_safe(decoded["expandedJson"])
                )
            if "decodedValue" in decoded:
                payload["decodedValue"] = _stringify_mapping_keys(
                    _hex_json_safe(decoded["decodedValue"])
                )
            if "ctap" in decoded:
                payload["ctap"] = _stringify_mapping_keys(make_json_safe(decoded["ctap"]))
            if not payload:
                payload["cbor"] = make_json_safe(decoded)
            return payload
        return {"cbor": make_json_safe(decoded)}

    decoded_value = result.get("decoded")
    if decoded_value is not None:
        return make_json_safe(decoded_value)
    binary_value = result.get("binary")
    if binary_value is not None:
        return make_json_safe(binary_value)
    return {}


def _convert_public_key_credential_data(result: Mapping[str, Any]) -> dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    response = decoded.get("response") if isinstance(decoded, Mapping) else {}

    payload: dict[str, Any] = {}

    credential_overview = conversion_leaf._build_credential_overview(decoded)
    if credential_overview:
        payload["credential"] = credential_overview

    attestation_entry = response.get("attestationObject") if isinstance(response, Mapping) else None
    attestation_section = _convert_attestation_entry(attestation_entry)
    if attestation_section:
        payload["attestationObject"] = attestation_section

    authenticator_section = _build_authenticator_section(
        response, attestation_entry
    )
    if authenticator_section:
        payload["authenticatorData"] = authenticator_section

    client_data_section = conversion_leaf._convert_client_data_entry(
        response.get("clientDataJSON") if isinstance(response, Mapping) else None
    )
    if client_data_section:
        payload["clientDataJSON"] = client_data_section

    client_extensions = decoded.get("clientExtensionResults") if isinstance(decoded, Mapping) else None
    if client_extensions is not None:
        payload["clientExtensionResults"] = make_json_safe(client_extensions)

    response_extras = conversion_leaf._collect_response_extras(response)
    if response_extras:
        payload["responseDetails"] = response_extras

    return payload


def _convert_attestation_object_data(result: Mapping[str, Any]) -> dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}

    attestation_section = _convert_attestation_entry(decoded)
    payload: dict[str, Any] = {}
    if attestation_section:
        if "raw" not in attestation_section:
            binary_info = result.get("binary") if isinstance(result.get("binary"), Mapping) else None
            if isinstance(binary_info, Mapping):
                raw_value = binary_info.get("base64") or binary_info.get("base64url")
                if raw_value:
                    attestation_section["raw"] = raw_value
        payload["attestationObject"] = attestation_section

    authenticator_details = decoded.get("authenticatorData") if isinstance(decoded, Mapping) else None
    authenticator_section = conversion_leaf._build_authenticator_data_payload(
        binary._extract_authenticator_bytes_from_attestation(decoded),
        authenticator_details,
        decoded.get("publicKeyAlgorithm") if isinstance(decoded, Mapping) else None,
    )
    if authenticator_section:
        payload["authenticatorData"] = authenticator_section

    client_extensions = decoded.get("extensions") if isinstance(decoded, Mapping) else None
    if client_extensions:
        payload["extensions"] = make_json_safe(client_extensions)

    return payload


def _convert_authenticator_data_result(result: Mapping[str, Any]) -> dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    result.get("binary")
    auth_bytes = binary._extract_bytes_from_binary(result.get("binary"))
    if auth_bytes is None:
        auth_bytes = binary._extract_bytes_from_binary(decoded)
    authenticator_section = conversion_leaf._build_authenticator_data_payload(
        auth_bytes,
        decoded,
        decoded.get("publicKeyAlgorithm") if isinstance(decoded, Mapping) else None,
    )
    return authenticator_section or {}


def _convert_client_data_result(result: Mapping[str, Any]) -> dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    return conversion_leaf._convert_client_data_entry(decoded) or {}


def _convert_certificate_result(result: Mapping[str, Any]) -> dict[str, Any]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}

    if not decoded:
        return {}

    if "certificates" in decoded and isinstance(decoded["certificates"], list):
        certificates = [
            _convert_certificate_payload(entry) for entry in decoded["certificates"] if isinstance(entry, Mapping)
        ]
        return {"certificates": [cert for cert in certificates if cert]}

    certificate_payload = _convert_certificate_payload(decoded)
    return certificate_payload or {}


def _convert_attestation_entry(entry: Any) -> dict[str, Any]:
    return _convert_attestation_entry_impl(
        entry,
        convert_attestation_statement=_convert_attestation_statement,
        convert_certificate_payload=lambda payload, cert_bytes=None: _convert_certificate_payload(
            payload, cert_bytes
        ),
    )


def _convert_attestation_statement(details: Any) -> dict[str, Any]:
    payload = _convert_attestation_statement_impl(
        details,
        convert_certificate_chain=_convert_certificate_chain,
    )
    normalized: dict[str, Any] = {}
    for key, value in payload.items():
        if key == "x5c":
            normalized[key] = value
        else:
            normalized[key] = _hex_json_safe(value)
    return normalized


def _convert_certificate_chain(value: Any) -> list[dict[str, Any]]:
    return _convert_certificate_chain_impl(
        value,
        convert_certificate_bytes=_convert_certificate_bytes,
    )


def _convert_certificate_bytes(value: Any) -> dict[str, Any]:
    return _convert_certificate_bytes_impl(
        value,
        serializer=serialize_attestation_certificate,
        convert_certificate_payload=lambda payload, cert_bytes=None: _convert_certificate_payload(
            payload, cert_bytes
        ),
    )


def _convert_certificate_payload(
    entry: Mapping[str, Any], cert_bytes: bytes | None = None
) -> dict[str, Any]:
    payload = _convert_certificate_payload_impl(entry, cert_bytes)
    parsed_entry = payload.get("parsedX5c")
    if parsed_entry is not None:
        payload["parsedX5c"] = _hex_json_safe(parsed_entry)
    return payload


def _build_authenticator_section(
    response: Any,
    attestation_entry: Any,
) -> dict[str, Any]:
    response_mapping = response if isinstance(response, Mapping) else {}
    attestation_mapping = attestation_entry if isinstance(attestation_entry, Mapping) else {}

    auth_bytes = binary._extract_authenticator_bytes(response_mapping, attestation_entry)

    details = None
    auth_entry = response_mapping.get("authenticatorData")
    if isinstance(auth_entry, Mapping):
        details = auth_entry.get("details")
    if details is None and isinstance(attestation_mapping.get("details"), Mapping):
        details = attestation_mapping["details"].get("authenticatorData")

    fallback_alg = None
    if isinstance(response_mapping, Mapping):
        fallback_alg = response_mapping.get("publicKeyAlgorithm")

    return conversion_leaf._build_authenticator_data_payload(auth_bytes, details, fallback_alg)
