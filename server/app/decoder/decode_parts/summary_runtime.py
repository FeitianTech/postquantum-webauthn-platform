"""Extracted summary rendering helper bodies executed via decode.py global rebinding."""
# pyright: reportUndefinedVariable=false
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional


def _format_result_summary(result: Dict[str, Any]) -> str:
    base_type = _base_type(result.get("format"))
    formatter = {
        "PublicKeyCredential": _format_public_key_credential_summary,
        "Attestation object": _format_attestation_object_summary,
        "Authenticator data": _format_authenticator_data_summary,
        "WebAuthn client data": _format_client_data_summary,
        "X.509 certificate": _format_certificate_summary,
        "JSON": _format_json_summary,
        "CBOR": _format_cbor_summary,
    }.get(base_type, _format_generic_summary)

    lines = formatter(result)
    return "\n".join(line for line in lines if line is not None).rstrip()
def _base_type(format_label: Optional[str]) -> str:
    if not format_label:
        return "Decoded data"
    separator = format_label.find(" (")
    if separator != -1:
        return format_label[:separator]
    return format_label
def _format_public_key_credential_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    response = decoded.get("response") if isinstance(decoded, Mapping) else {}
    attestation_entry = response.get("attestationObject") if isinstance(response, Mapping) else None
    authenticator_entry = response.get("authenticatorData") if isinstance(response, Mapping) else None

    attestation_details = attestation_entry.get("details") if isinstance(attestation_entry, Mapping) else None
    auth_details = None
    if isinstance(attestation_details, Mapping):
        auth_details = attestation_details.get("authenticatorData")
    if auth_details is None and isinstance(authenticator_entry, Mapping):
        auth_details = authenticator_entry.get("details")

    auth_bytes = _extract_authenticator_bytes(response, attestation_entry)

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _extend_with_authenticator_details(lines, auth_details, auth_bytes, response)
    _extend_with_authenticator_extensions(lines, auth_details)
    _extend_with_client_extensions(lines, decoded.get("clientExtensionResults") if isinstance(decoded, Mapping) else None)
    _extend_with_attestation_section(
        lines, attestation_entry, attestation_details, include_certificates=False
    )
    _extend_with_client_data_entry(lines, response.get("clientDataJSON") if isinstance(response, Mapping) else None)
    return lines


def _format_attestation_object_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    auth_details = decoded.get("authenticatorData") if isinstance(decoded, Mapping) else None

    lines: List[str] = [f"Detected type:\t{base_type}"]
    attestation_entry: Dict[str, Any] = {"binary": result.get("binary")} if result.get("binary") else {}
    auth_bytes = _extract_authenticator_bytes_from_attestation(attestation_entry)
    _extend_with_authenticator_details(lines, auth_details, auth_bytes)
    _extend_with_authenticator_extensions(lines, auth_details)
    _extend_with_client_extensions(lines, None)
    _extend_with_attestation_section(
        lines, attestation_entry, decoded, include_certificates=False
    )
    return lines


def _format_authenticator_data_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    auth_bytes = _extract_bytes_from_binary(result.get("binary"))

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _extend_with_authenticator_details(lines, decoded, auth_bytes)
    _extend_with_authenticator_extensions(lines, decoded)
    _extend_with_client_extensions(lines, None)
    return lines


def _format_client_data_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _extend_with_client_data_details(lines, decoded)
    return lines


def _format_certificate_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    certificate_lines = _build_certificate_summary_lines(decoded)
    if not certificate_lines:
        certificate_lines = _format_json_block(decoded)

    lines: List[str] = [f"Detected type:\t{base_type}"]
    _append_multiline_field(
        lines,
        "Certificate",
        certificate_lines,
        indent_str="",
        force_multiline=True,
    )
    return lines


def _format_json_summary(result: Dict[str, Any]) -> List[str]:
    decoded = result.get("decoded")
    json_lines = _format_json_block(decoded)
    lines: List[str] = ["Detected type:\tJSON"]
    _append_multiline_field(lines, "JSON", json_lines, indent_str="  ")
    return lines


def _format_cbor_summary(result: Dict[str, Any]) -> List[str]:
    decoded = result.get("decoded") if isinstance(result.get("decoded"), Mapping) else {}
    decoded_value = decoded.get("decodedValue") if isinstance(decoded, Mapping) else None
    expanded_json = decoded.get("expandedJson") if isinstance(decoded, Mapping) else None
    ctap_info = decoded.get("ctap") if isinstance(decoded, Mapping) else None
    ctap_decoded = decoded.get("ctapDecoded") if isinstance(decoded, Mapping) else None

    lines: List[str] = ["Detected type:\tCBOR"]

    if isinstance(ctap_info, Mapping):
        meaning = ctap_info.get("meaning") or ctap_info.get("description")
        if isinstance(meaning, str) and meaning:
            lines[0] = f"Detected type:\tCBOR ({meaning})"
        code_hex = ctap_info.get("codeHex")
        code_value = code_hex or ctap_info.get("code")
        _append_simple_field(lines, "CTAP code", code_value)
        category = ctap_info.get("kind") or ctap_info.get("category")
        _append_simple_field(lines, "CTAP type", category)
        payload_length = ctap_info.get("payloadLength")
        if payload_length is not None:
            _append_simple_field(lines, "CBOR payload length", payload_length)

    if isinstance(ctap_decoded, Mapping) and ctap_decoded:
        response_labels: List[str] = []
        if "makeCredentialResponse" in ctap_decoded:
            response_labels.append("MakeCredential response")
        if "getAssertionResponse" in ctap_decoded:
            response_labels.append("GetAssertion response")
        if response_labels:
            lines.append(f"CTAP interpretation:\t{', '.join(response_labels)}")
        interpreted_lines = _format_json_block(ctap_decoded)
        _append_multiline_field(lines, "CTAP decoded", interpreted_lines, indent_str="  ")

    if isinstance(expanded_json, Mapping):
        expanded_lines = _format_json_block(expanded_json)
        _append_multiline_field(lines, "Expanded JSON", expanded_lines, indent_str="  ")

    if decoded_value is not None:
        value_lines = _format_json_block(decoded_value)
        _append_multiline_field(lines, "Decoded value", value_lines, indent_str="  ")
    elif decoded and not expanded_json and not ctap_decoded:
        json_lines = _format_json_block(decoded)
        _append_multiline_field(lines, "CBOR", json_lines, indent_str="  ")

    return lines


def _format_generic_summary(result: Dict[str, Any]) -> List[str]:
    base_type = _base_type(result.get("format"))
    lines: List[str] = [f"Detected type:\t{base_type}"]

    decoded = result.get("decoded")
    if decoded is not None:
        _append_multiline_field(lines, "Decoded", _format_json_block(decoded), indent_str="  ")
    else:
        binary = result.get("binary")
        if binary is not None:
            _append_multiline_field(lines, "Binary", _format_json_block(binary), indent_str="  ")

    return lines


def _build_certificate_summary_lines(decoded: Any) -> List[str]:
    if not isinstance(decoded, Mapping):
        return []

    lines: List[str] = []

    version = decoded.get("version")
    if isinstance(version, Mapping):
        display = version.get("display")
        if display:
            lines.append(f"Version: {display}")

    serial = decoded.get("serialNumber")
    if isinstance(serial, Mapping):
        decimal = serial.get("decimal")
        hex_value = serial.get("hex")
        if decimal and hex_value:
            lines.append(f"Certificate Serial Number: {decimal} ({hex_value})")
        elif decimal:
            lines.append(f"Certificate Serial Number: {decimal}")

    signature_algorithm = decoded.get("signatureAlgorithm")
    if signature_algorithm:
        lines.append(f"Signature Algorithm: {signature_algorithm}")

    issuer = decoded.get("issuer")
    if issuer:
        lines.append(f"Issuer: {issuer}")

    validity = decoded.get("validity")
    if isinstance(validity, Mapping):
        not_before = _format_certificate_time(validity.get("notBefore"))
        not_after = _format_certificate_time(validity.get("notAfter"))
        if not_before or not_after:
            lines.append("Validity")
            if not_before:
                lines.append(f"Not Before: {not_before}")
            if not_after:
                lines.append(f"Not After: {not_after}")

    subject = decoded.get("subject")
    if subject:
        lines.append(f"Subject: {subject}")

    lines.extend(_build_subject_public_key_info_lines(decoded.get("publicKeyInfo")))
    lines.extend(_build_certificate_extensions_lines(decoded.get("extensions")))
    lines.extend(_build_signature_lines(decoded.get("signature")))
    lines.extend(_build_fingerprint_lines(decoded.get("fingerprints")))

    ski_lines = _build_subject_key_identifier_lines(decoded)
    if ski_lines:
        lines.append("Subject key identifier:")
        lines.extend(ski_lines)

    return [line for line in lines if line is not None]


def _extend_with_authenticator_details(
    lines: List[str],
    auth_details: Optional[Mapping[str, Any]],
    auth_bytes: Optional[bytes],
    response_context: Optional[Mapping[str, Any]] = None,
) -> None:
    data_lines = _build_authenticator_data_lines(auth_bytes, auth_details)
    _append_multiline_field(lines, "Authenticator data", data_lines)

    rp_hex = None
    flags_info = None
    sign_count = None
    attested_info: Optional[Dict[str, Any]] = None

    if isinstance(auth_details, Mapping):
        rp_info = auth_details.get("rpIdHash")
        if isinstance(rp_info, Mapping):
            rp_hex = rp_info.get("hex")
        flags_info = auth_details.get("flags")
        sign_count = auth_details.get("signCount")
        attested = auth_details.get("attestedCredentialData")
        if isinstance(attested, Mapping):
            fallback_alg = None
            if isinstance(response_context, Mapping):
                fallback_alg = response_context.get("publicKeyAlgorithm")
            attested_info = _collect_attested_info(attested, auth_bytes, fallback_alg)

    _append_simple_field(lines, "RP ID hash", rp_hex)
    flag_line = _format_flag_line(flags_info)
    _append_multiline_field(
        lines,
        "Flags",
        [flag_line] if flag_line else [],
        force_multiline=True,
    )
    _append_simple_field(lines, "Counter", _format_counter_value(sign_count))

    if attested_info:
        _append_multiline_field(lines, "Credential data", attested_info.get("credential_lines", []))
        _append_multiline_field(lines, "AAGUID", attested_info.get("aaguid_lines", []))
        _append_simple_field(lines, "Credential ID", attested_info.get("credential_id"))
        _append_simple_field(lines, "Key algorithm", attested_info.get("algorithm"))
        _append_multiline_field(
            lines,
            "Public key",
            attested_info.get("public_key_lines", []),
            indent_str="  ",
        )


def _extend_with_authenticator_extensions(lines: List[str], auth_details: Any) -> None:
    if not isinstance(auth_details, Mapping):
        _append_simple_field(lines, "Authenticator extensions", None)
        return

    extensions = auth_details.get("extensions")
    if not isinstance(extensions, Mapping):
        _append_simple_field(lines, "Authenticator extensions", None)
        return

    summary = extensions.get("summary")
    raw_value = extensions.get("raw")
    content = summary if summary is not None else raw_value
    if content is None:
        _append_simple_field(lines, "Authenticator extensions", None)
        return

    _append_multiline_field(lines, "Authenticator extensions", _format_json_block(content), indent_str="  ")


def _extend_with_client_extensions(lines: List[str], extensions: Any) -> None:
    if extensions is None:
        _append_simple_field(lines, "Client extensions", None)
        return
    _append_multiline_field(lines, "Client extensions", _format_json_block(extensions), indent_str="  ")


def _extend_with_attestation_section(
    lines: List[str],
    attestation_entry: Any,
    attestation_details: Any,
    *,
    include_certificates: bool = True,
) -> None:
    att_hex = _extract_hex_from_binary(attestation_entry)
    _append_simple_field(lines, "Attestation object", att_hex)

    att_format = None
    certificates = None
    if isinstance(attestation_details, Mapping):
        att_format = attestation_details.get("attestationFormat")
        certificates = attestation_details.get("attestationCertificate")

    _append_simple_field(lines, "Att. format", att_format)

    if not include_certificates:
        lines.append("Att. certificates:\t")
        return

    if isinstance(certificates, Mapping):
        summary = certificates.get("summary")
        if isinstance(summary, str) and summary.strip():
            cert_lines = summary.splitlines()
        else:
            cert_lines = _format_json_block(certificates)
        _append_multiline_field(lines, "Att. certificates", cert_lines, indent_str="  ")
    else:
        _append_simple_field(lines, "Att. certificates", None)


def _extend_with_client_data_entry(lines: List[str], client_data_entry: Any) -> None:
    details = None
    if isinstance(client_data_entry, Mapping):
        details = client_data_entry.get("details")
    _extend_with_client_data_details(lines, details)


def _extend_with_client_data_details(lines: List[str], details: Any) -> None:
    if not isinstance(details, Mapping):
        _append_simple_field(lines, "Client data", None)
        _append_simple_field(lines, "Type", None)
        _append_simple_field(lines, "Challenge", None)
        _append_simple_field(lines, "Origin", None)
        _append_simple_field(lines, "Cross-origin", None)
        return

    raw_json = details.get("rawJson")
    client_data_lines: List[str]
    if isinstance(raw_json, Mapping):
        client_data_lines = _format_json_block(raw_json)
    else:
        raw_text = details.get("rawText")
        if isinstance(raw_text, str) and raw_text.strip():
            client_data_lines = raw_text.splitlines()
        else:
            filtered = {
                key: details.get(key)
                for key in ("type", "challenge", "origin", "crossOrigin")
                if key in details
            }
            client_data_lines = _format_json_block(filtered)

    _append_multiline_field(lines, "Client data", client_data_lines, indent_str="  ")

    type_value = details.get("type")
    challenge = details.get("challenge")
    if isinstance(challenge, Mapping):
        challenge_value = challenge.get("hex") or challenge.get("raw")
    else:
        challenge_value = challenge
    origin = details.get("origin")
    cross_origin_value = details.get("crossOrigin")
    cross_origin_text = _format_boolean(cross_origin_value)
    if cross_origin_text is None and cross_origin_value is not None:
        cross_origin_text = str(cross_origin_value)

    _append_simple_field(lines, "Type", type_value)
    _append_simple_field(lines, "Challenge", challenge_value)
    _append_simple_field(lines, "Origin", origin)
    _append_simple_field(lines, "Cross-origin", cross_origin_text)
