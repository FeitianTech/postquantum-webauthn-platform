"""A metadata statement's fields as the MDS explorer shows them: names, identifiers,
AAGUIDs, dates, certification, user verification, transports and the icon."""
from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import date, datetime, timezone
from typing import Any

from .. import aaguid


def mapping_value(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def string_or_none(value: Any) -> str | None:
    if isinstance(value, str):
        text = value.strip()
        if text:
            return text
    return None


def extract_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [item for item in value if item not in (None, "")]
    if isinstance(value, tuple):
        return [item for item in value if item not in (None, "")]
    return [value]


def _parse_date(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)

    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    # ISO 8601 as MDS writes it: a date ("2024-01-02", read as its midnight) or
    # a date and time, "Z" included.
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_date(value: Any) -> str:
    parsed = _parse_date(value)
    if parsed is None:
        if isinstance(value, str):
            return value
        return ""
    return parsed.strftime("%b %d, %Y").replace(" 0", " ")


def _extract_byte_array(value: Any) -> bytes | None:
    """Bytes, or a list of byte values (0 to 255), as bytes; None for anything else."""

    if isinstance(value, list) and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
        return bytes(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    return None


def format_guid_candidate(value: Any) -> str:
    if value is None:
        return ""

    if isinstance(value, str):
        trimmed = value.strip()
        if not trimmed:
            return ""
        lowered = trimmed.lower()
        if len(lowered) == 36 and lowered.count("-") == 4:
            return lowered
        clean = "".join(ch for ch in lowered if ch in "0123456789abcdef")
        if len(clean) == 32:
            return (
                f"{clean[:8]}-{clean[8:12]}-{clean[12:16]}-"
                f"{clean[16:20]}-{clean[20:]}"
            )
        return ""

    guid = aaguid.guid(_extract_byte_array(value))
    if guid:
        return guid

    try:
        text = str(value)
    except Exception:  # pragma: no cover - defensive
        return ""
    return format_guid_candidate(text)


def normalise_aaguid_key(value: Any) -> str:
    formatted = format_guid_candidate(value)
    return formatted.replace("-", "").lower() if formatted else ""


def format_enum(value: Any) -> str:
    if value in (None, ""):
        return ""

    parts: list[str] = []
    for raw_part in str(value).split("_"):
        for sub_part in raw_part.split("-"):
            text = sub_part.strip()
            if text:
                parts.append(text)

    formatted_parts = []
    for part in parts:
        if part.isupper():
            if len(part) <= 4:
                formatted_parts.append(part)
            else:
                lowered = part.lower()
                formatted_parts.append(lowered[:1].upper() + lowered[1:])
            continue

        if any(char.isdigit() for char in part):
            formatted_parts.append(part.upper())
            continue

        lowered = part.lower()
        formatted_parts.append(lowered[:1].upper() + lowered[1:])

    return " ".join(formatted_parts)


def format_protocol(protocol: Any) -> str:
    formatted = format_enum(protocol)
    compact = formatted.replace(" ", "")
    if compact.lower().startswith("fido") and compact[4:].isdigit():
        return compact.upper()
    return formatted


def format_certification(status_reports: Any) -> tuple[str, str]:
    reports = [report for report in extract_list(status_reports) if isinstance(report, Mapping)]
    if not reports:
        return "", ""

    def sort_key(report: Mapping[str, Any]) -> float:
        parsed = _parse_date(mapping_value(report, "effectiveDate", "effective_date"))
        return parsed.timestamp() if parsed else 0.0

    sorted_reports = sorted(reports, key=sort_key, reverse=True)
    latest = sorted_reports[0]

    status_raw = string_or_none(mapping_value(latest, "status")) or ""
    status_value = status_raw.upper()
    descriptor = string_or_none(
        mapping_value(latest, "certificationDescriptor", "certification_descriptor")
    )
    certificate_number = string_or_none(
        mapping_value(latest, "certificateNumber", "certificate_number")
    )

    parts = []
    if status_value:
        parts.append(format_enum(status_value))
    if descriptor:
        parts.append(descriptor)
    if certificate_number:
        parts.append(f"({certificate_number})")

    return " • ".join(part for part in parts if part), status_value


def latest_effective_date(status_reports: Any) -> str:
    reports = [report for report in extract_list(status_reports) if isinstance(report, Mapping)]
    if not reports:
        return ""

    def sort_key(report: Mapping[str, Any]) -> float:
        parsed = _parse_date(mapping_value(report, "effectiveDate", "effective_date"))
        return parsed.timestamp() if parsed else 0.0

    latest = max(reports, key=sort_key)
    return string_or_none(mapping_value(latest, "effectiveDate", "effective_date")) or ""


def extract_user_verification(details: Any) -> list[str]:
    values = set()
    for group in extract_list(details):
        if not isinstance(group, list):
            group = [group]
        for entry in group:
            if isinstance(entry, Mapping):
                method = mapping_value(entry, "userVerificationMethod", "user_verification_method")
                if method:
                    values.add(format_enum(method))
    return sorted(values)


def extract_transports(metadata: Mapping[str, Any]) -> list[str]:
    info = mapping_value(metadata, "authenticatorGetInfo", "authenticator_get_info")
    info_transports = extract_list(mapping_value(info, "transports")) if isinstance(info, Mapping) else []
    metadata_transports = extract_list(mapping_value(metadata, "transports"))
    combined = {format_enum(value) for value in [*info_transports, *metadata_transports] if value}
    return sorted(item for item in combined if item)


def normalise_icon(icon: Any, icon_type: Any) -> str:
    value = string_or_none(icon)
    if not value:
        return ""
    if value.lower().startswith("data:") or value.lower().startswith("http://") or value.lower().startswith("https://"):
        return value
    content_type = string_or_none(icon_type) or "image/png"
    return f"data:{content_type};base64,{value}"


def resolve_name(metadata: Mapping[str, Any], entry: Mapping[str, Any]) -> str:
    description = mapping_value(metadata, "description")
    if isinstance(description, str) and description.strip():
        return description.strip()
    if isinstance(description, Mapping):
        for value in description.values():
            text = string_or_none(value)
            if text:
                return text

    alt_descriptions = mapping_value(metadata, "alternativeDescriptions", "alternative_descriptions")
    if isinstance(alt_descriptions, Mapping):
        for value in alt_descriptions.values():
            text = string_or_none(value)
            if text:
                return text

    for report in extract_list(mapping_value(entry, "statusReports", "status_reports")):
        if isinstance(report, Mapping):
            descriptor = string_or_none(
                mapping_value(report, "certificationDescriptor", "certification_descriptor")
            )
            if descriptor:
                return descriptor

    return "Unknown Authenticator"


def resolve_identifier(entry: Mapping[str, Any], metadata: Mapping[str, Any]) -> str:
    for candidate in (
        string_or_none(mapping_value(entry, "aaguid")),
        string_or_none(mapping_value(metadata, "aaguid")),
        string_or_none(mapping_value(metadata, "aaid")),
    ):
        if candidate:
            return candidate

    identifiers = extract_list(
        mapping_value(metadata, "attestationCertificateKeyIdentifiers", "attestation_certificate_key_identifiers")
    )
    if identifiers:
        return str(identifiers[0])
    return "—"


def resolve_aaguid(entry: Mapping[str, Any], metadata: Mapping[str, Any]) -> str:
    for candidate in (
        mapping_value(entry, "aaguid"),
        mapping_value(metadata, "aaguid"),
    ):
        formatted = format_guid_candidate(candidate)
        if formatted:
            return formatted
    return ""


def extract_attestation_key_identifiers(
    metadata: Mapping[str, Any], entry: Mapping[str, Any]
) -> list[str]:
    seen = set()
    values: list[str] = []
    for candidate in (
        *extract_list(
            mapping_value(
                metadata,
                "attestationCertificateKeyIdentifiers",
                "attestation_certificate_key_identifiers",
            )
        ),
        *extract_list(
            mapping_value(
                entry,
                "attestationCertificateKeyIdentifiers",
                "attestation_certificate_key_identifiers",
            )
        ),
    ):
        text = str(candidate).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        values.append(text)
    return values


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compact_metadata_statement(metadata_mapping: Mapping[str, Any]) -> dict[str, Any]:
    compact = dict(metadata_mapping)
    for key in (
        "attestationRootCertificates",
        "attestation_root_certificates",
        "attestationCertificateKeyIdentifiers",
        "attestation_certificate_key_identifiers",
        "icon",
        "iconType",
        "icon_type",
        # Images the explorer never shows, as large as the icon.
        "iconDark",
        "providerLogoLight",
        "providerLogoDark",
    ):
        compact.pop(key, None)
    return compact
