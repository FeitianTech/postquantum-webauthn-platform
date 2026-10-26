"""A metadata statement's fields as the MDS explorer shows them: names, identifiers,
AAGUIDs, dates, certification, user verification, transports and the icon."""
from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import date, datetime, timezone
from typing import Any

from .. import aaguid, encoding


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


def _effective_date(report: Mapping[str, Any]) -> datetime | None:
    """A status report's effective date, or None when it has none that reads."""

    return _parse_date(mapping_value(report, "effectiveDate", "effective_date"))


def _effective_timestamp(report: Mapping[str, Any]) -> float:
    """A status report's effective date as a timestamp; 0 (the oldest) without one."""

    parsed = _effective_date(report)
    return parsed.timestamp() if parsed else 0.0


# The certification levels, highest first.
_CERTIFICATION_LEVELS = (
    "FIDO_CERTIFIED_L3PLUS",
    "FIDO_CERTIFIED_L3",
    "FIDO_CERTIFIED_L2PLUS",
    "FIDO_CERTIFIED_L2",
    "FIDO_CERTIFIED_L1PLUS",
    "FIDO_CERTIFIED_L1",
    "FIDO_CERTIFIED",
)
# A report's status, the more serious first: of reports on one date, the first of
# them is the latest status (a revocation over the certification of that day, a
# level over the plain FIDO_CERTIFIED the MDS often dates the same day). Any
# other status comes after them all.
_STATUS_ORDER = (
    "REVOKED",
    "ATTESTATION_KEY_COMPROMISE",
    "USER_KEY_REMOTE_COMPROMISE",
    "USER_KEY_PHYSICAL_COMPROMISE",
    "USER_VERIFICATION_BYPASS",
    "UPDATE_AVAILABLE",
    *_CERTIFICATION_LEVELS,
    "SELF_ASSERTION_SUBMITTED",
    "NOT_FIDO_CERTIFIED",
)


def _status(report: Mapping[str, Any]) -> str:
    """A status report's status, upper-cased as the explorer compares it; "" without one."""

    return (string_or_none(mapping_value(report, "status")) or "").upper()


def _report_order(report: Mapping[str, Any]) -> tuple[Any, ...]:
    """Where a status report stands among an entry's, the latest first: one with no
    date is in force (MDS3: effective while present), then the dated ones newest
    first, then one whose date does not read; on one date the more serious status;
    then the report's JSON, so the statement's own order never decides."""

    raw_date = string_or_none(mapping_value(report, "effectiveDate", "effective_date"))
    parsed = _effective_date(report)
    if raw_date is None:
        when: tuple[int, float] = (0, 0.0)
    elif parsed is None:
        when = (2, 0.0)
    else:
        when = (1, -parsed.timestamp())
    status = _status(report)
    rank = _STATUS_ORDER.index(status) if status in _STATUS_ORDER else len(_STATUS_ORDER)
    return (*when, rank, canonical_json(report))


def _reports_latest_first(status_reports: Any) -> list[Mapping[str, Any]]:
    """An entry's status reports that name a status, the latest first (``_report_order``)."""

    reports = [report for report in extract_list(status_reports) if isinstance(report, Mapping) and _status(report)]
    return sorted(reports, key=_report_order)


def _report_text(report: Mapping[str, Any]) -> str:
    """A status report as the explorer writes it: "FIDO Certified L2 • descriptor • (number)"."""

    parts = [format_enum(_status(report))]
    descriptor = string_or_none(mapping_value(report, "certificationDescriptor", "certification_descriptor"))
    if descriptor:
        parts.append(descriptor)
    certificate_number = string_or_none(mapping_value(report, "certificateNumber", "certificate_number"))
    if certificate_number:
        parts.append(f"({certificate_number})")
    return " • ".join(parts)


def latest_status(status_reports: Any) -> str:
    """An entry's latest status, formatted ("Update Available"); "" when no report names one."""

    reports = _reports_latest_first(status_reports)
    return format_enum(_status(reports[0])) if reports else ""


def _level_rank(status: str) -> tuple[int, Any] | None:
    """How high a certification ``status`` stands (the higher, the higher), or None for a
    status that is no certification: the known levels in order, then any other
    ``FIDO_CERTIFIED_*`` above them all, by name."""

    if status in _CERTIFICATION_LEVELS:
        return (0, -_CERTIFICATION_LEVELS.index(status))
    if status.startswith("FIDO_CERTIFIED_"):
        return (1, status)
    return None


def certification_level(status_reports: Any) -> str:
    """The highest FIDO certification an entry reached, as the Certification column writes
    it: the level, then the descriptor and certificate number of its latest report at that
    level; "" when no report names a certification. A later status (an update available,
    a revocation) does not take it away: the Status column shows that."""

    ranked = [(rank, report) for report in _reports_latest_first(status_reports) if (rank := _level_rank(_status(report)))]
    if not ranked:
        return ""
    highest = max(rank for rank, _report in ranked)
    return _report_text(next(report for rank, report in ranked if rank == highest))


def latest_effective_date(status_reports: Any) -> str:
    reports = [report for report in extract_list(status_reports) if isinstance(report, Mapping)]
    if not reports:
        return ""

    latest = max(reports, key=_effective_timestamp)
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
    """A statement's icon as a data: URL, the one kind of image the page's policy
    loads: a data: URL as it is, bare base64 as one (of its ``iconType``, else
    PNG), anything else (an http(s) URL, text that is no base64) nothing."""

    value = string_or_none(icon)
    if not value:
        return ""
    if value[:5].lower() == "data:":
        return value
    if not encoding.try_decode_base64(value):
        return ""
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
