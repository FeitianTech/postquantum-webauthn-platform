"""Helpers for building fast FIDO MDS explorer snapshots."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.x509.oid import NameOID

__all__ = [
    "build_entry_id",
    "build_explorer_entry",
    "build_explorer_snapshot",
    "build_snapshot_meta",
    "normalise_aaguid_key",
]

_ENTRY_HASH_PREFIX = "entry:"


def _mapping_value(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _string_or_none(value: Any) -> Optional[str]:
    if isinstance(value, str):
        text = value.strip()
        if text:
            return text
    return None


def _extract_list(value: Any) -> List[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [item for item in value if item not in (None, "")]
    if isinstance(value, tuple):
        return [item for item in value if item not in (None, "")]
    return [value]


def _parse_date(value: Any) -> Optional[datetime]:
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

    normalised = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalised)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(f"{normalised}T00:00:00")
        except ValueError:
            return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_date(value: Any) -> str:
    parsed = _parse_date(value)
    if parsed is None:
        if isinstance(value, str):
            return value
        return ""
    return parsed.strftime("%b %d, %Y").replace(" 0", " ")


def _extract_byte_array(value: Any) -> Optional[List[int]]:
    if value is None:
        return None
    if isinstance(value, list) and all(isinstance(item, int) for item in value):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return list(bytes(value))
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

    byte_array = _extract_byte_array(value)
    if byte_array and len(byte_array) == 16:
        hex_value = "".join(f"{byte:02x}" for byte in byte_array)
        return (
            f"{hex_value[:8]}-{hex_value[8:12]}-{hex_value[12:16]}-"
            f"{hex_value[16:20]}-{hex_value[20:]}"
        )

    try:
        text = str(value)
    except Exception:  # pragma: no cover - defensive
        return ""
    return format_guid_candidate(text)


def normalise_aaguid_key(value: Any) -> str:
    formatted = format_guid_candidate(value)
    return formatted.replace("-", "").lower() if formatted else ""


def _format_enum(value: Any) -> str:
    if value in (None, ""):
        return ""

    parts: List[str] = []
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


def _format_protocol(protocol: Any) -> str:
    formatted = _format_enum(protocol)
    compact = formatted.replace(" ", "")
    if compact.lower().startswith("fido") and compact[4:].isdigit():
        return compact.upper()
    return formatted


def _format_certification(status_reports: Any) -> Tuple[str, str]:
    reports = [report for report in _extract_list(status_reports) if isinstance(report, Mapping)]
    if not reports:
        return "", ""

    def sort_key(report: Mapping[str, Any]) -> float:
        parsed = _parse_date(_mapping_value(report, "effectiveDate", "effective_date"))
        return parsed.timestamp() if parsed else 0.0

    sorted_reports = sorted(reports, key=sort_key, reverse=True)
    latest = sorted_reports[0]

    status_raw = _string_or_none(_mapping_value(latest, "status")) or ""
    status_value = status_raw.upper()
    descriptor = _string_or_none(
        _mapping_value(latest, "certificationDescriptor", "certification_descriptor")
    )
    certificate_number = _string_or_none(
        _mapping_value(latest, "certificateNumber", "certificate_number")
    )

    parts = []
    if status_value:
        parts.append(_format_enum(status_value))
    if descriptor:
        parts.append(descriptor)
    if certificate_number:
        parts.append(f"({certificate_number})")

    return " • ".join(part for part in parts if part), status_value


def _latest_effective_date(status_reports: Any) -> str:
    reports = [report for report in _extract_list(status_reports) if isinstance(report, Mapping)]
    if not reports:
        return ""

    def sort_key(report: Mapping[str, Any]) -> float:
        parsed = _parse_date(_mapping_value(report, "effectiveDate", "effective_date"))
        return parsed.timestamp() if parsed else 0.0

    latest = max(reports, key=sort_key)
    return _string_or_none(_mapping_value(latest, "effectiveDate", "effective_date")) or ""


def _extract_user_verification(details: Any) -> List[str]:
    values = set()
    for group in _extract_list(details):
        if not isinstance(group, list):
            group = [group]
        for entry in group:
            if isinstance(entry, Mapping):
                method = _mapping_value(entry, "userVerificationMethod", "user_verification_method")
                if method:
                    values.add(_format_enum(method))
    return sorted(values)


def _extract_transports(metadata: Mapping[str, Any]) -> List[str]:
    info = _mapping_value(metadata, "authenticatorGetInfo", "authenticator_get_info")
    info_transports = _extract_list(_mapping_value(info, "transports")) if isinstance(info, Mapping) else []
    metadata_transports = _extract_list(_mapping_value(metadata, "transports"))
    combined = {_format_enum(value) for value in [*info_transports, *metadata_transports] if value}
    return sorted(item for item in combined if item)


def _normalise_icon(icon: Any, icon_type: Any) -> str:
    value = _string_or_none(icon)
    if not value:
        return ""
    if value.lower().startswith("data:") or value.lower().startswith("http://") or value.lower().startswith("https://"):
        return value
    content_type = _string_or_none(icon_type) or "image/png"
    return f"data:{content_type};base64,{value}"


def _resolve_name(metadata: Mapping[str, Any], entry: Mapping[str, Any]) -> str:
    description = _mapping_value(metadata, "description")
    if isinstance(description, str) and description.strip():
        return description.strip()
    if isinstance(description, Mapping):
        for value in description.values():
            text = _string_or_none(value)
            if text:
                return text

    alt_descriptions = _mapping_value(metadata, "alternativeDescriptions", "alternative_descriptions")
    if isinstance(alt_descriptions, Mapping):
        for value in alt_descriptions.values():
            text = _string_or_none(value)
            if text:
                return text

    for report in _extract_list(_mapping_value(entry, "statusReports", "status_reports")):
        if isinstance(report, Mapping):
            descriptor = _string_or_none(
                _mapping_value(report, "certificationDescriptor", "certification_descriptor")
            )
            if descriptor:
                return descriptor

    return "Unknown Authenticator"


def _resolve_identifier(entry: Mapping[str, Any], metadata: Mapping[str, Any]) -> str:
    for candidate in (
        _string_or_none(_mapping_value(entry, "aaguid")),
        _string_or_none(_mapping_value(metadata, "aaguid")),
        _string_or_none(_mapping_value(metadata, "aaid")),
    ):
        if candidate:
            return candidate

    identifiers = _extract_list(
        _mapping_value(metadata, "attestationCertificateKeyIdentifiers", "attestation_certificate_key_identifiers")
    )
    if identifiers:
        return str(identifiers[0])
    return "—"


def _resolve_aaguid(entry: Mapping[str, Any], metadata: Mapping[str, Any]) -> str:
    for candidate in (
        _mapping_value(entry, "aaguid"),
        _mapping_value(metadata, "aaguid"),
    ):
        formatted = format_guid_candidate(candidate)
        if formatted:
            return formatted
    return ""


def _extract_attestation_key_identifiers(
    metadata: Mapping[str, Any], entry: Mapping[str, Any]
) -> List[str]:
    seen = set()
    values: List[str] = []
    for candidate in (
        *_extract_list(
            _mapping_value(
                metadata,
                "attestationCertificateKeyIdentifiers",
                "attestation_certificate_key_identifiers",
            )
        ),
        *_extract_list(
            _mapping_value(
                entry,
                "attestationCertificateKeyIdentifiers",
                "attestation_certificate_key_identifiers",
            )
        ),
    ):
        if candidate in (None, ""):
            continue
        text = str(candidate).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        values.append(text)
    return values


def _normalise_signature_algorithm_name(name: str) -> str:
    text = (name or "").strip()
    if not text:
        return ""

    lowered = text.lower()
    if "ecdsa" in lowered:
        return "ECDSA"
    if "rsassa-pss" in lowered:
        return "RSASSA-PSS"
    if "rsa" in lowered:
        return "RSASSA-PKCS1-v1_5"
    if "ed25519" in lowered:
        return "ED25519"
    if "ed448" in lowered:
        return "ED448"
    if "dsa" in lowered:
        return "DSA"

    return text.replace("-", "").replace(" ", "").upper()


def _format_hash_value(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    lower = text.lower().replace(" ", "").replace("-", "")
    if lower.startswith("sha") and lower[3:].isdigit():
        return f"SHA{lower[3:]}"
    return text.replace("-", "").replace(" ", "").upper()


def _derive_certificate_algorithm_info(algorithm_name: str, hash_name: str) -> str:
    components = []
    formatted_algorithm = _normalise_signature_algorithm_name(algorithm_name)
    formatted_hash = _format_hash_value(hash_name)

    for part in (formatted_algorithm, formatted_hash):
        if part and (not components or components[-1].lower() != part.lower()):
            components.append(part)
    return "_".join(components)


def _decode_der_certificate(value: Any) -> Optional[bytes]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if not isinstance(value, str):
        return None

    cleaned = "".join(value.split())
    if not cleaned:
        return None

    try:
        return base64.b64decode(cleaned + "=" * ((4 - len(cleaned) % 4) % 4))
    except Exception:  # pragma: no cover - defensive
        return None


def _summarise_attestation_certificates(certificates: Sequence[Any]) -> Tuple[List[str], List[str]]:
    algorithm_infos: List[str] = []
    common_names: List[str] = []
    seen_algorithms = set()
    seen_common_names = set()

    for certificate_value in certificates:
        certificate_bytes = _decode_der_certificate(certificate_value)
        if not certificate_bytes:
            continue

        try:
            certificate = x509.load_der_x509_certificate(certificate_bytes)
        except Exception:  # pragma: no cover - invalid certificate data
            continue

        try:
            hash_name = certificate.signature_hash_algorithm.name
        except (UnsupportedAlgorithm, ValueError):
            hash_name = ""

        oid = getattr(certificate.signature_algorithm_oid, "_name", None)
        if not isinstance(oid, str) or oid.lower() == "unknown oid":
            oid = getattr(certificate.signature_algorithm_oid, "dotted_string", "") or ""

        algorithm_info = _derive_certificate_algorithm_info(oid, hash_name)
        if algorithm_info and algorithm_info.lower() not in seen_algorithms:
            seen_algorithms.add(algorithm_info.lower())
            algorithm_infos.append(algorithm_info)

        for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if not isinstance(attribute.value, str):
                continue
            common_name = attribute.value.strip()
            if not common_name:
                continue
            key = common_name.lower()
            if key in seen_common_names:
                continue
            seen_common_names.add(key)
            common_names.append(common_name)

    return algorithm_infos, common_names


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_entry_id(entry_payload: Mapping[str, Any]) -> str:
    metadata = _mapping_value(entry_payload, "metadataStatement", "metadata_statement")
    metadata_mapping = metadata if isinstance(metadata, Mapping) else {}

    aaguid = _resolve_aaguid(entry_payload, metadata_mapping)
    if aaguid:
        return f"aaguid:{aaguid.lower()}"

    aaid = _string_or_none(_mapping_value(entry_payload, "aaid", "AAID")) or _string_or_none(
        _mapping_value(metadata_mapping, "aaid", "AAID")
    )
    if aaid:
        return f"aaid:{aaid}"

    key_ids = _extract_attestation_key_identifiers(metadata_mapping, entry_payload)
    if key_ids:
        return f"akid:{key_ids[0].lower()}"

    digest = hashlib.sha256(_canonical_json(entry_payload).encode("utf-8")).hexdigest()
    return f"{_ENTRY_HASH_PREFIX}{digest[:24]}"


def build_snapshot_meta(
    payload: Mapping[str, Any],
    cache_info: Optional[Mapping[str, Any]] = None,
    *,
    source: str = "packaged",
) -> Dict[str, Any]:
    metadata = dict(cache_info or {})
    generated_at = _string_or_none(_mapping_value(metadata, "generated_at"))
    if not generated_at:
        generated_at = datetime.now(timezone.utc).isoformat()

    entries = _extract_list(_mapping_value(payload, "entries"))
    return {
        "source": source,
        "legalHeader": _string_or_none(_mapping_value(payload, "legalHeader", "legal_header")) or "",
        "no": _mapping_value(payload, "no"),
        "nextUpdate": _string_or_none(_mapping_value(payload, "nextUpdate", "next_update")),
        "entryCount": len(entries),
        "lastModified": _string_or_none(_mapping_value(metadata, "last_modified")),
        "lastModifiedIso": _string_or_none(_mapping_value(metadata, "last_modified_iso")),
        "etag": _string_or_none(_mapping_value(metadata, "etag")),
        "fetchedAt": _string_or_none(_mapping_value(metadata, "fetched_at")),
        "generatedAt": generated_at,
    }


def build_explorer_entry(
    entry_payload: Mapping[str, Any],
    *,
    index: int = 0,
    source: str,
    trust_anchor_status: Optional[bool],
    snapshot_meta: Optional[Mapping[str, Any]] = None,
    include_detail: bool = False,
    source_info: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    metadata = _mapping_value(entry_payload, "metadataStatement", "metadata_statement")
    metadata_mapping = metadata if isinstance(metadata, Mapping) else {}
    status_reports = [
        report for report in _extract_list(_mapping_value(entry_payload, "statusReports", "status_reports"))
        if isinstance(report, Mapping)
    ]

    name = _resolve_name(metadata_mapping, entry_payload)
    protocol = _format_protocol(
        _mapping_value(metadata_mapping, "protocolFamily", "protocol_family")
        or _mapping_value(metadata_mapping, "protocolType", "protocol_type")
    )
    certification, certification_status = _format_certification(status_reports)
    identifier = _resolve_identifier(entry_payload, metadata_mapping)
    aaguid = _resolve_aaguid(entry_payload, metadata_mapping)
    user_verification_list = _extract_user_verification(
        _mapping_value(metadata_mapping, "userVerificationDetails", "user_verification_details")
    )
    attachment_list = [
        _format_enum(value)
        for value in _extract_list(_mapping_value(metadata_mapping, "attachmentHint", "attachment_hint"))
    ]
    transports_list = _extract_transports(metadata_mapping)
    key_protection_list = [
        _format_enum(value)
        for value in _extract_list(_mapping_value(metadata_mapping, "keyProtection", "key_protection"))
    ]
    algorithms_list = [
        _format_enum(value)
        for value in _extract_list(
            _mapping_value(metadata_mapping, "authenticationAlgorithms", "authentication_algorithms")
        )
    ]
    icon = _normalise_icon(
        _mapping_value(metadata_mapping, "icon"),
        _mapping_value(metadata_mapping, "iconType", "icon_type"),
    )
    attestation_certificates = _extract_list(
        _mapping_value(metadata_mapping, "attestationRootCertificates", "attestation_root_certificates")
    )
    attestation_key_identifiers = _extract_attestation_key_identifiers(metadata_mapping, entry_payload)

    latest_status_date = _latest_effective_date(status_reports)
    raw_date = (
        _string_or_none(_mapping_value(entry_payload, "timeOfLastStatusChange", "time_of_last_status_change"))
        or latest_status_date
    )
    date_updated = _format_date(raw_date)

    algorithm_info_list, common_name_list = _summarise_attestation_certificates(attestation_certificates)
    source_info_payload = dict(source_info) if isinstance(source_info, Mapping) else None

    entry: Dict[str, Any] = {
        "entryId": build_entry_id(entry_payload),
        "index": index,
        "name": name,
        "protocol": protocol,
        "certification": certification,
        "certificationStatus": certification_status,
        "id": identifier,
        "aaguid": aaguid,
        "icon": icon,
        "userVerification": ", ".join(user_verification_list),
        "userVerificationList": user_verification_list,
        "attachment": ", ".join(attachment_list),
        "attachmentList": attachment_list,
        "transports": ", ".join(transports_list),
        "transportsList": transports_list,
        "keyProtection": ", ".join(key_protection_list),
        "keyProtectionList": key_protection_list,
        "algorithms": ", ".join(algorithms_list),
        "algorithmsList": algorithms_list,
        "certificateAlgorithmInfo": ", ".join(algorithm_info_list) if algorithm_info_list else "—",
        "certificateAlgorithmInfoList": algorithm_info_list,
        "certificateCommonNames": ", ".join(common_name_list) if common_name_list else "—",
        "certificateCommonNameList": common_name_list,
        "algorithmInfo": ", ".join(algorithm_info_list) if algorithm_info_list else "—",
        "commonName": ", ".join(common_name_list) if common_name_list else "—",
        "dateUpdated": date_updated,
        "dateTooltip": raw_date or None,
        "timeOfLastStatusChange": raw_date or None,
        "source": source,
        "sourceInfo": source_info_payload,
        "trustAnchorStatus": trust_anchor_status,
        "snapshotNo": _mapping_value(snapshot_meta or {}, "no"),
        "snapshotNextUpdate": _mapping_value(snapshot_meta or {}, "nextUpdate"),
        "snapshotFetchedAt": _mapping_value(snapshot_meta or {}, "fetchedAt"),
        "snapshotGeneratedAt": _mapping_value(snapshot_meta or {}, "generatedAt"),
    }

    if include_detail:
        entry.update(
            {
                "metadataStatement": dict(metadata_mapping),
                "rawEntry": dict(entry_payload),
                "statusReports": [dict(report) for report in status_reports],
                "attestationCertificates": [str(value) for value in attestation_certificates if value],
                "attestationKeyIdentifiers": attestation_key_identifiers,
                "isLightweightEntry": False,
            }
        )
    else:
        entry.update(
            {
                "metadataStatement": None,
                "rawEntry": None,
                "statusReports": [],
                "attestationCertificates": [],
                "attestationKeyIdentifiers": [],
                "isLightweightEntry": True,
            }
        )

    return entry


def build_explorer_snapshot(
    payload: Mapping[str, Any],
    cache_info: Optional[Mapping[str, Any]] = None,
    *,
    source: str = "packaged",
    trust_anchor_status: Optional[bool] = True,
) -> Dict[str, Any]:
    snapshot_meta = build_snapshot_meta(payload, cache_info, source=source)
    entries = [
        build_explorer_entry(
            entry_payload,
            index=index,
            source=source,
            trust_anchor_status=trust_anchor_status,
            snapshot_meta=snapshot_meta,
            include_detail=False,
        )
        for index, entry_payload in enumerate(_extract_list(_mapping_value(payload, "entries")))
        if isinstance(entry_payload, Mapping)
    ]

    snapshot_meta["entryCount"] = len(entries)
    return {
        "meta": snapshot_meta,
        "entries": entries,
    }
