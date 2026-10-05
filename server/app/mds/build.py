"""The FIDO MDS explorer's entries and snapshots, built from a metadata BLOB's entries
(each statement's fields read by ``statement_fields``)."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from . import certificates as mds_certificates
from . import statement_fields

__all__ = [
    "build_entry_id",
    "build_bootstrap_snapshot",
    "build_explorer_entry",
    "build_explorer_snapshot",
    "build_snapshot_meta",
]

_ENTRY_HASH_PREFIX = "entry:"


def build_entry_id(entry_payload: Mapping[str, Any]) -> str:
    metadata = statement_fields.mapping_value(entry_payload, "metadataStatement", "metadata_statement")
    metadata_mapping = metadata if isinstance(metadata, Mapping) else {}

    aaguid = statement_fields.resolve_aaguid(entry_payload, metadata_mapping)
    if aaguid:
        return f"aaguid:{aaguid.lower()}"

    aaid = statement_fields.string_or_none(statement_fields.mapping_value(entry_payload, "aaid", "AAID")) or statement_fields.string_or_none(
        statement_fields.mapping_value(metadata_mapping, "aaid", "AAID")
    )
    if aaid:
        return f"aaid:{aaid}"

    key_ids = statement_fields.extract_attestation_key_identifiers(metadata_mapping, entry_payload)
    if key_ids:
        return f"akid:{key_ids[0].lower()}"

    digest = hashlib.sha256(statement_fields.canonical_json(entry_payload).encode("utf-8")).hexdigest()
    return f"{_ENTRY_HASH_PREFIX}{digest[:24]}"


def build_snapshot_meta(
    payload: Mapping[str, Any],
    cache_info: Mapping[str, Any] | None = None,
    *,
    source: str = "packaged",
) -> dict[str, Any]:
    metadata = dict(cache_info or {})
    generated_at = statement_fields.string_or_none(statement_fields.mapping_value(metadata, "generated_at"))
    if not generated_at:
        generated_at = datetime.now(timezone.utc).isoformat()

    entries = statement_fields.extract_list(statement_fields.mapping_value(payload, "entries"))
    return {
        "source": source,
        "legalHeader": statement_fields.string_or_none(statement_fields.mapping_value(payload, "legalHeader", "legal_header")) or "",
        "no": statement_fields.mapping_value(payload, "no"),
        "nextUpdate": statement_fields.string_or_none(statement_fields.mapping_value(payload, "nextUpdate", "next_update")),
        "entryCount": len(entries),
        "lastModified": statement_fields.string_or_none(statement_fields.mapping_value(metadata, "last_modified")),
        "lastModifiedIso": statement_fields.string_or_none(statement_fields.mapping_value(metadata, "last_modified_iso")),
        "etag": statement_fields.string_or_none(statement_fields.mapping_value(metadata, "etag")),
        "fetchedAt": statement_fields.string_or_none(statement_fields.mapping_value(metadata, "fetched_at")),
        "generatedAt": generated_at,
    }


def _authenticator_fields(
    metadata_mapping: Mapping[str, Any], entry_payload: Mapping[str, Any], status_reports: list[Mapping[str, Any]]
) -> dict[str, Any]:
    certification, certification_status = statement_fields.format_certification(status_reports)
    user_verification_list = statement_fields.extract_user_verification(
        statement_fields.mapping_value(metadata_mapping, "userVerificationDetails", "user_verification_details")
    )
    attachment_list = [
        statement_fields.format_enum(value)
        for value in statement_fields.extract_list(statement_fields.mapping_value(metadata_mapping, "attachmentHint", "attachment_hint"))
    ]
    transports_list = statement_fields.extract_transports(metadata_mapping)
    key_protection_list = [
        statement_fields.format_enum(value)
        for value in statement_fields.extract_list(statement_fields.mapping_value(metadata_mapping, "keyProtection", "key_protection"))
    ]
    algorithms_list = [
        statement_fields.format_enum(value)
        for value in statement_fields.extract_list(
            statement_fields.mapping_value(metadata_mapping, "authenticationAlgorithms", "authentication_algorithms")
        )
    ]
    return {
        "name": statement_fields.resolve_name(metadata_mapping, entry_payload),
        "protocol": statement_fields.format_protocol(
            statement_fields.mapping_value(metadata_mapping, "protocolFamily", "protocol_family")
            or statement_fields.mapping_value(metadata_mapping, "protocolType", "protocol_type")
        ),
        "certification": certification,
        "certificationStatus": certification_status,
        "id": statement_fields.resolve_identifier(entry_payload, metadata_mapping),
        "aaguid": statement_fields.resolve_aaguid(entry_payload, metadata_mapping),
        "icon": statement_fields.normalise_icon(
            statement_fields.mapping_value(metadata_mapping, "icon"),
            statement_fields.mapping_value(metadata_mapping, "iconType", "icon_type"),
        ),
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
    }


def _date_fields(entry_payload: Mapping[str, Any], status_reports: list[Mapping[str, Any]]) -> dict[str, Any]:
    raw_date = (
        statement_fields.string_or_none(statement_fields.mapping_value(entry_payload, "timeOfLastStatusChange", "time_of_last_status_change"))
        or statement_fields.latest_effective_date(status_reports)
    )
    return {
        "dateUpdated": statement_fields.format_date(raw_date),
        "dateTooltip": raw_date or None,
        "timeOfLastStatusChange": raw_date or None,
    }


def _provenance_fields(
    source: str,
    source_info: Mapping[str, Any] | None,
    trust_anchor_status: bool | None,
    snapshot_meta: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "source": source,
        "sourceInfo": dict(source_info) if isinstance(source_info, Mapping) else None,
        "trustAnchorStatus": trust_anchor_status,
        "snapshotNo": statement_fields.mapping_value(snapshot_meta or {}, "no"),
        "snapshotNextUpdate": statement_fields.mapping_value(snapshot_meta or {}, "nextUpdate"),
        "snapshotFetchedAt": statement_fields.mapping_value(snapshot_meta or {}, "fetchedAt"),
        "snapshotGeneratedAt": statement_fields.mapping_value(snapshot_meta or {}, "generatedAt"),
    }


def _detail_fields(
    entry_payload: Mapping[str, Any],
    metadata_mapping: Mapping[str, Any],
    status_reports: list[Mapping[str, Any]],
    attestation_certificates: list[Any],
    *,
    include_raw_entry: bool,
    compact_detail: bool,
) -> dict[str, Any]:
    return {
        "metadataStatement": (
            statement_fields.compact_metadata_statement(metadata_mapping) if compact_detail else dict(metadata_mapping)
        ),
        "rawEntry": dict(entry_payload) if include_raw_entry else None,
        "statusReports": [dict(report) for report in status_reports],
        "biometricStatusReports": [
            dict(report)
            for report in statement_fields.extract_list(statement_fields.mapping_value(entry_payload, "biometricStatusReports"))
            if isinstance(report, Mapping)
        ],
        "rogueListURL": statement_fields.string_or_none(statement_fields.mapping_value(entry_payload, "rogueListURL")),
        "rogueListHash": statement_fields.string_or_none(statement_fields.mapping_value(entry_payload, "rogueListHash")),
        "attestationCertificates": [str(value) for value in attestation_certificates if value],
        "attestationKeyIdentifiers": statement_fields.extract_attestation_key_identifiers(metadata_mapping, entry_payload),
        "isLightweightEntry": False,
    }


def _lightweight_fields() -> dict[str, Any]:
    return {
        "metadataStatement": None,
        "rawEntry": None,
        "statusReports": [],
        "attestationCertificates": [],
        "attestationKeyIdentifiers": [],
        "isLightweightEntry": True,
    }


def build_explorer_entry(
    entry_payload: Mapping[str, Any],
    *,
    index: int = 0,
    source: str,
    trust_anchor_status: bool | None,
    snapshot_meta: Mapping[str, Any] | None = None,
    include_detail: bool = False,
    include_raw_entry: bool = True,
    compact_detail: bool = False,
    source_info: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = statement_fields.mapping_value(entry_payload, "metadataStatement", "metadata_statement")
    metadata_mapping = metadata if isinstance(metadata, Mapping) else {}
    status_reports = [
        report for report in statement_fields.extract_list(statement_fields.mapping_value(entry_payload, "statusReports", "status_reports"))
        if isinstance(report, Mapping)
    ]
    attestation_certificates = statement_fields.extract_list(
        statement_fields.mapping_value(metadata_mapping, "attestationRootCertificates", "attestation_root_certificates")
    )

    entry: dict[str, Any] = {"entryId": build_entry_id(entry_payload), "index": index}
    entry.update(_authenticator_fields(metadata_mapping, entry_payload, status_reports))
    entry.update(mds_certificates.certificate_fields(attestation_certificates))
    entry.update(_date_fields(entry_payload, status_reports))
    entry.update(_provenance_fields(source, source_info, trust_anchor_status, snapshot_meta))
    if include_detail:
        entry.update(
            _detail_fields(
                entry_payload,
                metadata_mapping,
                status_reports,
                attestation_certificates,
                include_raw_entry=include_raw_entry,
                compact_detail=compact_detail,
            )
        )
    else:
        entry.update(_lightweight_fields())
    return entry


def build_explorer_snapshot(
    payload: Mapping[str, Any],
    cache_info: Mapping[str, Any] | None = None,
    *,
    source: str = "packaged",
    trust_anchor_status: bool | None = True,
    include_detail: bool = False,
    include_raw_entry: bool = True,
    compact_detail: bool = False,
) -> dict[str, Any]:
    snapshot_meta = build_snapshot_meta(payload, cache_info, source=source)
    entries = [
        build_explorer_entry(
            entry_payload,
            index=index,
            source=source,
            trust_anchor_status=trust_anchor_status,
            snapshot_meta=snapshot_meta,
            include_detail=include_detail,
            include_raw_entry=include_raw_entry,
            compact_detail=compact_detail,
        )
        for index, entry_payload in enumerate(statement_fields.extract_list(statement_fields.mapping_value(payload, "entries")))
        if isinstance(entry_payload, Mapping)
    ]

    snapshot_meta["entryCount"] = len(entries)
    return {
        "meta": snapshot_meta,
        "entries": entries,
    }


def build_bootstrap_snapshot(
    payload: Mapping[str, Any],
    cache_info: Mapping[str, Any] | None = None,
    *,
    source: str = "packaged",
    trust_anchor_status: bool | None = True,
) -> dict[str, Any]:
    return build_explorer_snapshot(
        payload,
        cache_info,
        source=source,
        trust_anchor_status=trust_anchor_status,
        include_detail=True,
        include_raw_entry=False,
        compact_detail=True,
    )
