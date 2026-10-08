"""Metadata entry payload normalisation and expansion helpers."""
from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from fido2.mds3 import MetadataBlobPayload, MetadataBlobPayloadEntry

# What an uploaded statement is given for a required member it lacks.
_METADATA_STATEMENT_REQUIRED_DEFAULTS: Mapping[str, Any] = {
    "description": "",
    "authenticatorVersion": 0,
    "schema": 3,
    "upv": [],
    "attestationTypes": [],
    "userVerificationDetails": [],
    "keyProtection": [],
    "matcherProtection": [],
    "attachmentHint": [],
    "tcDisplay": [],
    "attestationRootCertificates": [],
}


def _clone_json_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    try:
        return json.loads(json.dumps(value))
    except (TypeError, ValueError):
        return None


def _normalise_status_reports(raw: Mapping[str, Any]) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    value = raw.get("statusReports")
    if not isinstance(value, list):
        return reports

    for entry in value:
        cloned = _clone_json_value(entry)
        if isinstance(cloned, dict):
            reports.append(cloned)
    return reports


def _normalise_attestation_identifiers(raw: Mapping[str, Any]) -> list[str] | None:
    identifiers = raw.get("attestationCertificateKeyIdentifiers")
    if not isinstance(identifiers, list):
        return None

    filtered: list[str] = []
    for identifier in identifiers:
        if isinstance(identifier, str):
            trimmed = identifier.strip()
            if trimmed:
                filtered.append(trimmed)
    return filtered or None


def _normalise_metadata_statement(raw: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    legal_header: str | None = None
    raw_legal_header = raw.get("legalHeader")
    if isinstance(raw_legal_header, str):
        legal_header = raw_legal_header.strip() or None

    metadata_source: Mapping[str, Any] = raw
    nested_statement = raw.get("metadataStatement")
    if isinstance(nested_statement, Mapping):
        metadata_source = nested_statement

    excluded_keys = {
        "statusReports",
        "timeOfLastStatusChange",
        "attestationCertificateKeyIdentifiers",
        "aaid",
        "aaguid",
    }

    metadata_statement: dict[str, Any] = {}
    for key, value in metadata_source.items():
        if metadata_source is raw and key in excluded_keys:
            continue

        cloned = _clone_json_value(value)
        if cloned is not None:
            metadata_statement[key] = cloned

    if legal_header and "legalHeader" not in metadata_statement:
        metadata_statement["legalHeader"] = legal_header

    description = metadata_statement.get("description")
    if not isinstance(description, str):
        metadata_statement["description"] = _METADATA_STATEMENT_REQUIRED_DEFAULTS["description"]

    authenticator_version = metadata_statement.get("authenticatorVersion")
    if not isinstance(authenticator_version, int):
        metadata_statement["authenticatorVersion"] = _METADATA_STATEMENT_REQUIRED_DEFAULTS["authenticatorVersion"]

    schema = metadata_statement.get("schema")
    if not isinstance(schema, int):
        metadata_statement["schema"] = _METADATA_STATEMENT_REQUIRED_DEFAULTS["schema"]

    for key in (
        "upv",
        "attestationTypes",
        "userVerificationDetails",
        "keyProtection",
        "matcherProtection",
        "attachmentHint",
        "tcDisplay",
        "attestationRootCertificates",
    ):
        value = metadata_statement.get(key)
        if not isinstance(value, list):
            default_value = _METADATA_STATEMENT_REQUIRED_DEFAULTS[key]
            metadata_statement[key] = list(default_value) if isinstance(default_value, list) else default_value

    return metadata_statement, legal_header


# fido2 2.2.1 reads a biometric status report's ``effectiveDate`` as an integer,
# where MDS3 writes a date ("2026-02-01"), so it refuses an entry that has one.
# Nothing reads those reports from fido2's dataclasses (they are shown from the
# entry's JSON), so they are left out of what fido2 parses.
_FIDO2_MISREADS = ("biometricStatusReports",)

# fido2 2.2.1 requires a statement's ``userVerificationDetails`` and
# ``attachmentHint``, which MDS leaves out of a passkey provider's statement
# (Dashlane's, from no. 290), so it refuses the entry and with it the payload.
# Neither is read from fido2's dataclasses; what fido2 parses has them empty.
_FIDO2_REQUIRED_LISTS = ("userVerificationDetails", "attachmentHint")


def _fido2_readable(entry: Mapping[str, Any]) -> dict[str, Any]:
    readable = {key: value for key, value in entry.items() if key not in _FIDO2_MISREADS}
    statement = readable.get("metadataStatement")
    if isinstance(statement, Mapping) and any(key not in statement for key in _FIDO2_REQUIRED_LISTS):
        readable["metadataStatement"] = {**{key: [] for key in _FIDO2_REQUIRED_LISTS}, **statement}
    return readable


def parse_entry(raw: Mapping[str, Any]) -> MetadataBlobPayloadEntry:
    """An entry's JSON as fido2's ``MetadataBlobPayloadEntry``, as ``_fido2_readable`` gives it."""

    return MetadataBlobPayloadEntry.from_dict(_fido2_readable(raw))


def parse_payload(raw: Mapping[str, Any]) -> MetadataBlobPayload:
    """A BLOB payload's JSON as fido2's ``MetadataBlobPayload``, each entry as ``parse_entry`` reads it."""

    entries = raw.get("entries")
    readable = [
        _fido2_readable(entry) if isinstance(entry, Mapping) else entry
        for entry in (entries if isinstance(entries, list) else [])
    ]
    return MetadataBlobPayload.from_dict({**raw, "entries": readable} if isinstance(entries, list) else raw)


# An uploaded BLOB entry's fields that are read, trimmed and checked below; the
# statement and the BLOB's legal header go into the statement.
_READ_BELOW = frozenset(
    {
        "metadataStatement",
        "legalHeader",
        "statusReports",
        "timeOfLastStatusChange",
        "attestationCertificateKeyIdentifiers",
        "aaid",
        "aaguid",
    }
)


def build_metadata_entry_components(raw: Mapping[str, Any]) -> tuple[
    MetadataBlobPayloadEntry,
    str | None,
    dict[str, Any],
]:
    if not isinstance(raw, Mapping):
        raise TypeError("Metadata JSON must be an object.")

    payload: dict[str, Any] = {}
    if isinstance(raw.get("metadataStatement"), Mapping):
        # A BLOB entry: every entry-level field it has (its biometric reports, its
        # rogue list, one no MDS3 version defines yet), as it has it; those below
        # are read as fido2 needs them.
        for key, value in raw.items():
            cloned = _clone_json_value(value) if key not in _READ_BELOW else None
            if cloned is not None:
                payload[key] = cloned
    payload["statusReports"] = _normalise_status_reports(raw)

    time_of_last_status_change = raw.get("timeOfLastStatusChange")
    if isinstance(time_of_last_status_change, str) and time_of_last_status_change.strip():
        payload["timeOfLastStatusChange"] = time_of_last_status_change.strip()
    else:
        payload["timeOfLastStatusChange"] = datetime.now(timezone.utc).date().isoformat()

    identifiers = _normalise_attestation_identifiers(raw)
    if identifiers:
        payload["attestationCertificateKeyIdentifiers"] = identifiers

    if isinstance(raw.get("aaid"), str) and raw["aaid"].strip():
        payload["aaid"] = raw["aaid"].strip()

    if isinstance(raw.get("aaguid"), str) and raw["aaguid"].strip():
        payload["aaguid"] = raw["aaguid"].strip()

    metadata_statement, legal_header = _normalise_metadata_statement(raw)
    payload["metadataStatement"] = metadata_statement

    entry = parse_entry(payload)
    payload_clone = json.loads(json.dumps(payload))
    return entry, legal_header, payload_clone


def expand_metadata_entry_payloads(raw: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Expand a JSON payload into individual metadata entries.

    The FIDO Metadata BLOB contains an ``entries`` list with metadata
    statements. Uploaded JSON snippets may either provide a single metadata
    entry object or a structure mirroring the BLOB shape. This helper
    normalises both cases into a list of per-entry payload mappings that can be
    handed to :func:`build_metadata_entry_components`.
    """

    if not isinstance(raw, Mapping):
        raise TypeError("Metadata JSON must be an object.")

    entries_value = raw.get("entries")
    if not isinstance(entries_value, list):
        return [raw]

    if not entries_value:
        raise ValueError("Metadata JSON does not contain any entries.")

    legal_header: str | None = None
    raw_legal_header = raw.get("legalHeader")
    if isinstance(raw_legal_header, str) and raw_legal_header.strip():
        legal_header = raw_legal_header.strip()

    expanded: list[Mapping[str, Any]] = []
    for index, entry in enumerate(entries_value):
        if not isinstance(entry, Mapping):
            raise ValueError(f"Entry {index + 1} is not a JSON object.")

        cloned = _clone_json_value(entry)
        if not isinstance(cloned, dict):
            raise ValueError(f"Entry {index + 1} could not be cloned into a JSON object.")

        if legal_header and "legalHeader" not in cloned:
            cloned["legalHeader"] = legal_header

        expanded.append(cloned)

    return expanded


def _normalise_aaguid(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().replace("-", "").lower()
    return cleaned or None


def _extract_entry_aaguid(entry: MetadataBlobPayloadEntry) -> str | None:
    direct = _normalise_aaguid(getattr(entry, "aaguid", None))
    if direct:
        return direct

    statement = getattr(entry, "metadata_statement", None)
    if statement is None:
        statement = getattr(entry, "metadataStatement", None)
    if isinstance(statement, Mapping):
        return _normalise_aaguid(statement.get("aaguid"))
    return None
