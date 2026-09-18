from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from typing import Any

from . import constants


def _generate_storage_id_impl(credential_id: str) -> str:
    base = credential_id[:24] if credential_id else uuid.uuid4().hex
    timestamp = format(int(time.time() * 1000), "x")
    random_segment = uuid.uuid4().hex
    return f"{base}::{timestamp}::{random_segment}"


def _summarize_properties_impl(
    value: Any,
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None

    summary: dict[str, Any] = {}
    for key, item in value.items():
        if key in constants.HEAVY_PROPERTY_KEYS:
            continue
        summary[key] = item
    return summary if summary else None


def _summarize_relying_party_impl(
    value: Any,
) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None

    summary: dict[str, Any] = {}
    for key, item in value.items():
        if key in constants.HEAVY_RELYING_PARTY_KEYS:
            continue
        summary[key] = item
    return summary if summary else None


def _summarize_stored_credential_impl(
    stored: Mapping[str, Any],
    storage_id: str,
) -> dict[str, Any]:
    summary: dict[str, Any] = {}

    for key, value in stored.items():
        if key in constants.HEAVY_CREDENTIAL_KEYS:
            continue
        summary[key] = value

    properties_summary = _summarize_properties_impl(summary.get("properties"))
    if properties_summary is not None:
        summary["properties"] = properties_summary
    elif "properties" in summary:
        summary.pop("properties")

    relying_party_summary = _summarize_relying_party_impl(summary.get("relyingParty"))
    if relying_party_summary is not None:
        summary["relyingParty"] = relying_party_summary
    elif "relyingParty" in summary:
        summary.pop("relyingParty")

    summary["storageId"] = storage_id
    summary["localStorageId"] = storage_id
    summary["artifactVersion"] = 1
    summary["hasServerArtifact"] = True

    return summary
