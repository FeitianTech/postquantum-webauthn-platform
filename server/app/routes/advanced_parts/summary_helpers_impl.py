from __future__ import annotations

from typing import Any, Dict, Mapping, Optional


def _generate_storage_id_impl(advanced_module: Any, credential_id: str) -> str:
    base = credential_id[:24] if credential_id else advanced_module.uuid.uuid4().hex
    timestamp = format(int(advanced_module.time.time() * 1000), "x")
    random_segment = advanced_module.uuid.uuid4().hex
    return f"{base}::{timestamp}::{random_segment}"


def _summarize_properties_impl(
    advanced_module: Any,
    value: Any,
) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None

    summary: Dict[str, Any] = {}
    for key, item in value.items():
        if key in advanced_module._HEAVY_PROPERTY_KEYS:
            continue
        summary[key] = item
    return summary if summary else None


def _summarize_relying_party_impl(
    advanced_module: Any,
    value: Any,
) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None

    summary: Dict[str, Any] = {}
    for key, item in value.items():
        if key in advanced_module._HEAVY_RELYING_PARTY_KEYS:
            continue
        summary[key] = item
    return summary if summary else None


def _summarize_stored_credential_impl(
    advanced_module: Any,
    stored: Mapping[str, Any],
    storage_id: str,
) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}

    for key, value in stored.items():
        if key in advanced_module._HEAVY_CREDENTIAL_KEYS:
            continue
        summary[key] = value

    properties_summary = advanced_module._summarize_properties(summary.get("properties"))
    if properties_summary is not None:
        summary["properties"] = properties_summary
    elif "properties" in summary:
        summary.pop("properties")

    relying_party_summary = advanced_module._summarize_relying_party(summary.get("relyingParty"))
    if relying_party_summary is not None:
        summary["relyingParty"] = relying_party_summary
    elif "relyingParty" in summary:
        summary.pop("relyingParty")

    summary["storageId"] = storage_id
    summary["localStorageId"] = storage_id
    summary["artifactVersion"] = 1
    summary["hasServerArtifact"] = True

    return summary
