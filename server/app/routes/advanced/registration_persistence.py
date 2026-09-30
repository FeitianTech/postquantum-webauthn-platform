"""Advanced registration complete: storing the credential artifact and answering.

``finalize_registration_completion`` stores the artifact (a failure is a 500 and
nothing else happens), records the device-log event, and builds the OK answer
from the artifact's summary.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from flask import jsonify

from ...storage import credential_artifacts, github_mirror
from .. import binary_helpers
from . import summary

logger = logging.getLogger(__name__)

_ARTIFACT_NOT_STORED = "Unable to persist credential artifact."


def _store_artifact(
    stored_credential: dict[str, Any], metadata_session_id: str, username: str
) -> tuple[dict[str, Any] | None, str | None, Any]:
    """Store the credential artifact: its record and storage id, or the 500 to answer."""

    artifact_record = json.loads(json.dumps(stored_credential))
    storage_id_source = (
        artifact_record.get("credentialIdBase64Url")
        or artifact_record.get("credentialIdHex")
        or ""
    )
    storage_id = summary._generate_storage_id(str(storage_id_source))

    artifact_payload = {"schemaVersion": 1, "storedCredential": artifact_record}
    try:
        artifact_stored = credential_artifacts.store_credential_artifact(
            storage_id,
            artifact_payload,
            session_id=metadata_session_id,
        )
    except Exception:
        logger.exception(
            "Failed to store advanced credential artifact for user %s",
            username,
        )
        return None, None, (jsonify({"error": _ARTIFACT_NOT_STORED}), 500)

    if not artifact_stored:
        logger.error(
            "Advanced credential artifact was not stored for user %s",
            username,
        )
        return None, None, (jsonify({"error": _ARTIFACT_NOT_STORED}), 500)
    return artifact_record, storage_id, None


def _record_registration_event(
    *,
    metadata_summary: Any,
    resolved_rp_id: str,
    aaguid_bytes: bytes | None,
    attestation_object_b64: Any,
) -> None:
    metadata_description: str | None = None
    if isinstance(metadata_summary, Mapping):
        raw_description = metadata_summary.get("description")
        if isinstance(raw_description, str):
            metadata_description = raw_description

    event = github_mirror.RegistrationEvent(
        timestamp=datetime.now(timezone.utc),
        rp_id=resolved_rp_id,
        aaguid=aaguid_bytes or None,
        device_name_mds=metadata_description,
        attestation_object=binary_helpers.decode_base64url_bytes(attestation_object_b64),
    )

    github_mirror.record_registration_event(event)


def finalize_registration_completion(
    *,
    stored_credential: dict[str, Any],
    rp_info: dict[str, Any],
    metadata_summary: Any,
    metadata_session_id: str,
    username: str,
    warnings: list[str],
    debug_info: dict[str, Any],
    algoname: str,
    resolved_rp_id: str,
    aaguid_bytes: bytes | None,
    attestation_object_b64: Any,
) -> Any:
    artifact_record, storage_id, error_response = _store_artifact(stored_credential, metadata_session_id, username)
    if error_response is not None:
        return error_response

    summary_credential = summary._summarize_stored_credential(artifact_record, storage_id)

    _record_registration_event(
        metadata_summary=metadata_summary,
        resolved_rp_id=resolved_rp_id,
        aaguid_bytes=aaguid_bytes,
        attestation_object_b64=attestation_object_b64,
    )

    response_payload: dict[str, Any] = {
        "status": "OK",
        "algo": algoname,
        **debug_info,
        "relyingParty": rp_info,
        "storedCredential": summary_credential,
    }
    if warnings:
        response_payload["warnings"] = warnings

    return jsonify(response_payload)
