from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from flask import jsonify, request

from ... import credential_artifacts
from ...webauthn import metadata


def api_get_advanced_credential_artifact(storage_id: str):
    metadata_session_id = metadata.ensure_metadata_session_id()
    artifact = credential_artifacts.load_credential_artifact(storage_id, session_id=metadata_session_id)
    if artifact is None:
        return jsonify({"error": "Credential artifact not found."}), 404

    return jsonify({"storageId": storage_id, "artifact": artifact})


def api_get_advanced_credential_artifacts_bulk():
    data = request.get_json(silent=True) or {}
    raw_storage_ids = data.get("storageIds")
    if not isinstance(raw_storage_ids, list):
        return jsonify({"error": "storageIds must be an array."}), 400

    storage_ids: list[str] = []
    seen = set()
    for candidate in raw_storage_ids:
        if not isinstance(candidate, str):
            continue
        trimmed = candidate.strip()
        if not trimmed or trimmed in seen:
            continue
        seen.add(trimmed)
        storage_ids.append(trimmed)

    metadata_session_id = metadata.ensure_metadata_session_id()
    artifacts: dict[str, Any] = {}
    for storage_id in storage_ids:
        artifact = credential_artifacts.load_credential_artifact(storage_id, session_id=metadata_session_id)
        if artifact is not None:
            artifacts[storage_id] = artifact

    return jsonify({"artifacts": artifacts})


def api_put_advanced_credential_artifact(storage_id: str):
    data = request.get_json(silent=True) or {}
    merge = True
    if isinstance(data, Mapping) and "merge" in data:
        merge = bool(data.get("merge"))

    artifact_payload = None
    if isinstance(data, Mapping):
        candidate = data.get("artifact") or data.get("payload")
        if isinstance(candidate, Mapping):
            artifact_payload = candidate

    if artifact_payload is None:
        return jsonify({"error": "Artifact payload must be an object."}), 400

    metadata_session_id = metadata.ensure_metadata_session_id()
    if not credential_artifacts.store_credential_artifact(
        storage_id,
        artifact_payload,
        merge=merge,
        session_id=metadata_session_id,
    ):
        return jsonify({"error": "Unable to store artifact."}), 400

    return jsonify({"status": "OK"})


def api_put_advanced_credential_snapshot(storage_id: str):
    data = request.get_json(silent=True) or {}
    snapshot = data.get("snapshot")
    if snapshot is not None and not isinstance(snapshot, Mapping):
        return jsonify({"error": "Snapshot must be an object."}), 400

    payload = {"registrationDetailSnapshot": snapshot}
    metadata_session_id = metadata.ensure_metadata_session_id()
    if not credential_artifacts.store_credential_artifact(
        storage_id,
        payload,
        merge=True,
        session_id=metadata_session_id,
    ):
        return jsonify({"error": "Unable to store artifact snapshot."}), 400

    return jsonify({"status": "OK"})


def api_delete_advanced_credential_artifact(storage_id: str):
    if not isinstance(storage_id, str) or not storage_id.strip():
        return jsonify(
            {"status": "failed", "error": "Invalid storage identifier."},
        ), 400

    metadata_session_id = metadata.ensure_metadata_session_id()
    status = credential_artifacts.delete_credential_artifact_with_status(
        storage_id,
        session_id=metadata_session_id,
    )

    if status == "deleted":
        return jsonify({"status": "deleted"})

    if status == "absent":
        return jsonify({"status": "absent"})

    return jsonify(
        {"status": "failed", "error": "Unable to delete credential artifact."},
    ), 500
