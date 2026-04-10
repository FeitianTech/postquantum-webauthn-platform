from __future__ import annotations

from typing import Any, Dict, List, Mapping


def api_get_advanced_credential_artifact_impl(advanced_module: Any, storage_id: str):
    metadata_session_id = advanced_module.ensure_metadata_session_id()
    artifact = advanced_module.load_credential_artifact(storage_id, session_id=metadata_session_id)
    if artifact is None:
        return advanced_module.jsonify({"error": "Credential artifact not found."}), 404

    return advanced_module.jsonify({"storageId": storage_id, "artifact": artifact})


def api_get_advanced_credential_artifacts_bulk_impl(advanced_module: Any):
    data = advanced_module.request.get_json(silent=True) or {}
    raw_storage_ids = data.get("storageIds")
    if not isinstance(raw_storage_ids, list):
        return advanced_module.jsonify({"error": "storageIds must be an array."}), 400

    storage_ids: List[str] = []
    seen = set()
    for candidate in raw_storage_ids:
        if not isinstance(candidate, str):
            continue
        trimmed = candidate.strip()
        if not trimmed or trimmed in seen:
            continue
        seen.add(trimmed)
        storage_ids.append(trimmed)

    metadata_session_id = advanced_module.ensure_metadata_session_id()
    artifacts: Dict[str, Any] = {}
    for storage_id in storage_ids:
        artifact = advanced_module.load_credential_artifact(storage_id, session_id=metadata_session_id)
        if artifact is not None:
            artifacts[storage_id] = artifact

    return advanced_module.jsonify({"artifacts": artifacts})


def api_put_advanced_credential_artifact_impl(advanced_module: Any, storage_id: str):
    data = advanced_module.request.get_json(silent=True) or {}
    merge = True
    if isinstance(data, Mapping) and "merge" in data:
        merge = bool(data.get("merge"))

    artifact_payload = None
    if isinstance(data, Mapping):
        candidate = data.get("artifact") or data.get("payload")
        if isinstance(candidate, Mapping):
            artifact_payload = candidate

    if artifact_payload is None:
        return advanced_module.jsonify({"error": "Artifact payload must be an object."}), 400

    metadata_session_id = advanced_module.ensure_metadata_session_id()
    if not advanced_module.store_credential_artifact(
        storage_id,
        artifact_payload,
        merge=merge,
        session_id=metadata_session_id,
    ):
        return advanced_module.jsonify({"error": "Unable to store artifact."}), 400

    return advanced_module.jsonify({"status": "OK"})


def api_put_advanced_credential_snapshot_impl(advanced_module: Any, storage_id: str):
    data = advanced_module.request.get_json(silent=True) or {}
    snapshot = data.get("snapshot")
    if snapshot is not None and not isinstance(snapshot, Mapping):
        return advanced_module.jsonify({"error": "Snapshot must be an object."}), 400

    payload = {"registrationDetailSnapshot": snapshot}
    metadata_session_id = advanced_module.ensure_metadata_session_id()
    if not advanced_module.store_credential_artifact(
        storage_id,
        payload,
        merge=True,
        session_id=metadata_session_id,
    ):
        return advanced_module.jsonify({"error": "Unable to store artifact snapshot."}), 400

    return advanced_module.jsonify({"status": "OK"})


def api_delete_advanced_credential_artifact_impl(advanced_module: Any, storage_id: str):
    if not isinstance(storage_id, str) or not storage_id.strip():
        return advanced_module.jsonify(
            {"status": "failed", "error": "Invalid storage identifier."},
        ), 400

    metadata_session_id = advanced_module.ensure_metadata_session_id()
    status = advanced_module.delete_credential_artifact_with_status(
        storage_id,
        session_id=metadata_session_id,
    )

    if status == "deleted":
        return advanced_module.jsonify({"status": "deleted"})

    if status == "absent":
        return advanced_module.jsonify({"status": "absent"})

    return advanced_module.jsonify(
        {"status": "failed", "error": "Unable to delete credential artifact."},
    ), 500
