"""Repository upload helpers for metadata JSON payloads."""
from __future__ import annotations


def _safe_metadata_repo_filename(filename: str) -> str:
    candidate = os.path.basename(filename.strip()) if isinstance(filename, str) else ""
    if not candidate:
        return "metadata.json"
    return candidate


def maybe_store_uploaded_metadata_file(filename: str, content: bytes) -> bool:
    """Upload ``content`` to the credential log repository metadata folder."""

    if not content or not is_logging_enabled():
        return False

    safe_name = _safe_metadata_repo_filename(filename)

    try:
        existing_items = github_list_directory(_METADATA_REPO_FOLDER)
    except Exception as exc:  # pragma: no cover - best effort logging
        app.logger.warning("Unable to list metadata repository contents: %s", exc)
        return False

    blob_sha = git_blob_sha(content)
    existing_sha_for_name: Optional[str] = None
    path_for_name: Optional[str] = None

    for item in existing_items:
        if not isinstance(item, Mapping):
            continue
        if item.get("type") != "file":
            continue

        item_sha = item.get("sha")
        if isinstance(item_sha, str) and item_sha == blob_sha:
            app.logger.info(
                "Skipping upload of metadata file %s; identical content already present as %s.",
                safe_name,
                item.get("name"),
            )
            return False

        if item.get("name") == safe_name and isinstance(item_sha, str):
            existing_sha_for_name = item_sha
            path_value = item.get("path")
            if isinstance(path_value, str):
                path_for_name = path_value

    remote_path = path_for_name or f"{_METADATA_REPO_FOLDER}/{safe_name}"
    action = "update" if existing_sha_for_name else "add"
    message = f"metadata: {action} {safe_name}"

    try:
        github_upload_file(remote_path, content, message, sha=existing_sha_for_name)
        return True
    except Exception as exc:  # pragma: no cover - best effort logging
        app.logger.warning("Failed to upload metadata file %s: %s", safe_name, exc)
        return False
