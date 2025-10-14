"""Scheduled updater for the FIDO MDS metadata cache."""
from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from typing import Optional, Tuple

from fido2.mds3 import parse_blob

from server.server.config import (
    FIDO_METADATA_TRUST_ROOT_CERT,
    MDS_CACHE_DIR,
    MDS_METADATA_PATH,
    MDS_METADATA_URL,
    MDS_VERIFIED_PAYLOAD_PATH,
    app,
)
from server.server.metadata import (
    MetadataDownloadError,
    combine_with_local_metadata,
    download_metadata_blob,
    load_metadata_cache_entry,
)


@dataclass(frozen=True)
class UpdateOutcome:
    success: bool
    updated: bool = False
    bytes_written: int = 0
    last_modified_iso: Optional[str] = None


def _configure_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    root_logger = logging.getLogger("mds-cron")
    if not root_logger.handlers:
        # Ensure at least one handler exists when basicConfig is ignored.
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

    if logging.getLogger().handlers:
        app.logger.handlers = logging.getLogger().handlers
    app.logger.setLevel(logging.INFO)

    return root_logger


def _log_download_result(
    logger: logging.Logger,
    updated: bool,
    bytes_written: int,
    last_modified: str | None,
) -> None:
    if updated:
        if last_modified:
            logger.info(
                "Downloaded new FIDO MDS blob (%d bytes, Last-Modified: %s)",
                bytes_written,
                last_modified,
            )
        else:
            logger.info("Downloaded new FIDO MDS blob (%d bytes)", bytes_written)
    else:
        if last_modified:
            logger.info("FIDO MDS blob already current (Last-Modified: %s)", last_modified)
        else:
            logger.info("FIDO MDS blob already current; no download needed")


def _write_verified_payload(payload) -> None:
    target_dir = os.path.dirname(MDS_VERIFIED_PAYLOAD_PATH) or "."
    os.makedirs(target_dir, exist_ok=True)
    serialized = dict(payload)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=target_dir, delete=False
    ) as temp_file:
        json.dump(serialized, temp_file, indent=2, sort_keys=True)
        temp_file.write("\n")
        temp_path = temp_file.name
    shutil.move(temp_path, MDS_VERIFIED_PAYLOAD_PATH)


def perform_update(logger: Optional[logging.Logger] = None) -> UpdateOutcome:
    """Refresh the cached MDS metadata, returning an outcome summary."""

    logger = logger or logging.getLogger("mds-updater")
    logger.info("Starting scheduled FIDO MDS metadata refresh from %s", MDS_METADATA_URL)

    os.makedirs(MDS_CACHE_DIR, exist_ok=True)

    try:
        download_outcome: Tuple[bool, int, str | None] = download_metadata_blob()
    except MetadataDownloadError as exc:
        logger.error("Unable to download metadata from FIDO MDS: %s", exc)
        return UpdateOutcome(success=False)
    except Exception:
        logger.exception("Unexpected error while downloading metadata from FIDO MDS")
        return UpdateOutcome(success=False)

    updated, bytes_written, last_modified = download_outcome
    _log_download_result(logger, updated, bytes_written, last_modified)

    if not os.path.exists(MDS_METADATA_PATH):
        logger.error("Metadata blob %s is missing after download step", MDS_METADATA_PATH)
        return UpdateOutcome(success=False)

    try:
        with open(MDS_METADATA_PATH, "rb") as blob_file:
            blob_data = blob_file.read()
    except OSError:
        logger.exception("Failed to read metadata blob from %s", MDS_METADATA_PATH)
        return UpdateOutcome(success=False, updated=updated, bytes_written=bytes_written, last_modified_iso=last_modified)

    try:
        verified_payload = parse_blob(blob_data, FIDO_METADATA_TRUST_ROOT_CERT)
    except Exception:
        logger.exception("Failed to verify metadata blob signature")
        return UpdateOutcome(success=False, updated=updated, bytes_written=bytes_written, last_modified_iso=last_modified)

    combined_payload = combine_with_local_metadata(verified_payload)
    if combined_payload is None:
        logger.error("No metadata payload available after verification; aborting update")
        return UpdateOutcome(success=False, updated=updated, bytes_written=bytes_written, last_modified_iso=last_modified)

    try:
        _write_verified_payload(combined_payload)
    except Exception:
        logger.exception(
            "Failed to write verified metadata payload to %s",
            MDS_VERIFIED_PAYLOAD_PATH,
        )
        return UpdateOutcome(success=False, updated=updated, bytes_written=bytes_written, last_modified_iso=last_modified)

    logger.info("Stored verified metadata payload at %s", MDS_VERIFIED_PAYLOAD_PATH)

    cache_state = load_metadata_cache_entry()
    if cache_state.get("last_modified_iso"):
        logger.info("Latest Last-Modified: %s", cache_state["last_modified_iso"])
    if cache_state.get("etag"):
        logger.info("Latest ETag: %s", cache_state["etag"])
    if cache_state.get("fetched_at"):
        logger.info("Metadata fetched at: %s", cache_state["fetched_at"])

    logger.info("FIDO MDS metadata refresh complete")

    return UpdateOutcome(
        success=True,
        updated=updated,
        bytes_written=bytes_written,
        last_modified_iso=last_modified,
    )


def main() -> int:
    logger = _configure_logging()
    outcome = perform_update(logger=logger)
    return 0 if outcome.success else 1


if __name__ == "__main__":
    sys.exit(main())
