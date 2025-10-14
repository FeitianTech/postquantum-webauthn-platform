"""Refresh the FIDO MDS cache using the scheduled cron job."""
from __future__ import annotations

import logging
import sys
from typing import NoReturn

from server.server.metadata import (
    MetadataDownloadError,
    MetadataVerificationError,
    load_metadata_cache_entry,
    refresh_metadata_cache,
)


def _configure_logging() -> logging.Logger:
    """Configure structured logging for cron execution."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    return logging.getLogger("mds_cron")


def main() -> int:
    """Entry point for the cron-driven metadata refresh."""

    logger = _configure_logging()
    logger.info("Starting FIDO MDS metadata refresh.")

    try:
        result = refresh_metadata_cache()
    except MetadataDownloadError as exc:
        logger.error("Failed to download metadata: %s", exc)
        return 1
    except MetadataVerificationError as exc:
        logger.error("Failed to verify downloaded metadata: %s", exc)
        return 1
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.exception("Unexpected error while refreshing metadata: %s", exc)
        return 1

    if result.blob_updated:
        logger.info(
            "Downloaded new metadata blob (%d bytes).",
            result.blob_bytes_written,
        )
    else:
        logger.info("Metadata blob already up to date.")

    if result.verified_payload_updated:
        logger.info(
            "Stored verified metadata snapshot with %d entries (%d bytes).",
            result.entry_count,
            result.verified_payload_bytes,
        )
    else:
        logger.info(
            "Verified metadata snapshot already up to date with %d entries.",
            result.entry_count,
        )

    if result.blob_last_modified:
        logger.info("Last-Modified header: %s", result.blob_last_modified)

    cache_state = load_metadata_cache_entry()
    fetched_at = cache_state.get("fetched_at") if cache_state else None
    if fetched_at:
        logger.info("Metadata last fetched at: %s", fetched_at)

    logger.info("Completed FIDO MDS metadata refresh successfully.")
    return 0


def run() -> NoReturn:
    """Execute the cron refresh and exit with the appropriate status code."""

    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover - CLI execution
    run()
