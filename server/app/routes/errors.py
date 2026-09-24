"""Answers for errors any route can raise."""
from __future__ import annotations

import logging

from flask import jsonify, request

from ..storage.common import InvalidStorageIdentifier, StorageReadError

logger = logging.getLogger(__name__)


def invalid_storage_identifier(exc: InvalidStorageIdentifier):
    # The store refused a caller's name before touching a path (a traversal
    # attempt, say): the request is at fault and there is nothing to debug, so
    # one line in the log and no traceback.
    logger.warning("Refused a storage name in %s %s: %s", request.method, request.path, exc)
    return jsonify({"error": f"Invalid credential name: {exc}."}), 400


def storage_read_error(exc: StorageReadError):
    # The store could not be read (an I/O or Cloud Storage error): not the
    # request's fault, and not "nothing stored". One line naming the copy and
    # its cause; the answer names neither.
    logger.warning("Could not read the store in %s %s: %s (%r)", request.method, request.path, exc, exc.__cause__)
    return jsonify({"error": "The stored credentials could not be read. Please try again."}), 503


def init_app(app) -> None:
    app.register_error_handler(InvalidStorageIdentifier, invalid_storage_identifier)
    app.register_error_handler(StorageReadError, storage_read_error)
