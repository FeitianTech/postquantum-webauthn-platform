"""Answers for errors any route can raise."""
from __future__ import annotations

import logging

from flask import jsonify, request

from ..storage.common import InvalidStorageIdentifier

logger = logging.getLogger(__name__)


def invalid_storage_identifier(exc: InvalidStorageIdentifier):
    # The store refused a caller's name before touching a path (a traversal
    # attempt, say): the request is at fault and there is nothing to debug, so
    # one line in the log and no traceback.
    logger.warning("Refused a storage name in %s %s: %s", request.method, request.path, exc)
    return jsonify({"error": f"Invalid credential name: {exc}."}), 400


def init_app(app) -> None:
    app.register_error_handler(InvalidStorageIdentifier, invalid_storage_identifier)
