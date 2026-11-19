"""Answers for errors any route can raise.

Under ``/api/`` every HTTP error is answered in JSON, ``{"error": sentence}``, the
status kept: ``abort()``, a path no route holds, a method a route does not take, and
(where exceptions are not propagated, as in production) an unhandled exception's 500.
The site's GET catch-all holds every path, so it is set aside: a path under ``/api/``
no API route holds answers 404 whatever the method, and one a route holds for other
methods answers 405 naming them (a GET of ``/api/codec`` too). Pages keep Werkzeug's
answers and the export's 404 page.
"""
from __future__ import annotations

import logging

from flask import current_app, jsonify, request
from werkzeug.exceptions import (
    HTTPException,
    MethodNotAllowed,
    NotFound,
    RequestEntityTooLarge,
)

from ..storage.common import (
    InvalidStorageIdentifier,
    StorageQuotaExceeded,
    StorageReadError,
)
from . import json_body

logger = logging.getLogger(__name__)

# What an API client is told for an HTTP error no route answered itself.
_API_SENTENCES = {
    400: "The server could not read this request.",
    404: "There is nothing at this address.",
    405: "This address does not take this method.",
    500: "The server failed while handling this request.",
}
# The site's catch-all (routes/web_export.py): GET only, for pages, and every path.
_SITE_ENDPOINT = "web_export.page"
_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")


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


def storage_quota_exceeded(exc: StorageQuotaExceeded):
    # A write that would take a visitor's namespace past a quota, refused before
    # anything was written: the visitor's to act on, so its sentence, and one line.
    logger.warning("Refused a write past a namespace's quota in %s %s: %s", request.method, request.path, exc.sentence)
    return jsonify({"error": exc.sentence}), exc.status


def too_large_answer(limit: int | None):
    """The 413 answer for a body over ``limit`` bytes, as JSON like every other answer."""

    size = f" of {limit} bytes" if limit else ""
    return jsonify({"error": f"The request is larger than the limit{size} this server accepts."}), 413


def request_entity_too_large(exc: RequestEntityTooLarge):
    # A body over the limit config/request_limits.py sets, refused before any
    # route read it.
    logger.warning("Refused an oversized body in %s %s (%s bytes)", request.method, request.path, request.content_length)
    return too_large_answer(request.max_content_length)


def json_nested_too_deep(exc: json_body.NestedTooDeep):
    # Refused before it was parsed: Python's JSON reader would go as deep as the text.
    logger.warning("Refused a JSON body nested too deep in %s %s", request.method, request.path)
    return jsonify({"error": f"The request body is JSON nested more than {json_body.MAX_DEPTH} deep, deeper than this server reads."}), 400


def json_too_many_values(exc: json_body.TooManyValues):
    # Refused before it was parsed: Python's reader keeps every value, 210 MiB of them for 8 MiB of "{},".
    logger.warning("Refused a JSON body holding too many values in %s %s", request.method, request.path)
    return jsonify({"error": f"The request body is JSON holding more than {json_body.MAX_VALUES:,} values, more than this server reads."}), 400


def json_large_bodies_busy(exc: json_body.LargeBodiesBusy):
    # Its bytes were read but not parsed: two other large bodies held the places (routes/json_body.py).
    logger.warning("Refused a large body while others were read in %s %s (%s bytes)", request.method, request.path, request.content_length)
    response = jsonify({"error": "The server is reading other large requests: try again in a few seconds."})
    response.status_code = 503
    response.headers["Retry-After"] = str(json_body.RETRY_AFTER_SECONDS)
    return response


def json_not_strict(exc: json_body.NotStrictJson):
    logger.warning("Refused a JSON body holding %s in %s %s", exc.text, request.method, request.path)
    return jsonify({"error": exc.sentence}), 400


def _under_api(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


def _api_methods() -> set[str]:
    """The methods a route other than the site's catch-all takes at the request's path."""

    adapter = current_app.create_url_adapter(request)
    methods: set[str] = set()
    for method in _METHODS:
        try:
            endpoint, _arguments = adapter.match(method=method)
        except HTTPException:
            continue
        if endpoint != _SITE_ENDPOINT:
            methods.add(method)
    return methods


def api_http_error(exc: HTTPException):
    # Pages, and an answer an exception already carries, are left as they are.
    if not _under_api(request.path) or exc.response is not None or exc.code is None:
        return exc
    # A 404 or 405 an API route did not give itself: the catch-all's, or the router's.
    if isinstance(exc, (NotFound, MethodNotAllowed)) and request.method not in (methods := _api_methods()):
        exc = MethodNotAllowed(sorted(methods)) if methods else NotFound()
    response = jsonify({"error": _API_SENTENCES.get(exc.code) or f"The server refused this request ({exc.code} {exc.name})."})
    response.status_code = exc.code
    # Its own headers too (a 405's Allow), but its HTML's Content-Type.
    for name, value in exc.get_headers():
        if name.lower() != "content-type":
            response.headers[name] = value
    return response


def init_app(app) -> None:
    app.register_error_handler(InvalidStorageIdentifier, invalid_storage_identifier)
    app.register_error_handler(StorageReadError, storage_read_error)
    app.register_error_handler(StorageQuotaExceeded, storage_quota_exceeded)
    app.register_error_handler(RequestEntityTooLarge, request_entity_too_large)
    app.register_error_handler(json_body.NestedTooDeep, json_nested_too_deep)
    app.register_error_handler(json_body.TooManyValues, json_too_many_values)
    app.register_error_handler(json_body.NotStrictJson, json_not_strict)
    app.register_error_handler(json_body.LargeBodiesBusy, json_large_bodies_busy)
    # Looked up by status first: the handlers above keep their own answers.
    app.register_error_handler(HTTPException, api_http_error)
