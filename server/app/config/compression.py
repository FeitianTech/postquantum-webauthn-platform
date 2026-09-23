"""Gzip for dynamic responses the client accepts it for.

Registered as an ``after_request`` handler when imported. Static assets are
precompressed at build time instead.
"""
from __future__ import annotations

import gzip

from flask import Flask, current_app, has_request_context, request

from .application import app

_COMPRESSIBLE_MIMETYPES = {
    "application/javascript",
    "application/json",
    "application/manifest+json",
    "application/xml",
    "image/svg+xml",
    "text/css",
    "text/html",
    "text/javascript",
    "text/plain",
    "text/xml",
}
_DEFAULT_COMPRESSION_MIN_SIZE = 512
_FAST_COMPRESSION_THRESHOLD = 256 * 1024
_RESPONSE_COMPRESSION_MARKER = "_postquantum_response_compression"


def _accepts_gzip() -> bool:
    if not has_request_context():
        return False
    accepted = request.headers.get("Accept-Encoding", "")
    return "gzip" in accepted.lower()


def _append_vary(existing: str | None, value: str) -> str:
    tokens = [token.strip() for token in (existing or "").split(",") if token.strip()]
    lowered = {token.lower() for token in tokens}
    if value.lower() not in lowered:
        tokens.append(value)
    return ", ".join(tokens)


def maybe_compress_response(response):
    if not _accepts_gzip():
        return response

    if response.status_code < 200 or response.status_code >= 300:
        return response

    if response.headers.get("Content-Encoding"):
        return response

    mimetype = (response.mimetype or "").lower()
    if mimetype not in _COMPRESSIBLE_MIMETYPES and not mimetype.startswith("text/"):
        return response

    if response.direct_passthrough:
        response.direct_passthrough = False

    try:
        payload = response.get_data()
    except Exception:  # pragma: no cover - depends on response type
        return response

    min_size = current_app.config.get("RESPONSE_COMPRESSION_MIN_SIZE", _DEFAULT_COMPRESSION_MIN_SIZE)
    if not payload or len(payload) < int(min_size):
        return response

    # Large bodies (e.g. a per-session MDS snapshot) favour speed over ratio;
    # static assets are precompressed at build time instead.
    compresslevel = 1 if len(payload) > _FAST_COMPRESSION_THRESHOLD else 6
    compressed = gzip.compress(payload, compresslevel=compresslevel)
    if len(compressed) >= len(payload):
        return response

    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(compressed))
    response.headers["Vary"] = _append_vary(response.headers.get("Vary"), "Accept-Encoding")
    response.headers.pop("ETag", None)
    response.headers.pop("Content-MD5", None)
    return response


setattr(maybe_compress_response, _RESPONSE_COMPRESSION_MARKER, True)


def _register_after_request_once(flask_app: Flask, handler) -> None:
    existing_handlers = flask_app.after_request_funcs.setdefault(None, [])
    for existing in existing_handlers:
        if getattr(existing, _RESPONSE_COMPRESSION_MARKER, False):
            return

    if flask_app._got_first_request:
        return

    flask_app.after_request(handler)


_register_after_request_once(app, maybe_compress_response)
