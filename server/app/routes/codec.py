"""The Codec's route: ``/api/codec`` decodes an input, or encodes a value (docs/DECODER.md).

A refusal answers 422 with the decoder's or encoder's own sentence, and where the
input stops being well-formed; anything else is logged and answers 500.
"""
from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, current_app, jsonify, request

from ..config import request_limits
from ..decoder.decode import text as decode_text
from ..decoder.encode import text as encode_text
from . import json_body

logger = logging.getLogger(__name__)

bp = Blueprint("codec", __name__)


def _refusal(exc: ValueError) -> dict[str, Any]:
    body: dict[str, Any] = {"error": str(exc)}
    # A parse error says where the input stops being well-formed (CBOR, EDN, JSON),
    # as far as its reader can tell: JSON gives no offset, EDN no path.
    for field in ("offset", "path"):
        value = getattr(exc, field, None)
        if value is not None:
            body[field] = value
    return body


def _perform_decode(decoder_input: str, *, lenient: bool, max_items: int):
    try:
        return decode_text.decode_payload_text(decoder_input, lenient=lenient, max_items=max_items), 200
    except ValueError as exc:
        return _refusal(exc), 422
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Failed to decode payload: %s", exc)
        return {"error": "Unable to decode payload."}, 500


def _perform_encode(encoder_input: str, target_format: str, *, max_items: int):
    try:
        return encode_text.encode_payload_text(encoder_input, target_format, max_items=max_items), 200
    except ValueError as exc:
        return _refusal(exc), 422
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Failed to encode payload: %s", exc)
        return {"error": "Unable to encode payload."}, 500


@bp.route("/api/codec", methods=["POST"])
def api_codec_payload():
    # Its own limit, before the body is read (config/request_limits.py).
    request.max_content_length = current_app.config[request_limits.CODEC_REQUEST_LIMIT_KEY]
    if not request.is_json:
        return jsonify({"error": "Expected JSON payload."}), 400

    payload = json_body.json_object()
    codec_input = payload.get("payload")
    if not isinstance(codec_input, str) or not codec_input.strip():
        return jsonify({"error": "Codec payload must be a non-empty string."}), 400

    mode = payload.get("mode", "decode")
    mode_normalized = mode.lower() if isinstance(mode, str) else "decode"
    # How many items one decode or encode reads (config/request_limits.py).
    max_items = current_app.config[request_limits.CODEC_ITEM_LIMIT_KEY]

    if mode_normalized == "encode":
        target_format = payload.get("format")
        if not isinstance(target_format, str) or not target_format.strip():
            return jsonify({"error": "Encoder format must be provided."}), 400
        result, status = _perform_encode(codec_input, target_format, max_items=max_items)
        return jsonify(result), status

    lenient = payload.get("lenient", False)
    if not isinstance(lenient, bool):
        return jsonify({"error": "lenient must be true or false."}), 400

    result, status = _perform_decode(codec_input, lenient=lenient, max_items=max_items)
    return jsonify(result), status
