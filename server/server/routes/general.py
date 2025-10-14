"""General application routes."""
from __future__ import annotations

import base64
import binascii
import os
from typing import Any, Dict

from flask import abort, jsonify, redirect, render_template, request, send_file

from ..attestation import serialize_attestation_certificate
from ..config import (
    MDS_METADATA_FILENAME,
    MDS_METADATA_PATH,
    MDS_METADATA_STATIC_PATH,
    app,
    basepath,
)
from ..decoder import decode_payload_text, encode_payload_text
from ..metadata import load_metadata_cache_entry
from ..storage import delkey


@app.route("/")
def index():
    return redirect("/index.html")


@app.route(f"/{MDS_METADATA_FILENAME}")
def serve_mds_metadata_blob():
    path = MDS_METADATA_PATH
    if not os.path.exists(path):
        path = MDS_METADATA_STATIC_PATH
        if not os.path.exists(path):
            abort(404)
    return send_file(
        path,
        mimetype="application/jose",
        conditional=True,
        download_name=MDS_METADATA_FILENAME,
    )


@app.route("/index.html")
def index_html():
    initial_mds_blob = None
    for candidate in (MDS_METADATA_PATH, MDS_METADATA_STATIC_PATH):
        try:
            with open(candidate, "r", encoding="utf-8") as blob_file:
                initial_mds_blob = blob_file.read()
                break
        except OSError:
            continue
    else:
        initial_mds_blob = None

    initial_mds_info = load_metadata_cache_entry()

    return render_template(
        "index.html",
        initial_mds_blob=initial_mds_blob,
        initial_mds_info=initial_mds_info,
    )


@app.route("/api/mds/update", methods=["POST"])
def api_update_mds_metadata():
    cache_state = load_metadata_cache_entry()
    message = (
        "Runtime metadata updates are disabled. "
        "The internal background updater refreshes the verified cache once per day."
    )
    payload: Dict[str, Any] = {
        "updated": False,
        "bytes_written": 0,
        "message": message,
        "metadata_available": os.path.exists(MDS_METADATA_PATH),
    }

    if cache_state:
        if cache_state.get("last_modified_iso"):
            payload["last_modified"] = cache_state["last_modified_iso"]
        if cache_state.get("fetched_at"):
            payload["fetched_at"] = cache_state["fetched_at"]

    return jsonify(payload), 503


def _perform_decode(decoder_input: str):
    try:
        return decode_payload_text(decoder_input), 200
    except ValueError as exc:
        return {"error": str(exc)}, 422
    except Exception as exc:  # pylint: disable=broad-except
        app.logger.exception("Failed to decode payload: %s", exc)
        return {"error": "Unable to decode payload."}, 500


def _perform_encode(encoder_input: str, target_format: str):
    try:
        return encode_payload_text(encoder_input, target_format), 200
    except ValueError as exc:
        return {"error": str(exc)}, 422
    except Exception as exc:  # pylint: disable=broad-except
        app.logger.exception("Failed to encode payload: %s", exc)
        return {"error": "Unable to encode payload."}, 500


@app.route("/api/codec", methods=["POST"])
def api_codec_payload():
    if not request.is_json:
        return jsonify({"error": "Expected JSON payload."}), 400

    payload = request.get_json(silent=True) or {}
    codec_input = payload.get("payload")
    if not isinstance(codec_input, str) or not codec_input.strip():
        return jsonify({"error": "Codec payload must be a non-empty string."}), 400

    mode = payload.get("mode", "decode")
    mode_normalized = mode.lower() if isinstance(mode, str) else "decode"

    if mode_normalized == "encode":
        target_format = payload.get("format")
        if not isinstance(target_format, str) or not target_format.strip():
            return jsonify({"error": "Encoder format must be provided."}), 400
        result, status = _perform_encode(codec_input, target_format)
        return jsonify(result), status

    result, status = _perform_decode(codec_input)
    return jsonify(result), status


@app.route("/api/decode", methods=["POST"])
def api_decode_payload():
    if not request.is_json:
        return jsonify({"error": "Expected JSON payload."}), 400

    payload = request.get_json(silent=True) or {}
    decoder_input = payload.get("payload")
    if not isinstance(decoder_input, str) or not decoder_input.strip():
        return jsonify({"error": "Decoder payload must be a non-empty string."}), 400

    result, status = _perform_decode(decoder_input)
    return jsonify(result), status


@app.route("/api/mds/decode-certificate", methods=["POST"])
def api_decode_mds_certificate():
    if not request.is_json:
        return jsonify({"error": "Expected JSON payload."}), 400

    payload = request.get_json(silent=True) or {}
    certificate_value = payload.get("certificate")
    if not certificate_value or not isinstance(certificate_value, str):
        return jsonify({"error": "Certificate is required."}), 400

    cleaned = "".join(certificate_value.split())
    padding = len(cleaned) % 4
    if padding:
        cleaned += "=" * (4 - padding)

    try:
        certificate_bytes = base64.b64decode(cleaned)
    except (ValueError, binascii.Error):
        return jsonify({"error": "Invalid certificate encoding."}), 400

    try:
        details = serialize_attestation_certificate(certificate_bytes)
    except Exception as exc:  # pylint: disable=broad-except
        return jsonify({"error": f"Unable to decode certificate: {exc}"}), 422

    return jsonify({"details": details})


@app.route("/api/deletepub", methods=["POST"])
def deletepub():
    response = request.get_json(silent=True) or {}
    email = response.get("email")
    if not email:
        abort(400)
    delkey(email)
    return jsonify({"status": "OK"})


@app.route("/api/downloadcred", methods=["GET"])
def downloadcred():
    name = request.args.get("email")
    if not name:
        abort(400)
    filename = f"{name}_credential_data.pkl"
    return send_file(os.path.join(basepath, filename), as_attachment=True, download_name=filename)
