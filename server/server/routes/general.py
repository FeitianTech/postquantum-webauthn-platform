"""General application routes."""
from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Any, Dict

from flask import abort, jsonify, redirect, render_template, request, send_file

from ..attestation import serialize_attestation_certificate
from ..config import MDS_METADATA_PATH, app, basepath
from ..decoder import decode_payload_text, encode_payload_text
from ..metadata import (
    ensure_metadata_session_id,
    delete_session_metadata_item,
    expand_metadata_entry_payloads,
    list_session_metadata_items,
    load_metadata_cache_entry,
    save_session_metadata_item,
    serialize_session_metadata_item,
)
from ..storage import delkey


@app.route("/")
def index():
    return redirect("/index.html")


@app.route("/index.html")
def index_html():
    ensure_metadata_session_id()

    initial_mds_payload = None
    try:
        with open(MDS_METADATA_PATH, "r", encoding="utf-8") as metadata_file:
            initial_mds_payload = metadata_file.read()
    except OSError:
        initial_mds_payload = None

    initial_mds_info = load_metadata_cache_entry()

    return render_template(
        "index.html",
        initial_mds_payload=initial_mds_payload,
        initial_mds_info=initial_mds_info,
    )


@app.route("/api/mds/update", methods=["POST"])
def api_update_mds_metadata():
    cached_state = load_metadata_cache_entry()
    message = (
        "Reloading the cached metadata snapshot. A daily background service keeps the file up to date."
    )

    payload: Dict[str, Any] = {
        "updated": True,
        "bytes_written": 0,
        "message": message,
    }

    if cached_state:
        last_modified_iso = cached_state.get("last_modified_iso")
        fetched_at = cached_state.get("fetched_at")
        if last_modified_iso:
            payload["last_modified"] = last_modified_iso
        if fetched_at:
            payload["fetched_at"] = fetched_at

    return jsonify(payload)


@app.route("/api/mds/metadata/custom", methods=["GET"])
def api_list_custom_metadata():
    ensure_metadata_session_id()
    items = [serialize_session_metadata_item(item) for item in list_session_metadata_items()]
    return jsonify({"items": items})


@app.route("/api/mds/metadata/upload", methods=["POST"])
def api_upload_custom_metadata():
    ensure_metadata_session_id()

    file_entries = request.files.getlist("files") if request.files else []
    if not file_entries:
        return jsonify({"items": [], "errors": ["No JSON files were provided."]}), 400

    saved_items = []
    errors = []

    for storage in file_entries:
        filename = storage.filename or ""
        trimmed = filename.strip()
        if not trimmed:
            trimmed = "metadata.json"

        if not trimmed.lower().endswith(".json"):
            errors.append(f"{trimmed} is not a JSON file.")
            continue

        try:
            raw_bytes = storage.read()
        except Exception as exc:  # pylint: disable=broad-except
            errors.append(f"Failed to read {trimmed}: {exc}")
            continue

        try:
            text = raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            errors.append(f"{trimmed} is not valid UTF-8 JSON.")
            continue

        try:
            payload: Dict[str, Any] = json.loads(text)
        except ValueError as exc:
            errors.append(f"{trimmed}: {exc}")
            continue

        if not isinstance(payload, dict):
            errors.append(f"{trimmed} must contain a JSON object.")
            continue

        try:
            entry_payloads = expand_metadata_entry_payloads(payload)
        except (TypeError, ValueError) as exc:
            errors.append(f"{trimmed}: {exc}")
            continue

        for index, entry_payload in enumerate(entry_payloads, start=1):
            display_name = (
                trimmed
                if len(entry_payloads) == 1
                else f"{trimmed} (entry {index})"
            )

            try:
                item = save_session_metadata_item(
                    entry_payload,
                    original_filename=display_name,
                )
            except ValueError as exc:
                errors.append(f"{display_name}: {exc}")
                continue
            except RuntimeError as exc:
                return jsonify({"error": str(exc)}), 500

            saved_items.append(serialize_session_metadata_item(item))

    status_code = 200 if saved_items else 400
    response: Dict[str, Any] = {"items": saved_items}
    if errors:
        response["errors"] = errors

    return jsonify(response), status_code


@app.route("/api/mds/metadata/custom/<string:stored_filename>", methods=["DELETE"])
def api_delete_custom_metadata(stored_filename: str):
    ensure_metadata_session_id()
    try:
        deleted = delete_session_metadata_item(stored_filename)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": str(exc)}), 500

    if not deleted:
        return (
            jsonify({"deleted": False, "message": "Metadata entry not found."}),
            404,
        )

    return jsonify({"deleted": True})


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
