"""General application routes."""
from __future__ import annotations

import base64
import binascii
import os
from typing import Any, Dict

from flask import abort, jsonify, redirect, render_template, request, send_file

from ..backend.attestation import serialize_attestation_certificate
from ..backend.config import MDS_METADATA_PATH, app, basepath
from ..backend.metadata import (
    MetadataDownloadError,
    download_metadata_blob,
    load_metadata_cache_entry,
)
from ..backend.storage import delkey


@app.route("/")
def index():
    return redirect("/index.html")


@app.route("/index.html")
def index_html():
    return render_template("index.html")


@app.route("/api/mds/update", methods=["POST"])
def api_update_mds_metadata():
    metadata_existed = os.path.exists(MDS_METADATA_PATH)
    try:
        updated, bytes_written, last_modified = download_metadata_blob()
    except MetadataDownloadError as exc:
        if metadata_existed and getattr(exc, "status_code", None) == 429:
            app.logger.warning("Metadata update rate limited by FIDO MDS: %s", exc)
            cached_state = load_metadata_cache_entry()
            cached_last_modified_iso = cached_state.get("last_modified_iso") if cached_state else None
            retry_after = getattr(exc, "retry_after", None)
            if retry_after:
                note = (
                    "Metadata already up to date. The FIDO Metadata Service asked us to wait before "
                    f"downloading again (retry after {retry_after})."
                )
            else:
                note = (
                    "Metadata already up to date. The FIDO Metadata Service asked us to wait before downloading again."
                )
            payload: Dict[str, Any] = {
                "updated": False,
                "bytes_written": 0,
                "message": note,
            }
            if cached_last_modified_iso:
                payload["last_modified"] = cached_last_modified_iso
            return jsonify(payload)
        return jsonify({"updated": False, "message": str(exc)}), 502
    except OSError as exc:
        app.logger.exception("Failed to store metadata BLOB: %s", exc)
        return (
            jsonify(
                {
                    "updated": False,
                    "message": "Failed to store the metadata BLOB on the server.",
                }
            ),
            500,
        )

    if updated:
        message = "Metadata updated successfully." if metadata_existed else "Metadata downloaded successfully."
    else:
        message = "Metadata already up to date."

    payload = {
        "updated": updated,
        "bytes_written": bytes_written,
        "message": message,
    }
    if last_modified:
        payload["last_modified"] = last_modified

    return jsonify(payload)


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
