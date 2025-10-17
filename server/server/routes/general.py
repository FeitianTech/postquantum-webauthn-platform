"""General application routes."""
from __future__ import annotations

import base64
import binascii
import json
import os
import sys
from datetime import datetime, timezone
from importlib import import_module
from importlib.util import find_spec
from threading import Lock
from typing import Any, Dict, Optional

from flask import abort, jsonify, redirect, render_template, request, send_file

from ..attestation import serialize_attestation_certificate
from ..config import MDS_METADATA_PATH, app, basepath
from ..decoder import decode_payload_text, encode_payload_text
from ..metadata import (
    MetadataDownloadError,
    download_metadata_blob,
    ensure_metadata_session_id,
    delete_session_metadata_item,
    expand_metadata_entry_payloads,
    list_session_metadata_items,
    load_metadata_cache_entry,
    refresh_metadata_snapshot,
    save_session_metadata_item,
    serialize_session_metadata_item,
)
from ..storage import delkey


_metadata_bootstrap_lock = Lock()
_metadata_bootstrap_state = {"started": False, "completed": False}
_METADATA_BOOTSTRAP_ENV_FLAG = "FIDO_SERVER_MDS_BOOTSTRAPPED"

if os.environ.get(_METADATA_BOOTSTRAP_ENV_FLAG) == "1":
    _metadata_bootstrap_state["completed"] = True


_RESOURCE_MODULE = import_module("resource") if find_spec("resource") else None


def _current_process_rss_bytes() -> Optional[int]:
    """Return the resident set size of the current process in bytes."""

    # Prefer /proc/self/statm on Linux-like systems for current RSS readings.
    try:
        with open("/proc/self/statm", "r", encoding="utf-8") as statm_file:
            contents = statm_file.readline().split()
            if len(contents) >= 2:
                rss_pages = int(contents[1])
                page_size = os.sysconf("SC_PAGE_SIZE")
                return rss_pages * page_size
    except (OSError, ValueError):
        pass

    # Fallback to the resource module when /proc is unavailable.
    if _RESOURCE_MODULE is not None:
        usage = _RESOURCE_MODULE.getrusage(_RESOURCE_MODULE.RUSAGE_SELF)
        rss_kb = getattr(usage, "ru_maxrss", 0)
        if rss_kb:
            if sys.platform == "darwin":
                return int(rss_kb)
            return int(rss_kb * 1024)

    return None


def _auto_refresh_metadata() -> None:
    with _metadata_bootstrap_lock:
        if _metadata_bootstrap_state["completed"] or _metadata_bootstrap_state["started"]:
            return
        _metadata_bootstrap_state["started"] = True

    try:
        updated, bytes_written, last_modified = download_metadata_blob()
    except MetadataDownloadError as exc:
        app.logger.warning("Automatic metadata update failed: %s", exc)
        with _metadata_bootstrap_lock:
            _metadata_bootstrap_state["started"] = False
        return
    except Exception as exc:  # pylint: disable=broad-except
        app.logger.exception("Unexpected error while refreshing metadata automatically: %s", exc)
        with _metadata_bootstrap_lock:
            _metadata_bootstrap_state["started"] = False
        return

    if updated:
        if last_modified:
            app.logger.info(
                "Automatically refreshed FIDO MDS metadata (%d bytes written, Last-Modified: %s).",
                bytes_written,
                last_modified,
            )
        else:
            app.logger.info(
                "Automatically refreshed FIDO MDS metadata (%d bytes written).",
                bytes_written,
            )
    else:
        if last_modified:
            app.logger.info(
                "FIDO MDS metadata already up to date (Last-Modified: %s).",
                last_modified,
            )
        else:
            app.logger.info("FIDO MDS metadata already up to date.")

    with _metadata_bootstrap_lock:
        _metadata_bootstrap_state["completed"] = True
        _metadata_bootstrap_state["started"] = False

    os.environ[_METADATA_BOOTSTRAP_ENV_FLAG] = "1"


def ensure_metadata_bootstrapped(skip_if_reloader_parent: bool = True) -> None:
    """Ensure the MDS metadata cache is refreshed once per server process."""

    if skip_if_reloader_parent and app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    if os.environ.get(_METADATA_BOOTSTRAP_ENV_FLAG) == "1":
        refresh_metadata_snapshot()
        return

    with _metadata_bootstrap_lock:
        if _metadata_bootstrap_state["completed"]:
            return

    _auto_refresh_metadata()
    refresh_metadata_snapshot()


# Refresh eagerly for environments lacking ``before_serving`` (older Flask versions)
# while still registering the hook when available so each process performs the
# bootstrap exactly once as it starts handling requests.
ensure_metadata_bootstrapped()

if hasattr(app, "before_serving"):

    @app.before_serving
    def _bootstrap_metadata_before_serving() -> None:
        """Refresh metadata as the server starts handling requests."""

        ensure_metadata_bootstrapped(skip_if_reloader_parent=False)


@app.route("/")
def index():
    return redirect("/index.html")


@app.route("/index.html")
def index_html():
    ensure_metadata_bootstrapped(skip_if_reloader_parent=False)
    ensure_metadata_session_id()

    initial_mds_blob = None

    initial_mds_info = load_metadata_cache_entry()

    return render_template(
        "index.html",
        initial_mds_blob=initial_mds_blob,
        initial_mds_info=initial_mds_info,
    )


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


@app.route("/api/mds/runtime/memory", methods=["GET"])
def api_mds_memory_usage():
    """Return the current memory usage of the server process."""

    rss_bytes = _current_process_rss_bytes()
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload: Dict[str, Any] = {"timestamp": timestamp, "rss_bytes": rss_bytes}
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
