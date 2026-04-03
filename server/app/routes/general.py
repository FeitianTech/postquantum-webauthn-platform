"""General application routes."""
from __future__ import annotations

import base64
import binascii
import io
import json
import os
import pickle
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Mapping, Optional

from flask import abort, jsonify, render_template, request, send_file

from ..attestation import serialize_attestation_certificate
from ..config import MDS_METADATA_VERIFIED_PATH, app
from ..decoder import decode_payload_text, encode_payload_text
from ..metadata import (
    ensure_metadata_session_id,
    delete_session_metadata_item,
    expand_metadata_entry_payloads,
    list_session_metadata_items,
    load_cached_metadata_snapshot,
    load_effective_explorer_snapshot,
    load_effective_full_snapshot,
    load_packaged_explorer_summary,
    maybe_store_uploaded_metadata_file,
    resolve_effective_metadata_entry,
    save_session_metadata_item,
    serialize_session_metadata_item,
    _load_base_metadata,
)
from ..startup import startup_fail_fast_enabled, warm_up_dependencies
from ..storage import delkey, readkey


_metadata_bootstrap_lock = Lock()
_metadata_bootstrap_state = {
    "started": False,
    "completed": False,
    "marker": None,
    "cache_loaded": False,
}
_METADATA_BOOTSTRAP_ENV_FLAG = "FIDO_SERVER_MDS_BOOTSTRAPPED"
_INDEX_EAGER_METADATA_ENV_FLAG = "FIDO_SERVER_EAGER_INDEX_METADATA_BOOTSTRAP"


def _env_flag(name: str) -> Optional[bool]:
    raw = os.environ.get(name)
    if raw is None:
        return None

    normalised = raw.strip().lower()
    if normalised in {"", "0", "false", "off", "no"}:
        return False
    return True


def _should_bootstrap_metadata_on_index() -> bool:
    explicit = _env_flag(_INDEX_EAGER_METADATA_ENV_FLAG)
    if explicit is not None:
        return explicit
    return startup_fail_fast_enabled()


def _bootstrap_marker_for_today() -> str:
    """Return the marker string used to identify today's bootstrap."""

    return datetime.now(timezone.utc).date().isoformat()


def _mark_bootstrap_completed_for_today() -> None:
    """Record that the metadata bootstrap completed for the current day."""

    today_marker = _bootstrap_marker_for_today()
    with _metadata_bootstrap_lock:
        _metadata_bootstrap_state["completed"] = True
        _metadata_bootstrap_state["started"] = False
        _metadata_bootstrap_state["marker"] = today_marker
    os.environ[_METADATA_BOOTSTRAP_ENV_FLAG] = today_marker


def _load_cached_metadata_snapshot_if_available() -> None:
    """Load any stored metadata snapshot into process memory before serving requests."""

    try:
        cached = load_cached_metadata_snapshot()
    except Exception as exc:  # pragma: no cover - defensive
        app.logger.warning("Failed to load cached FIDO MDS metadata snapshot: %s", exc)
        return

    if not cached:
        return

    with _metadata_bootstrap_lock:
        if not _metadata_bootstrap_state.get("cache_loaded"):
            _metadata_bootstrap_state["cache_loaded"] = True
            app.logger.info("Loaded cached FIDO MDS metadata snapshot from disk.")


_existing_marker = os.environ.get(_METADATA_BOOTSTRAP_ENV_FLAG)
if _existing_marker:
    _metadata_bootstrap_state["marker"] = _existing_marker
    if _existing_marker == _bootstrap_marker_for_today():
        _metadata_bootstrap_state["completed"] = True


def ensure_metadata_bootstrapped(skip_if_reloader_parent: bool = True) -> None:
    """Ensure the MDS metadata cache is refreshed once per server process."""

    if skip_if_reloader_parent and app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return

    _load_cached_metadata_snapshot_if_available()

    with _metadata_bootstrap_lock:
        today_marker = _bootstrap_marker_for_today()
        existing_marker = _metadata_bootstrap_state.get("marker")
        if _metadata_bootstrap_state.get("completed") and existing_marker == today_marker:
            return
        _metadata_bootstrap_state["started"] = True
        _metadata_bootstrap_state["marker"] = today_marker

    metadata, _ = _load_base_metadata()
    if metadata is not None:
        app.logger.info(
            "Loaded packaged FIDO MDS metadata snapshot (%d entries).",
            len(metadata.entries),
        )
    else:
        app.logger.warning(
            "Packaged FIDO MDS metadata snapshot not found at %s.",
            MDS_METADATA_VERIFIED_PATH,
        )

    _mark_bootstrap_completed_for_today()


if hasattr(app, "before_serving"):

    @app.before_serving
    def _warm_dependencies_before_serving() -> None:
        """Warm up external dependencies before the server handles requests."""

        warm_up_dependencies(skip_if_reloader_parent=False)

elif hasattr(app, "before_first_request"):

    @app.before_first_request
    def _warm_dependencies_before_first_request() -> None:
        """Fallback for Flask versions without ``before_serving``."""

        warm_up_dependencies(skip_if_reloader_parent=False)


@app.route("/")
def index():
    return index_html()


@app.route("/index.html")
def index_html():
    if _should_bootstrap_metadata_on_index():
        ensure_metadata_bootstrapped(skip_if_reloader_parent=False)
    ensure_metadata_session_id()

    initial_mds_info = load_packaged_explorer_summary()

    return render_template(
        "index.html",
        initial_mds_info=initial_mds_info,
    )


def _no_store_json_response(payload: Mapping[str, Any], status: int = 200):
    response = jsonify(payload)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.headers["Vary"] = "Cookie"
    return response


@app.route("/api/mds/metadata/explorer", methods=["GET"])
def api_get_explorer_metadata():
    ensure_metadata_session_id()
    snapshot = load_effective_explorer_snapshot()
    if not snapshot.get("entries") and not snapshot.get("meta"):
        return _no_store_json_response(
            {"error": "Verified metadata snapshot is not available."},
            status=404,
        )
    return _no_store_json_response(snapshot)


@app.route("/api/mds/metadata/explorer/full", methods=["GET"])
def api_get_full_explorer_metadata():
    ensure_metadata_session_id()
    snapshot = load_effective_full_snapshot()
    if not snapshot.get("entries") and not snapshot.get("meta"):
        return _no_store_json_response(
            {"error": "Verified metadata snapshot is not available."},
            status=404,
        )
    return _no_store_json_response(snapshot)


@app.route("/api/mds/metadata/resolve", methods=["GET"])
def api_resolve_metadata_entry():
    ensure_metadata_session_id()

    requested = {
        "entry_id": request.args.get("entryId", type=str),
        "aaguid": request.args.get("aaguid", type=str),
        "aaid": request.args.get("aaid", type=str),
    }
    provided = {
        key: value.strip()
        for key, value in requested.items()
        if isinstance(value, str) and value.strip()
    }

    if len(provided) != 1:
        return _no_store_json_response(
            {"error": "Provide exactly one of entryId, aaguid, or aaid."},
            status=400,
        )

    resolved = resolve_effective_metadata_entry(
        entry_id=provided.get("entry_id"),
        aaguid=provided.get("aaguid"),
        aaid=provided.get("aaid"),
    )
    if resolved is None:
        return _no_store_json_response({"error": "Metadata entry not found."}, status=404)

    return _no_store_json_response({"entry": resolved})


@app.route("/api/mds/metadata/base", methods=["GET"])
def api_get_verified_metadata():
    metadata_path = MDS_METADATA_VERIFIED_PATH
    try:
        with open(metadata_path, "r", encoding="utf-8") as metadata_file:
            payload = json.load(metadata_file)
    except FileNotFoundError:
        return jsonify({"error": "Verified metadata snapshot is not available."}), 404
    except json.JSONDecodeError as exc:
        app.logger.error("Invalid verified metadata snapshot: %s", exc)
        return jsonify({"error": "Verified metadata snapshot is corrupted."}), 500

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

        maybe_store_uploaded_metadata_file(trimmed, raw_bytes)

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
    if saved_items:
        response["snapshot"] = load_effective_full_snapshot()

    return _no_store_json_response(response, status=status_code)


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
        return _no_store_json_response(
            {"deleted": False, "message": "Metadata entry not found."},
            status=404,
        )

    return _no_store_json_response(
        {"deleted": True, "snapshot": load_effective_full_snapshot()}
    )


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
    metadata_session_id = ensure_metadata_session_id()
    delkey(email, session_id=metadata_session_id)
    return jsonify({"status": "OK"})


@app.route("/api/downloadcred", methods=["GET"])
def downloadcred():
    name = request.args.get("email")
    if not name:
        abort(400)
    metadata_session_id = ensure_metadata_session_id()
    credentials = readkey(name, session_id=metadata_session_id)
    if not credentials:
        abort(404)

    filename = f"{name}_credential_data.pkl"
    payload = pickle.dumps(credentials)
    buffer = io.BytesIO(payload)
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
    )
