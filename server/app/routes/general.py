"""General application routes."""
from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any

from flask import (
    Blueprint,
    current_app,
    g,
    jsonify,
    request,
    session,
)

from .. import encoding, mds_snapshot_dir
from ..config.request_limits import METADATA_UPLOAD_LIMIT_KEY
from ..decoder.decode.pipeline import decode_payload_text
from ..decoder.encode.text import encode_payload_text
from ..mds_provisioning import (
    ensure_snapshot_available,
    follow_newer_snapshot,
    waits_for_the_snapshot,
)
from ..static_assets import asset_url, snapshot_version
from ..webauthn.attestation.certificates import serialize_attestation_certificate
from ..webauthn.metadata.blob import (
    load_packaged_explorer_summary,
    load_packaged_snapshot_meta,
)
from ..webauthn.metadata.effective import (
    load_effective_full_snapshot,
    resolve_effective_metadata_entry,
)
from ..webauthn.metadata.entries import expand_metadata_entry_payloads
from ..webauthn.metadata.sessions import (
    delete_session_metadata_item,
    ensure_metadata_session_id,
    list_session_metadata_items,
    save_session_metadata_item,
    serialize_session_metadata_item,
)
from ..webauthn.metadata.uploads import maybe_store_uploaded_metadata_file

logger = logging.getLogger(__name__)

# The HTTP rules, registered on the app by server.app.app.
bp = Blueprint("general", __name__)

@bp.route("/health")
def health():
    """Cheap liveness endpoint that touches no session or storage state.

    Not ``/healthz``: Cloud Run reserves URL paths ending in ``z``.
    """

    response = current_app.response_class("ok", mimetype="text/plain")
    response.headers["Cache-Control"] = "no-store"
    return response


_MDS_EXPLORER_FULL_STATIC_FILENAME = mds_snapshot_dir.EXPLORER_FULL
_MDS_CUSTOM_ENTRIES_SESSION_KEY = "fido.mds.custom"


def _remember_custom_entries_state(snapshot: Any) -> None:
    """Record whether this session has uploaded metadata.

    The page uses this to load the cacheable packaged snapshot for sessions
    without custom entries instead of the per-session explorer API.
    """

    meta = snapshot.get("meta") if isinstance(snapshot, Mapping) else None
    if not isinstance(meta, Mapping) or not isinstance(meta.get("hasCustomEntries"), bool):
        return
    state = "present" if meta["hasCustomEntries"] else "none"
    if session.get(_MDS_CUSTOM_ENTRIES_SESSION_KEY) != state:
        session[_MDS_CUSTOM_ENTRIES_SESSION_KEY] = state


def _initial_custom_entries_state(metadata_session_id: str | None) -> str:
    if metadata_session_id and getattr(g, "_mds_session_new", None) == metadata_session_id:
        return "none"
    stored = session.get(_MDS_CUSTOM_ENTRIES_SESSION_KEY)
    return stored if stored in ("none", "present") else "unknown"


def _packaged_snapshot_url() -> str | None:
    """Where browsers load the packaged snapshot from, or None when there is no
    file there that the explorer API would agree with (the page then asks the API).

    The URL carries the snapshot's own version (``static_assets.snapshot_version``),
    so a new snapshot is a new URL."""

    version = snapshot_version(load_packaged_snapshot_meta())
    if version is None:
        return None
    return f"{asset_url(_MDS_EXPLORER_FULL_STATIC_FILENAME)}?v={version}"


def _initial_mds_info() -> dict[str, Any]:
    """What the MDS explorer starts from: the packaged snapshot's summary (absent
    without a snapshot), the URL of the packaged snapshot (absent without one),
    and whether this session has uploaded metadata. The page asks
    ``/api/mds/metadata/info`` for it, which waits for a provisioning under way;
    the page itself is static and never waits. A running instance takes a newer
    snapshot from Cloud Storage here (``follow_newer_snapshot``): this is where
    the page starts."""

    ensure_snapshot_available()
    follow_newer_snapshot()
    metadata_session_id = ensure_metadata_session_id()

    initial_mds_info = dict(load_packaged_explorer_summary() or {})
    snapshot_url = _packaged_snapshot_url()
    if snapshot_url:
        initial_mds_info["snapshotUrl"] = snapshot_url
    initial_mds_info["customEntriesState"] = _initial_custom_entries_state(
        metadata_session_id
    )
    return initial_mds_info


def _no_store_json_response(payload: Mapping[str, Any], status: int = 200):
    response = jsonify(payload)
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    response.headers["Vary"] = "Cookie"
    return response


@bp.route("/api/mds/metadata/info", methods=["GET"])
def api_get_metadata_info():
    # Per session (customEntriesState), so never cached and keyed on the cookie.
    return _no_store_json_response(_initial_mds_info())


@bp.route("/api/mds/metadata/explorer/full", methods=["GET"])
@waits_for_the_snapshot
def api_get_full_explorer_metadata():
    ensure_metadata_session_id()
    snapshot = load_effective_full_snapshot()
    if not snapshot.get("entries") and not snapshot.get("meta"):
        return _no_store_json_response(
            {"error": "Verified metadata snapshot is not available."},
            status=404,
        )
    _remember_custom_entries_state(snapshot)
    return _no_store_json_response(snapshot)


@bp.route("/api/mds/metadata/resolve", methods=["GET"])
@waits_for_the_snapshot
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


@bp.route("/api/mds/metadata/custom", methods=["GET"])
def api_list_custom_metadata():
    ensure_metadata_session_id()
    items = [serialize_session_metadata_item(item) for item in list_session_metadata_items()]
    return jsonify({"items": items})


def _refuse_json_constant(constant: str) -> Any:
    raise ValueError(f"{constant} is not JSON (RFC 8259 has no NaN or Infinity)")


def _read_metadata_json(text: str) -> Any:
    # RFC 8259's JSON: the metadata is answered back, and NaN would make that answer not JSON.
    return json.loads(text, parse_constant=_refuse_json_constant)


@bp.route("/api/mds/metadata/upload", methods=["POST"])
@waits_for_the_snapshot
def api_upload_custom_metadata():
    # Its own limit, before the body is read: the whole MDS metadata (config/request_limits.py).
    request.max_content_length = current_app.config[METADATA_UPLOAD_LIMIT_KEY]
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
            payload: dict[str, Any] = _read_metadata_json(text)
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

    return _upload_answer(saved_items, errors)


def _upload_answer(saved_items: list[Any], errors: list[str]):
    """What an upload answers: the files saved, what was refused, and the explorer
    snapshot with them when any was saved (400 when none was)."""

    response: dict[str, Any] = {"items": saved_items}
    if errors:
        response["errors"] = errors
    if saved_items:
        response["snapshot"] = load_effective_full_snapshot()
        # A reload must now load this session's own list, not the packaged snapshot.
        _remember_custom_entries_state(response["snapshot"])

    return _no_store_json_response(response, status=200 if saved_items else 400)


@bp.route("/api/mds/metadata/custom/<string:stored_filename>", methods=["DELETE"])
@waits_for_the_snapshot
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

    snapshot = load_effective_full_snapshot()
    _remember_custom_entries_state(snapshot)
    return _no_store_json_response({"deleted": True, "snapshot": snapshot})


def _refusal(exc: ValueError) -> dict[str, Any]:
    body: dict[str, Any] = {"error": str(exc)}
    # A parse error says where the input stops being well-formed (CBOR, EDN, JSON).
    for field in ("offset", "path"):
        if hasattr(exc, field):
            body[field] = getattr(exc, field)
    return body


def _perform_decode(decoder_input: str, *, lenient: bool = False):
    try:
        return decode_payload_text(decoder_input, lenient=lenient), 200
    except ValueError as exc:
        return _refusal(exc), 422
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Failed to decode payload: %s", exc)
        return {"error": "Unable to decode payload."}, 500


def _perform_encode(encoder_input: str, target_format: str):
    try:
        return encode_payload_text(encoder_input, target_format), 200
    except ValueError as exc:
        return _refusal(exc), 422
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Failed to encode payload: %s", exc)
        return {"error": "Unable to encode payload."}, 500


@bp.route("/api/codec", methods=["POST"])
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

    lenient = payload.get("lenient", False)
    if not isinstance(lenient, bool):
        return jsonify({"error": "lenient must be true or false."}), 400

    result, status = _perform_decode(codec_input, lenient=lenient)
    return jsonify(result), status


@bp.route("/api/mds/decode-certificate", methods=["POST"])
def api_decode_mds_certificate():
    if not request.is_json:
        return jsonify({"error": "Expected JSON payload."}), 400

    payload = request.get_json(silent=True) or {}
    certificate_value = payload.get("certificate")
    if not certificate_value or not isinstance(certificate_value, str):
        return jsonify({"error": "Certificate is required."}), 400

    # MDS ships standard base64, but the box accepts a paste from anywhere, so
    # base64url is read as base64url rather than being fed to a standard
    # decoder that drops its ``-``/``_`` and returns a shorter, wrong DER.
    certificate_bytes = encoding.try_decode_base64(certificate_value)
    if certificate_bytes is None:
        certificate_bytes = encoding.try_decode_base64url(certificate_value)
    if certificate_bytes is None:
        return jsonify({"error": "Invalid certificate encoding."}), 400

    try:
        details = serialize_attestation_certificate(certificate_bytes)
    except Exception as exc:  # pylint: disable=broad-except
        return jsonify({"error": f"Unable to decode certificate: {exc}"}), 422

    return jsonify({"details": details})
