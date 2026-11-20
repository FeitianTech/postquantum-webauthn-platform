"""The MDS routes: the packaged snapshot's info and entries, a visitor's uploaded metadata, certificate decoding.

Every route that reads the snapshot waits for a provisioning under way
(``waits_for_the_snapshot``); the answers that depend on the visitor are
``no-store``.
"""
from __future__ import annotations

import json
import logging
import math
import threading
from collections.abc import Mapping
from typing import Any, NamedTuple

from flask import Blueprint, Response, abort, current_app, jsonify, request

from .. import encoding, visitor_session
from ..config import request_limits
from ..config.request_limits import METADATA_UPLOAD_LIMIT_KEY
from ..mds import cache as mds_cache
from ..mds import effective as mds_effective
from ..mds import entries as mds_entries
from ..mds import listed_uploads as mds_listed_uploads
from ..mds import provisioning as mds_provisioning
from ..mds import uploads as mds_uploads
from ..storage import github_mirror, session_metadata
from ..storage.common import StorageReadError
from ..webauthn.attestation import certificates as attestation_certificates
from . import assets, json_body

# The HTTP rules, registered on the app by server.app.app.
bp = Blueprint("mds", __name__)

logger = logging.getLogger(__name__)

# What the upload and its deletion answer when the store fails (mds/uploads.py logs why).
_STORE_FAILED = "Failed to store uploaded metadata on the server."
_DELETE_FAILED = "Failed to delete the uploaded metadata file."

# An upload's icon (api_custom_metadata_icon): the browser keeps it, and no shared cache.
_ICON_CACHE_CONTROL = "private, max-age=31536000, immutable"

# One upload is read at a time in a process: it holds its body, its text and its JSON several
# times over, and the worst the limits let in (16 MiB of strings each with a 4-byte character,
# kept at 4 bytes a character) peaks at 177 MiB as tracemalloc counts it, in an instance of 1 GiB.
# Another waits a moment for the place, then is told to try again, its body unread.
_UPLOADS_READ = threading.BoundedSemaphore(1)
_UPLOAD_WAIT_SECONDS = 2
_UPLOAD_RETRY_AFTER_SECONDS = 5
_UPLOADS_BUSY = "The server is reading other metadata uploads: try again in a few seconds."


def _custom_entries_state(metadata_session_id: str | None) -> str:
    """Whether the visitor's namespace holds uploaded metadata: "present" or "none",
    or "unknown" when its uploads cannot be listed. The page asks for the session's
    own rows (explorer/custom) beside the packaged list unless it is "none"."""

    if not metadata_session_id:
        return "none"
    try:
        return "present" if mds_uploads.has_items(metadata_session_id) else "none"
    except StorageReadError:
        return "unknown"


def _initial_mds_info() -> dict[str, Any]:
    """What the MDS explorer starts from: the packaged snapshot's summary (absent
    without a snapshot) and whether this session has uploaded metadata; the page
    loads the packaged list at its one URL. The page asks
    ``/api/mds/metadata/info`` for it, which waits for a provisioning under way;
    the page itself is static and never waits. A running instance takes a newer
    snapshot from Cloud Storage here (``mds_provisioning.follow_newer_snapshot``): this is where
    the page starts."""

    mds_provisioning.ensure_snapshot_available()
    mds_provisioning.follow_newer_snapshot()
    metadata_session_id = visitor_session.current_id()

    initial_mds_info = dict(mds_cache.load_packaged_explorer_summary() or {})
    initial_mds_info["customEntriesState"] = _custom_entries_state(metadata_session_id)
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
def api_get_full_explorer_metadata():
    # Where a page loaded before explorer/custom asked for every row, its own and the
    # packaged ones: it shows this sentence and keeps the rows it has.
    return _no_store_json_response({"error": "This page is older than the server: reload it."}, status=410)


@bp.route("/api/mds/metadata/explorer/custom", methods=["GET"])
@mds_provisioning.waits_for_the_snapshot
def api_get_custom_explorer_entries():
    # The visitor's own rows and the counts (the page holds the packaged list):
    # per session, so never cached and keyed on the cookie.
    return _no_store_json_response(mds_effective.load_custom_entries())


@bp.route("/api/mds/metadata/resolve", methods=["GET"])
@mds_provisioning.waits_for_the_snapshot
def api_resolve_metadata_entry():
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

    resolved = mds_effective.resolve_effective_metadata_entry(
        entry_id=provided.get("entry_id"),
        aaguid=provided.get("aaguid"),
        aaid=provided.get("aaid"),
    )
    if resolved is None:
        return _no_store_json_response({"error": "Metadata entry not found."}, status=404)

    return _no_store_json_response({"entry": resolved})


@bp.route("/api/mds/metadata/custom", methods=["GET"])
def api_list_custom_metadata():
    # Each upload's item as it was worked out for its version (mds/listed_uploads.py).
    return _no_store_json_response({"items": [upload.item for upload in mds_listed_uploads.list_uploads()]})


@bp.route("/api/mds/metadata/custom/<string:stored_filename>/icon", methods=["GET"])
def api_custom_metadata_icon(stored_filename: str):
    # An upload's icon, the visitor's own: kept for good, since an upload never changes
    # (another is saved under a new random name).
    icon = mds_effective.upload_icon(stored_filename)
    if icon is None:
        abort(404)
    response = Response(icon.data, mimetype=icon.mimetype)
    response.headers["Cache-Control"] = _ICON_CACHE_CONTROL
    response.headers["Content-Security-Policy"] = assets.ICON_POLICY
    return response


def _refuse_json_constant(constant: str) -> Any:
    raise mds_entries.MetadataRefused(f"{constant} is not JSON (RFC 8259 has no NaN or Infinity)")


def _finite_number(text: str) -> float:
    number = float(text)
    if not math.isfinite(number):
        raise mds_entries.MetadataRefused(f"{text[:32]} is beyond the range of a double")
    return number


def _metadata_values(raw_bytes: bytes, max_values: int) -> int:
    """How many values an uploaded file's JSON holds, as ``json_body`` counts them; refused past
    ``max_values``, what is left of the upload's, or nested deeper than a JSON body may be.

    Python's reader goes as deep as the text, and keeps about 26 bytes for each byte of ``{},``;
    the files of one upload are all kept until it is answered."""

    try:
        return json_body.check_limits(raw_bytes, max_values)
    except json_body.NestedTooDeep:
        raise mds_entries.MetadataRefused(f"JSON nested more than {json_body.MAX_DEPTH} deep, deeper than this server reads") from None
    except json_body.TooManyValues:
        cap = request_limits.MAX_METADATA_UPLOAD_VALUES
        raise mds_entries.MetadataRefused(f"JSON holding more than {cap:,} values in one upload, more than this server reads") from None


def _read_metadata_json(text: str) -> Any:
    # RFC 8259's JSON: the metadata is answered back, and NaN, or a number beyond a double's
    # range, which Python's reader makes an infinity, would make that answer not JSON.
    return json.loads(text, parse_constant=_refuse_json_constant, parse_float=_finite_number)


class _UploadedFile(NamedTuple):
    """One uploaded file read as metadata: its name, its bytes, the entries it holds and how many
    values its JSON holds (``_metadata_values``)."""

    name: str
    raw_bytes: bytes
    entries: list[Mapping[str, Any]]
    values: int


def _read_uploaded_file(storage: Any, max_values: int) -> tuple[_UploadedFile | None, str | None]:
    """One file of an upload, read and expanded into its entries; or the sentence that refuses it.

    Its JSON holds at most ``max_values`` values. A sentence is the app's own (``MetadataRefused``)
    or one written here: an exception's own text (a reader's, fido2's) is logged at INFO, never answered."""

    trimmed = (storage.filename or "").strip() or "metadata.json"
    if not trimmed.lower().endswith(".json"):
        return None, f"{trimmed} is not a JSON file."

    try:
        raw_bytes = storage.read()
    except Exception as exc:  # pylint: disable=broad-except
        logger.info("Could not read the uploaded file %s", trimmed, exc_info=exc)
        return None, f"Failed to read {trimmed}."

    try:
        # Counted before the text is decoded and parsed: both cost more than the bytes.
        values = _metadata_values(raw_bytes, max_values)
        payload: dict[str, Any] = _read_metadata_json(raw_bytes.decode("utf-8-sig"))
    except UnicodeDecodeError:
        return None, f"{trimmed} is not valid UTF-8 JSON."
    except json.JSONDecodeError as exc:
        logger.info("The uploaded file %s is not JSON", trimmed, exc_info=exc)
        return None, f"{trimmed} is not JSON (line {exc.lineno}, column {exc.colno})."
    except mds_entries.MetadataRefused as exc:
        return None, f"{trimmed}: {exc}"

    if not isinstance(payload, dict):
        return None, f"{trimmed} must contain a JSON object."

    try:
        entry_payloads = mds_entries.expand_metadata_entry_payloads(payload)
    except mds_entries.MetadataRefused as exc:
        return None, f"{trimmed}: {exc}"
    except (TypeError, ValueError) as exc:
        logger.info("Could not read the entries of the uploaded file %s", trimmed, exc_info=exc)
        return None, f"{trimmed}: {mds_entries.UNREADABLE_ENTRY}"
    return _UploadedFile(trimmed, raw_bytes, list(entry_payloads), values), None


def _save_uploaded_file(uploaded: _UploadedFile, saved_items: list[Any], errors: list[str]) -> Any | None:
    """Save one read file's entries; the 500 to answer when the store fails."""

    for index, entry_payload in enumerate(uploaded.entries, start=1):
        display_name = uploaded.name if len(uploaded.entries) == 1 else f"{uploaded.name} (entry {index})"

        try:
            item = mds_uploads.save_session_metadata_item(
                entry_payload,
                original_filename=display_name,
                max_bytes=current_app.config[request_limits.METADATA_ENTRY_LIMIT_KEY],
                listed=mds_listed_uploads.stored_form,
            )
        except mds_entries.MetadataRefused as exc:
            errors.append(f"{display_name}: {exc}")
            continue
        except ValueError as exc:
            logger.info("Could not save the uploaded entry %s", display_name, exc_info=exc)
            errors.append(f"{display_name}: {mds_entries.UNREADABLE_ENTRY}")
            continue
        except RuntimeError as exc:
            logger.info("Could not store the uploaded entry %s", display_name, exc_info=exc)
            return jsonify({"error": _STORE_FAILED}), 500

        saved_items.append(mds_uploads.serialize_session_metadata_item(item))
    return None


@bp.route("/api/mds/metadata/upload", methods=["POST"])
@mds_provisioning.waits_for_the_snapshot
def api_upload_custom_metadata():
    # The place is taken before the body is read, where an upload's memory starts, and given
    # back once its answer is built.
    if not _UPLOADS_READ.acquire(timeout=_UPLOAD_WAIT_SECONDS):
        response = jsonify({"error": _UPLOADS_BUSY})
        response.status_code = 503
        response.headers["Retry-After"] = str(_UPLOAD_RETRY_AFTER_SECONDS)
        return response
    try:
        return _read_and_save_upload()
    finally:
        _UPLOADS_READ.release()


def _read_and_save_upload():
    # Its own limit, before the body is read: the whole MDS metadata (config/request_limits.py).
    request.max_content_length = current_app.config[METADATA_UPLOAD_LIMIT_KEY]
    namespace = visitor_session.ensure_id()

    file_entries = request.files.getlist("files") if request.files else []
    if not file_entries:
        return jsonify({"items": [], "errors": ["No JSON files were provided."]}), 400

    # Every file is read before any is saved; each file's sentences stay in its place.
    read_files = []
    values_left = request_limits.MAX_METADATA_UPLOAD_VALUES
    for storage in file_entries:
        uploaded, refusal = _read_uploaded_file(storage, values_left)
        values_left -= uploaded.values if uploaded is not None else 0
        read_files.append((uploaded, refusal))
    errors_by_file = [[refusal] if refusal is not None else [] for _uploaded, refusal in read_files]
    upload_entries = [entry for uploaded, _refusal in read_files if uploaded is not None for entry in uploaded.entries]
    # Past the namespace's quota nothing is saved or queued (StorageQuotaExceeded: routes/errors.py).
    mds_uploads.refuse_past_quota(
        namespace,
        upload_entries,
        request_limits.metadata_quota(current_app.config),
        current_app.config[request_limits.METADATA_ENTRY_LIMIT_KEY],
    )
    if upload_entries:
        # Its last access is marked once, before any entry is saved, not with each entry: Cloud
        # Storage takes about one write a second to one object name.
        session_metadata.ensure_session(namespace)

    saved_items: list[Any] = []
    logged: list[tuple[str, bytes]] = []
    for (uploaded, _refusal), file_errors in zip(read_files, errors_by_file, strict=True):
        if uploaded is not None:
            saved_before = len(saved_items)
            failure = _save_uploaded_file(uploaded, saved_items, file_errors)
            if failure is not None:
                return failure
            if len(saved_items) > saved_before:
                logged.append((uploaded.name, uploaded.raw_bytes))

    # A file one of whose entries was saved is queued, whole, for the device log (never in this
    # request's time); a file none of whose entries was saved is not, nor one over the log's cap.
    github_mirror.queue_uploaded_metadata_files(logged)
    # The upload's bytes and entries go before the answer reads the namespace's rows back.
    del read_files, uploaded, logged
    return _upload_answer(saved_items, [error for file_errors in errors_by_file for error in file_errors])


def _upload_answer(saved_items: list[Any], errors: list[str]):
    """What an upload answers: the files saved, what was refused, and the session's
    own rows (as explorer/custom answers them) when any was saved (400 when none was)."""

    response: dict[str, Any] = {"items": saved_items}
    if errors:
        response["errors"] = errors
    if saved_items:
        response["custom"] = mds_effective.load_custom_entries()

    return _no_store_json_response(response, status=200 if saved_items else 400)


@bp.route("/api/mds/metadata/custom/<string:stored_filename>", methods=["DELETE"])
@mds_provisioning.waits_for_the_snapshot
def api_delete_custom_metadata(stored_filename: str):
    try:
        deleted = mds_uploads.delete_session_metadata_item(stored_filename)
    except ValueError as exc:  # the name, or the namespace's, refused before any store was touched
        logger.info("Refused deleting uploaded metadata %s", stored_filename, exc_info=exc)
        return jsonify({"error": "Invalid metadata filename."}), 400
    except RuntimeError as exc:
        logger.info("Could not delete uploaded metadata %s", stored_filename, exc_info=exc)
        return jsonify({"error": _DELETE_FAILED}), 500

    if not deleted:
        return _no_store_json_response(
            {"deleted": False, "message": "Metadata entry not found."},
            status=404,
        )

    return _no_store_json_response({"deleted": True, "custom": mds_effective.load_custom_entries()})


@bp.route("/api/mds/decode-certificate", methods=["POST"])
def api_decode_mds_certificate():
    if not request.is_json:
        return jsonify({"error": "Expected JSON payload."}), 400

    payload = json_body.json_object()
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
        details = attestation_certificates.serialize_attestation_certificate(certificate_bytes)
    except Exception as exc:  # pylint: disable=broad-except
        logger.info("Could not decode a certificate", exc_info=exc)
        return jsonify({"error": "Unable to decode certificate."}), 422

    return jsonify({"details": details})
