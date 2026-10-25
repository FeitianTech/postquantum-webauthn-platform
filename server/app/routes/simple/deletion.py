"""Deleting a Simple credential's record from the server, when the person deletes the
credential in the page or clears them all.

The record is in its username's list, which the deletion rewrites by
compare-and-swap, as a registration's append does; the list's other records are
brought to today's form as it is written. It answers as the artifact DELETE does
(``deleted``, ``absent``, or ``failed`` with the reason), so the page tells the
outcomes apart the same way for both tabs' credentials.
"""
from __future__ import annotations

import logging
from typing import Any

from flask import Blueprint, jsonify, request

from ... import encoding, visitor_session
from ...storage import common as storage_common
from ...storage import credentials
from . import stored_sign_count

bp = Blueprint("simple_deletion", __name__)

logger = logging.getLogger(__name__)

# As a registration's append: each other writer wins at most once while this one waits.
_DELETE_ATTEMPTS = 8
_DELETE_FAILED = "Unable to delete credential from server storage."


@bp.after_request
def _per_visitor(response):
    """Every answer here is the visitor's own: never cached, and keyed on the cookie."""

    response.headers["Cache-Control"] = "no-store"
    response.vary.add("Cookie")
    return response


def _failed(error: str, status: int) -> Any:
    return jsonify({"status": "failed", "error": error}), status


@bp.route("/api/simple/credentials/<string:credential_id>", methods=["DELETE"])
def api_delete_simple_credential(credential_id: str):
    # The name as the store names its file, not as the begins take one: a record saved
    # before their 64-byte rule can still be deleted.
    try:
        username = storage_common.validate_storage_component(request.args.get("email"))
    except storage_common.InvalidStorageIdentifier:
        return _failed("Invalid username.", 400)
    raw_id = encoding.try_decode_base64url(credential_id)
    if not raw_id:
        return _failed("Invalid credential ID.", 400)

    # A visitor without a namespace has stored nothing, and deleting mints none.
    namespace = visitor_session.current_id()
    if not namespace:
        return jsonify({"status": "absent"})
    return _delete_record(username, raw_id, namespace)


def _delete_record(username: str, credential_id: bytes, namespace: str) -> Any:
    """Remove the record from its username's list by compare-and-swap; the answer."""

    for _attempt in range(_DELETE_ATTEMPTS):
        try:
            records, version = credentials.read_for_update(username, session_id=namespace)
        except credentials.CredentialsUndecodable as exc:
            # Rewriting a copy nobody could read would lose it: unreadable, as a registration treats it.
            raise storage_common.StorageReadError(str(exc)) from exc
        kept = [record for record in records if stored_sign_count.record_credential_id(record) != credential_id]
        if len(kept) == len(records):
            return jsonify({"status": "absent"})

        saved = [stored_sign_count.as_counter_record(record) for record in kept]
        try:
            if credentials.save_if_unchanged(username, saved, version, session_id=namespace):
                return jsonify({"status": "deleted"})
        except Exception:
            if _is_gone(username, credential_id, namespace):
                return jsonify({"status": "deleted"})
            logger.exception("Failed to delete a Simple credential of %s", username)
            return _failed(_DELETE_FAILED, 500)
        logger.info("The stored credentials of %s changed while one was being deleted; reading them again", username)

    logger.warning("Kept a Simple credential of %s: its stored credentials kept changing", username)
    return _failed("The stored credentials kept changing while this one was being deleted. Please try again.", 409)


def _is_gone(username: str, credential_id: bytes, namespace: str) -> bool:
    """Whether a save that raised had landed anyway (a reply lost after the write)."""

    try:
        records = credentials.readkey(username, session_id=namespace)
    except Exception:
        return False
    return all(stored_sign_count.record_credential_id(record) != credential_id for record in records)
