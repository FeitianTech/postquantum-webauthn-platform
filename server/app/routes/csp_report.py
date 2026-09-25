"""``POST /api/csp-report``: where browsers send Content-Security-Policy violations.

``config/security_headers.py`` names it in both policies' ``report-uri`` and, as
the ``csp`` endpoint of ``Reporting-Endpoints``, their ``report-to``. What a report
holds, and the one line logged for each violation, is ``csp_reports.py``.

The body is bounded here, before it is read: 512 KiB, room for a Reporting API
batch of a few hundred reports of about 1.2 KB each. A larger one is answered
413 without ``errors.py``'s log line for every oversized body, so a flood of
large reports writes no more than the rate limit lets through. At most 100
violations of one request are logged; the rest count as dropped.
"""
from __future__ import annotations

import json

from flask import Blueprint, current_app, jsonify, request

from ..csp_reports import ViolationLog, violations_from
from .errors import too_large_answer

bp = Blueprint("csp_report", __name__)

MAX_REPORT_BYTES = 512 * 1024
MAX_VIOLATIONS_PER_REQUEST = 100
REPORT_MEDIA_TYPES = frozenset({"application/csp-report", "application/reports+json", "application/json"})

# The app's ViolationLog: one per app, so each instance keeps its own limit.
LOG_EXTENSION = "csp_report_log"


@bp.record_once
def _create_log(state) -> None:
    state.app.extensions[LOG_EXTENSION] = ViolationLog()


@bp.route("/api/csp-report", methods=["POST"])
def csp_report():
    log: ViolationLog = current_app.extensions[LOG_EXTENSION]

    if request.mimetype not in REPORT_MEDIA_TYPES:
        return jsonify({"error": "A CSP report is sent as application/csp-report or application/reports+json."}), 415

    # Content-Length first: reading a stream longer than MAX_CONTENT_LENGTH raises
    # the 413 errors.py logs. Without one (chunked), read one byte past the limit.
    if request.content_length is not None and request.content_length > MAX_REPORT_BYTES:
        log.refused_as_too_large(MAX_REPORT_BYTES)
        return too_large_answer(MAX_REPORT_BYTES)
    body = request.stream.read(MAX_REPORT_BYTES + 1)
    if len(body) > MAX_REPORT_BYTES:
        log.refused_as_too_large(MAX_REPORT_BYTES)
        return too_large_answer(MAX_REPORT_BYTES)

    try:
        payload = json.loads(body)
    except ValueError:
        return jsonify({"error": "The report is not JSON."}), 400
    violations = violations_from(payload)
    if violations is None:
        return jsonify({"error": "The report is neither a report-uri nor a report-to body."}), 400

    for violation in violations[:MAX_VIOLATIONS_PER_REQUEST]:
        log.record(violation)
    log.drop(len(violations) - MAX_VIOLATIONS_PER_REQUEST)
    return "", 204
