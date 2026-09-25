"""Content-Security-Policy violation reports: read them, and log each in one line.

A browser reports what the policy (``config/security_headers.py``) blocks, and
what the report-only Trusted Types policy would block, in one of two formats:

- ``report-uri`` (Firefox, Safari): one ``{"csp-report": {...}}`` per request,
  sent as ``application/csp-report``, its keys spelled with hyphens;
- ``report-to`` (Chromium): a JSON list of reports, sent as
  ``application/reports+json``, each ``{"type": "csp-violation", "body": {...}}``
  with camelCase keys. Other report types in the list are skipped.

Each violation becomes one WARNING line (production logs WARNING and above) --
``CSP violation: directive=<d> blocked=<b> path=<p>`` -- so a page the policy
breaks shows in the Cloud Run logs. Nothing else is kept: no query string or
fragment, no user agent, no address, no sample of the blocked code. A Trusted
Types report names its sink (``trusted-types-sink(Element.innerHTML)``), the part
of the sample before its ``|``, since that is all it says about what was blocked.
Every field is cut to printable ASCII and 200 characters, so a line stays one
line whatever a report holds.

``ViolationLog`` bounds how many lines a flood can write: a token bucket per app,
burst 30 and 30 a minute after that. What it drops it counts, and the next line
it writes says how many.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

FIELD_LIMIT = 200
BURST = 30
PER_MINUTE = 30

_UNPRINTABLE = re.compile(r"[^\x21-\x7e]")
_TRUSTED_TYPES_SINK = "trusted-types-sink"


@dataclass(frozen=True)
class Violation:
    directive: str
    blocked: str
    path: str


def _clean(text: str) -> str:
    return _UNPRINTABLE.sub("?", text)[:FIELD_LIMIT] or "-"


def _directive(value: Any) -> str:
    # CSP2's violated-directive carries its sources too ("script-src 'self'").
    words = value.split() if isinstance(value, str) else []
    return _clean(words[0]) if words else "-"


def _blocked(value: Any, sample: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "-"
    value = value.strip()
    if ":" not in value:
        # A keyword: inline, eval, wasm-eval, data, blob, trusted-types-sink ...
        if value == _TRUSTED_TYPES_SINK and isinstance(sample, str) and "|" in sample:
            sink = ".".join(sample.split("|", 1)[0].split())
            if sink:
                return _clean(f"{value}({sink})")
        return _clean(value)
    parts = urlsplit(value)
    if parts.scheme in ("http", "https") and parts.hostname:
        host = parts.netloc.rpartition("@")[2]
        return _clean(f"{parts.scheme}://{host}{parts.path}")
    # data:, blob:, chrome-extension: ...: the scheme says enough.
    return _clean(f"{parts.scheme}:" if parts.scheme else value)


def _path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "-"
    parts = urlsplit(value.strip())
    if parts.scheme in ("http", "https"):
        return _clean(parts.path or "/")
    # about:blank (the MDS raw-data popup) and the like.
    return _clean(f"{parts.scheme}:{parts.path}" if parts.scheme else parts.path)


def violations_from(payload: Any) -> list[Violation] | None:
    """The violations a report body holds, or None when it is neither format."""

    if isinstance(payload, dict):
        body = payload.get("csp-report")
        if not isinstance(body, dict):
            return None
        return [
            Violation(
                directive=_directive(body.get("effective-directive") or body.get("violated-directive")),
                blocked=_blocked(body.get("blocked-uri"), body.get("script-sample")),
                path=_path(body.get("document-uri")),
            )
        ]
    if isinstance(payload, list):
        violations = []
        for report in payload:
            if not isinstance(report, dict) or report.get("type") != "csp-violation":
                continue
            body = report.get("body")
            if not isinstance(body, dict):
                continue
            violations.append(
                Violation(
                    directive=_directive(body.get("effectiveDirective")),
                    blocked=_blocked(body.get("blockedURL"), body.get("sample")),
                    path=_path(body.get("documentURL")),
                )
            )
        return violations
    return None


class ViolationLog:
    """Logs violations one line each, at most ``burst`` at once and ``per_minute`` after."""

    def __init__(
        self,
        *,
        burst: int = BURST,
        per_minute: int = PER_MINUTE,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._capacity = float(burst)
        self._tokens = float(burst)
        self._rate = per_minute / 60.0
        self._clock = clock
        self._updated = clock()
        self._dropped = 0
        self._lock = threading.Lock()

    def _take(self) -> tuple[bool, int]:
        """Whether a line may be written, and how many were dropped before it."""

        with self._lock:
            now = self._clock()
            self._tokens = min(self._capacity, self._tokens + (now - self._updated) * self._rate)
            self._updated = now
            if self._tokens < 1:
                self._dropped += 1
                return False, 0
            self._tokens -= 1
            dropped, self._dropped = self._dropped, 0
            return True, dropped

    def _write(self, message: str, *args: Any) -> None:
        allowed, dropped = self._take()
        if not allowed:
            return
        if dropped:
            logger.warning("CSP violation reports dropped over the rate limit: %d", dropped)
        logger.warning(message, *args)

    def record(self, violation: Violation) -> None:
        self._write(
            "CSP violation: directive=%s blocked=%s path=%s",
            violation.directive,
            violation.blocked,
            violation.path,
        )

    def refused_as_too_large(self, limit: int) -> None:
        """A report not read at all, logged under the same limit."""

        self._write("CSP report refused: larger than %d bytes", limit)

    def drop(self, count: int) -> None:
        """Count violations a request carried past what one request may log."""

        if count > 0:
            with self._lock:
                self._dropped += count
