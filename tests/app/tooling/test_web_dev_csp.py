"""``npm run dev`` sends Flask's own Content Security Policy.

``web/scripts/dev-csp.mjs`` holds a copy of the default policies in
``server/app/config/security_headers.py`` as data, and adds the two allowances the
dev server needs, each with its reason (``web/scripts/dev-csp.test.ts`` holds
those). This fails when the copy and Flask's defaults differ, so a change to the
policy reaches the dev server too.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from server.app.config import security_headers

_DEV_CSP = Path(__file__).resolve().parents[3] / "web" / "scripts" / "dev-csp.mjs"


def _array(name: str) -> list[str]:
    text = _DEV_CSP.read_text(encoding="utf-8")
    match = re.search(rf"^export const {name} = (\[.*?\]);$", text, re.M | re.S)
    assert match, f"{name} is not an array literal in dev-csp.mjs"
    return json.loads(re.sub(r",\s*\]$", "]", match.group(1)))


def _string(name: str) -> str:
    match = re.search(rf"^export const {name} = '([^']*)';$", _DEV_CSP.read_text(encoding="utf-8"), re.M)
    assert match, f"{name} is not a string literal in dev-csp.mjs"
    return match.group(1)


def test_the_dev_server_copies_flasks_enforced_policy():
    assert "; ".join(_array("FLASK_POLICY")) == security_headers._DEFAULT_CONTENT_SECURITY_POLICY


def test_the_dev_server_copies_flasks_report_only_policy_and_endpoints():
    assert "; ".join(_array("FLASK_REPORT_ONLY_POLICY")) == security_headers._DEFAULT_CONTENT_SECURITY_POLICY_REPORT_ONLY
    assert _string("FLASK_REPORTING_ENDPOINTS") == security_headers._DEFAULT_REPORTING_ENDPOINTS
