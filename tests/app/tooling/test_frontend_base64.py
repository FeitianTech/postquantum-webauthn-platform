"""Frontend scripts decode base64 with ``shared/utils/base64.js``, never ``atob``.

``atob`` takes either spelling of a byte string -- padded or not, with or
without whitespace, with stray bits in its last character -- so the bytes a
value names depend on who reads it. Every byte field from the server is
base64url and is decoded with ``base64UrlToBytes``; a field named for base64
(``derBase64``, ...) with ``base64ToBytes``; text a person typed with
``forgivingBase64ToBytes``, which says what it forgives.

``ALLOWED`` names the files that still call ``atob``, each with the reason. It
may only shrink: a file that no longer calls it must leave the list.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _ROOT / "frontend" / "static" / "scripts"
_ATOB = re.compile(r"(?<![\w.$])atob\s*\(")

ALLOWED: dict[str, str] = {
    "shared/webauthn/json-ponyfill.js": (
        "vendored @github/webauthn-json, kept as published with its source map; it turns the "
        "server's base64url request options into buffers for navigator.credentials"
    ),
}


def _calls() -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for path in sorted(_SCRIPTS.rglob("*.js")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("//", 1)[0]
            if code.lstrip().startswith(("*", "/*")):
                continue
            if _ATOB.search(code):
                found.setdefault(path.relative_to(_SCRIPTS).as_posix(), []).append(number)
    return found


def test_frontend_scripts_do_not_call_atob():
    calls = {path: lines for path, lines in _calls().items() if path not in ALLOWED}

    assert calls == {}, "decode with shared/utils/base64.js instead of atob"


def test_allowed_files_still_call_atob():
    calls = _calls()

    stale = sorted(path for path in ALLOWED if path not in calls)

    assert stale == [], "no longer calls atob: remove these entries from ALLOWED"
