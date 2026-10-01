"""The logic modules decode base64 with ``shared/utils/base64.js``, never ``atob``.

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

from tests.app.tooling.test_html_sinks import LOGIC_ROOT, logic_modules

_ATOB = re.compile(r"(?<![\w.$])atob\s*\(")

ALLOWED: dict[str, str] = {}


def _calls() -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for path in logic_modules():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("//", 1)[0]
            if code.lstrip().startswith(("*", "/*")):
                continue
            if _ATOB.search(code):
                found.setdefault(path.relative_to(LOGIC_ROOT).as_posix(), []).append(number)
    return found


def test_frontend_scripts_do_not_call_atob():
    calls = {path: lines for path, lines in _calls().items() if path not in ALLOWED}

    assert calls == {}, "decode with shared/utils/base64.js instead of atob"


def test_allowed_files_still_call_atob():
    calls = _calls()

    stale = sorted(path for path in ALLOWED if path not in calls)

    assert stale == [], "no longer calls atob: remove these entries from ALLOWED"
