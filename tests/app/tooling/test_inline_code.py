"""Nothing in the page needs a policy that allows inline code or inline style.

A Content-Security-Policy whose ``script-src`` and ``style-src`` carry no
``'unsafe-inline'`` refuses what these checks keep out of the source:

- a script that sets a ``style`` attribute (``setAttribute('style', ...)``):
  views style through CSSOM (``element.style``), which the policy allows, and
  ``shared/ui/dom.js`` ``el()`` applies its ``style`` option that way.

``ALLOWED`` names what still does, each with the reason. It may only shrink: an
entry that no longer matches fails the test, so a converted file must also
leave the list.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _ROOT / "frontend" / "static" / "scripts"

_STYLE_ATTRIBUTE = re.compile(r"""\bsetAttribute\s*\(\s*(['"`])style\1""")

# path under frontend/static/scripts -> reason.
ALLOWED_STYLE_ATTRIBUTES: dict[str, str] = {}


def _code_lines(text: str):
    """(line number, code) for each line, with ``//`` tails and comment lines blanked."""

    for number, line in enumerate(text.splitlines(), 1):
        code = line.split("//", 1)[0]
        if code.lstrip().startswith(("*", "/*")):
            code = ""
        yield number, code


def find_style_attributes(text: str) -> list[int]:
    """The lines of ``text`` that set a style attribute."""

    return [number for number, code in _code_lines(text) if _STYLE_ATTRIBUTE.search(code)]


def _scripts_setting_style() -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for path in sorted(_SCRIPTS.rglob("*.js")):
        lines = find_style_attributes(path.read_text(encoding="utf-8"))
        if lines:
            found[path.relative_to(_SCRIPTS).as_posix()] = lines
    return found


def test_scripts_never_set_a_style_attribute():
    found = {path: lines for path, lines in _scripts_setting_style().items() if path not in ALLOWED_STYLE_ATTRIBUTES}

    assert found == {}, "set the style through element.style (CSSOM) instead"


def test_allowed_style_attributes_still_exist():
    stale = sorted(set(ALLOWED_STYLE_ATTRIBUTES) - set(_scripts_setting_style()))

    assert stale == [], "no longer sets a style attribute: remove these entries from ALLOWED_STYLE_ATTRIBUTES"


def test_the_reader_finds_style_attributes():
    source = "\n".join([
        "node.setAttribute('style', style);",
        'node.setAttribute( "style" , value);',
        "node.style.cssText = style;",
        "node.setAttribute('data-style', 'x');",
        "// node.setAttribute('style', notCode);",
        " * node.setAttribute('style', inDocs);",
    ])

    assert find_style_attributes(source) == [1, 2]
