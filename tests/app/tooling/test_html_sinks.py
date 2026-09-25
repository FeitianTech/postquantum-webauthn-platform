"""Frontend scripts write markup only as fixed text from the code itself.

Every ``.innerHTML`` / ``.outerHTML`` assignment and every ``insertAdjacentHTML``
call in ``frontend/static/scripts`` must be given ``''`` or a single string or
template literal with no ``${...}`` in it. Anything else -- a variable, a call,
a concatenation, ``+=`` -- is a string built at run time, and a string built at
run time sooner or later carries data. Views that show data build it with
``shared/ui/dom.js`` (createElement and textContent) instead.

``ALLOWED`` names the sinks that still take a built string, each with the reason.
It may only shrink: an entry that no longer matches a sink fails the test, so a
converted view must also leave the list.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _ROOT / "frontend" / "static" / "scripts"

_ASSIGNMENT = re.compile(r"\.(?:inner|outer)HTML\s*(\+?=)(?!=)")
_INSERT = re.compile(r"\binsertAdjacentHTML\s*\(")

# (path under frontend/static/scripts, the right-hand side as written) -> reason.
ALLOWED: dict[tuple[str, str], str] = {
    ("advanced/credential-display/credential-detail-runtime/entry.js", "finalDetailsHtml"): (
        "the credential detail sections, values escaped; goes when they are built as DOM"
    ),
}


def _read_quoted(text: str, start: int) -> tuple[str, int] | None:
    """The literal opening at ``start`` and the index after it, or None if unterminated."""

    quote = text[start]
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return text[start + 1:index], index + 1
        if char == "\n" and quote != "`":
            return None
        index += 1
    return None


def _literal_verdict(text: str, start: int, terminators: str) -> tuple[bool, str]:
    """Whether the expression at ``start`` is one markup-free literal, and its source."""

    index = start
    while index < len(text) and text[index] in " \t\r\n":
        index += 1
    end = index
    while end < len(text) and text[end] not in terminators:
        if text[end] in "'\"`":
            quoted = _read_quoted(text, end)
            end = quoted[1] if quoted else len(text)
            continue
        end += 1
    source = text[index:end].strip()

    if index >= len(text) or text[index] not in "'\"`":
        return False, source
    quoted = _read_quoted(text, index)
    if quoted is None:
        return False, source
    body, after = quoted
    if text[index] == "`" and "${" in body:
        return False, source
    rest = after
    while rest < len(text) and text[rest] in " \t\r\n":
        rest += 1
    return rest < len(text) and text[rest] in terminators, source


def _is_comment(text: str, position: int) -> bool:
    line_start = text.rfind("\n", 0, position) + 1
    before = text[line_start:position]
    stripped = before.lstrip()
    return "//" in before or stripped.startswith("*") or stripped.startswith("/*")


def find_sinks(text: str) -> list[tuple[int, str, bool]]:
    """Every sink in ``text``: (line, right-hand side as written, whether it is allowed as is)."""

    sinks: list[tuple[int, str, bool]] = []
    for match in _ASSIGNMENT.finditer(text):
        if _is_comment(text, match.start()):
            continue
        is_literal, source = _literal_verdict(text, match.end(), ";")
        allowed = is_literal and match.group(1) == "="
        sinks.append((text.count("\n", 0, match.start()) + 1, source, allowed))
    for match in _INSERT.finditer(text):
        if _is_comment(text, match.start()):
            continue
        comma = text.find(",", match.end())
        if comma < 0:
            sinks.append((text.count("\n", 0, match.start()) + 1, text[match.end():].strip(), False))
            continue
        is_literal, source = _literal_verdict(text, comma + 1, ")")
        sinks.append((text.count("\n", 0, match.start()) + 1, source, is_literal))
    return sinks


def _script_sinks() -> list[tuple[str, int, str, bool]]:
    return [
        (path.relative_to(_SCRIPTS).as_posix(), line, source, allowed)
        for path in sorted(_SCRIPTS.rglob("*.js"))
        for line, source, allowed in find_sinks(path.read_text(encoding="utf-8"))
    ]


def test_markup_sinks_take_only_fixed_text():
    built = [
        f"{path}:{line} = {source}"
        for path, line, source, allowed in _script_sinks()
        if not allowed and (path, source) not in ALLOWED
    ]

    assert built == [], (
        "these sinks take a string built at run time; build the view with "
        "shared/ui/dom.js instead"
    )


def test_allowed_sinks_still_exist():
    current = {(path, source) for path, _line, source, allowed in _script_sinks() if not allowed}

    stale = sorted(f"{path} = {source}" for path, source in ALLOWED if (path, source) not in current)

    assert stale == [], "no longer a sink: remove these entries from ALLOWED"


def test_the_reader_tells_fixed_text_from_built_strings():
    source = "\n".join([
        "el.innerHTML = '';",
        'el.innerHTML = "";',
        "el.innerHTML = '<p>fixed</p>';",
        "el.innerHTML = `",
        "    <option value=\"all\">All</option>",
        "`;",
        "el.innerHTML = `<p>${name}</p>`;",
        "el.innerHTML = html;",
        "el.innerHTML = '<p>' + name + '</p>';",
        "el.innerHTML += '';",
        "el.outerHTML = markup;",
        "el.insertAdjacentHTML('beforeend', '<hr>');",
        "el.insertAdjacentHTML('beforeend', row);",
        "// el.innerHTML = notCode;",
        "if (el.innerHTML === '') {}",
    ])

    assert find_sinks(source) == [
        (1, "''", True),
        (2, '""', True),
        (3, "'<p>fixed</p>'", True),
        (4, '`\n    <option value="all">All</option>\n`', True),
        (7, "`<p>${name}</p>`", False),
        (8, "html", False),
        (9, "'<p>' + name + '</p>'", False),
        (10, "''", False),
        (11, "markup", False),
        (12, "'<hr>'", True),
        (13, "row", False),
    ]
