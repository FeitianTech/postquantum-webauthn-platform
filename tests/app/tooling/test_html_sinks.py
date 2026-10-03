"""The logic modules never hand the browser a string to parse as markup.

There is no ``.innerHTML`` / ``.outerHTML`` assignment, no ``insertAdjacentHTML``,
``document.write`` / ``writeln``, ``parseFromString``, ``createContextualFragment``
or ``setHTMLUnsafe`` / ``parseHTMLUnsafe`` call in ``web/src/logic`` (its tests
aside); web/'s components render with React (``test_web_source_rules.py`` holds
them to the same rule).

A string built at run time sooner or later carries data; a fixed one does not,
but each of these calls is a Trusted Types sink all the same. The policy
(``require-trusted-types-for 'script'`` in ``config/security_headers.py``)
refuses every string given to one, so none is written.

``ALLOWED`` names the sinks that remain, each with the reason. It may only
shrink: an entry that no longer matches a sink fails the test, so a converted
view must also leave the list.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
LOGIC_ROOT = _ROOT / "web" / "src" / "logic"

_SINK = re.compile(
    r"\.(?:inner|outer)HTML\s*\+?=(?!=)"
    r"|\binsertAdjacentHTML\s*\("
    r"|\b\w*[dD]oc(?:ument)?\.write(?:ln)?\s*\("
    r"|\bparseFromString\s*\("
    r"|\bcreateContextualFragment\s*\("
    r"|\b(?:set|parse)HTMLUnsafe\s*\("
)

# (path under web/src/logic, the line as written, stripped) -> reason.
ALLOWED: dict[tuple[str, str], str] = {}


def _code(line: str) -> str:
    """The line without a ``//`` tail, or nothing for a comment line."""

    code = line.split("//", 1)[0]
    return "" if code.lstrip().startswith(("*", "/*")) else code


def find_sinks(text: str) -> list[tuple[int, str]]:
    """Every sink in ``text``: (line, the line as written, stripped)."""

    return [
        (number, line.strip())
        for number, line in enumerate(text.splitlines(), 1)
        if _SINK.search(_code(line))
    ]


def logic_modules() -> list[Path]:
    """Every logic module: the ``.js`` files under web/src/logic but their tests."""

    return sorted(path for path in LOGIC_ROOT.rglob("*.js") if not path.name.endswith(".test.js"))


def _script_sinks() -> list[tuple[str, int, str]]:
    return [
        (path.relative_to(LOGIC_ROOT).as_posix(), line, source)
        for path in logic_modules()
        for line, source in find_sinks(path.read_text(encoding="utf-8"))
    ]


def test_scripts_parse_no_markup():
    found = [
        f"{path}:{line} {source}"
        for path, line, source in _script_sinks()
        if (path, source) not in ALLOWED
    ]

    assert found == [], (
        "these hand the browser markup to parse; give the text to a React component instead"
    )


def test_allowed_sinks_still_exist():
    current = {(path, source) for path, _line, source in _script_sinks()}

    stale = sorted(f"{path}: {source}" for path, source in ALLOWED if (path, source) not in current)

    assert stale == [], "no longer a sink: remove these entries from ALLOWED"


def test_the_reader_finds_every_sink():
    source = "\n".join([
        "el.innerHTML = '';",
        "el.innerHTML = `<p>${name}</p>`;",
        "el.innerHTML += row;",
        "el.outerHTML = markup;",
        "el.insertAdjacentHTML('beforeend', '<hr>');",
        "document.write(template);",
        "popupDoc.writeln('<p>');",
        "new DOMParser().parseFromString(text, 'text/html');",
        "range.createContextualFragment(markup);",
        "el.setHTMLUnsafe(markup);",
        "// el.innerHTML = notCode;",
        " * document.write(inDocs);",
        "if (el.innerHTML === '') {}",
        "el.replaceChildren();",
        "writer.write(chunk);",
        "const doc = viewer.document;",
    ])

    assert [line for line, _source in find_sinks(source)] == list(range(1, 11))
