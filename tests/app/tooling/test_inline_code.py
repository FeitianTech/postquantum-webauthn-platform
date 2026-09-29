"""Nothing in the logic modules needs a policy that allows inline code or inline style.

A Content-Security-Policy whose ``script-src`` and ``style-src`` carry no
``'unsafe-inline'`` refuses what these checks keep out of the source:

- a script that sets a ``style`` attribute (``setAttribute('style', ...)``):
  code styles through CSSOM (``element.style``), which the policy allows;
- markup in a script that carries an ``on...=`` handler or a ``style=``
  attribute (a tag written in a string, as the MDS raw-data popup once was).

And the modules put nothing on ``window`` (or ``globalThis`` / ``self``): no
assignment, no ``delete``, no ``Object.assign`` / ``defineProperty`` onto it; a
module imports what it uses. These read ``web/src/logic`` (its tests aside);
``test_web_source_rules.py`` holds web/'s components to the same rules, and the
pages are the UI's static export, which ``web/scripts/check-export-csp.mjs`` scans
for inline scripts, style elements and attributes and ``on*`` handlers.

Each ``ALLOWED_*`` dict names what still does, each with the reason. It may only
shrink: an entry that no longer matches fails the test, so a converted file must
also leave the list.
"""
from __future__ import annotations

import re

from tests.app.tooling.test_html_sinks import LOGIC_ROOT, logic_modules

_STYLE_ATTRIBUTE = re.compile(r"""\bsetAttribute\s*\(\s*(['"`])style\1""")
# A tag written out in a string: ``<name``, attributes, then an inline handler or style.
_MARKUP_ATTRIBUTE = re.compile(
    r"""<[a-zA-Z][\w-]*(?:\s+[\w:-]+(?:\s*=\s*(?:\\?"[^"<>]*\\?"|'[^'<>]*'))?)*\s+(on[a-zA-Z]+|style)\s*="""
)

# path under web/src/logic -> reason.
ALLOWED_STYLE_ATTRIBUTES: dict[str, str] = {}

# (path under web/src/logic, attribute) -> reason.
ALLOWED_MARKUP_ATTRIBUTES: dict[tuple[str, str], str] = {}

# path under web/src/logic -> reason.
ALLOWED_GLOBAL_WRITES: dict[str, str] = {}

_GLOBAL = r"(?:window|globalThis|self)"
_ASSIGN = r"\s*(?:[-+*/%&|^]|\*\*|<<|>>>?|&&|\|\||\?\?)?=(?!=)"
_GLOBAL_WRITE = re.compile(
    rf"(?<![\w$.]){_GLOBAL}\s*\.\s*[A-Za-z_$][\w$]*{_ASSIGN}"
    rf"|(?<![\w$.]){_GLOBAL}\s*\[[^\]]*\]{_ASSIGN}"
    rf"|\bdelete\s+{_GLOBAL}\s*[.\[]"
    rf"|\bObject\s*\.\s*(?:assign|defineProperty|defineProperties)\s*\(\s*{_GLOBAL}\b"
)


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
    for path in logic_modules():
        lines = find_style_attributes(path.read_text(encoding="utf-8"))
        if lines:
            found[path.relative_to(LOGIC_ROOT).as_posix()] = lines
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


def find_markup_attributes(text: str) -> list[tuple[int, str]]:
    """(line, attribute) for each tag written in ``text`` with a handler or a style."""

    return [
        (number, match.group(1).lower())
        for number, code in _code_lines(text)
        for match in _MARKUP_ATTRIBUTE.finditer(code)
    ]


def _script_markup_attributes() -> list[tuple[str, int, str]]:
    return [
        (path.relative_to(LOGIC_ROOT).as_posix(), line, name)
        for path in logic_modules()
        for line, name in find_markup_attributes(path.read_text(encoding="utf-8"))
    ]


def test_script_markup_carries_no_inline_attributes():
    found = [
        f"{path}:{line} {name}="
        for path, line, name in _script_markup_attributes()
        if (path, name) not in ALLOWED_MARKUP_ATTRIBUTES
    ]

    assert found == [], "build the element with shared/ui/dom.js and style it from a stylesheet"


def test_allowed_markup_attributes_still_exist():
    current = {(path, name) for path, _line, name in _script_markup_attributes()}

    stale = sorted(f"{path} {name}=" for path, name in ALLOWED_MARKUP_ATTRIBUTES if (path, name) not in current)

    assert stale == [], "no longer there: remove these entries from ALLOWED_MARKUP_ATTRIBUTES"


def test_the_reader_finds_markup_attributes():
    source = "\n".join([
        r"""const a = '<p id="x" style="display: none;"></p>';""",
        r"""const b = `<button type="button" onclick="go()">Go</button>`;""",
        r"""const c = "<div class=\"x\" onMouseEnter=\"show(this)\">";""",
        r"""for (let i = 0; i<len; i += 1) { const style = 'x'; }""",
        r"""node.style = value; node.onclick = handler;""",
        r"""const d = '<p data-style="x" data-onclick="y">';""",
        r"""// const e = '<p style="x">';""",
    ])

    assert find_markup_attributes(source) == [(1, "style"), (2, "onclick"), (3, "onmouseenter")]


def find_global_writes(text: str) -> list[int]:
    """The lines of ``text`` that write to window, globalThis or self."""

    return [number for number, code in _code_lines(text) if _GLOBAL_WRITE.search(code)]


def _scripts_writing_globals() -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for path in logic_modules():
        lines = find_global_writes(path.read_text(encoding="utf-8"))
        if lines:
            found[path.relative_to(LOGIC_ROOT).as_posix()] = lines
    return found


def test_scripts_put_nothing_on_window():
    found = {path: lines for path, lines in _scripts_writing_globals().items() if path not in ALLOWED_GLOBAL_WRITES}

    assert found == {}, "import what the module needs instead of reading it from window"


def test_allowed_global_writes_still_exist():
    stale = sorted(set(ALLOWED_GLOBAL_WRITES) - set(_scripts_writing_globals()))

    assert stale == [], "no longer writes to window: remove these entries from ALLOWED_GLOBAL_WRITES"


def test_the_reader_finds_global_writes():
    source = "\n".join([
        "window.switchTab = switchTab;",
        "window.lastFakeCredLength=0;",
        "globalThis.foo ??= {};",
        "self['bar'] = 1;",
        "window.count += 1;",
        "delete window.__INITIAL_MDS_INFO__;",
        "Object.assign(window, { a });",
        "Object.defineProperty(globalThis, 'b', {});",
        "window.location.href = url;",
        "if (window.foo === bar) {}",
        "const nav = globalThis.navigator;",
        "window.addEventListener('resize', onResize);",
        "state.window = value;",
        "mywindow.x = 1;",
        "// window.commented = out;",
        "if (window.innerWidth >= 900) {}",
    ])

    assert find_global_writes(source) == [1, 2, 3, 4, 5, 6, 7, 8]
