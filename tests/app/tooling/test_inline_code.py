"""Nothing in the page needs a policy that allows inline code or inline style.

A Content-Security-Policy whose ``script-src`` and ``style-src`` carry no
``'unsafe-inline'`` refuses what these checks keep out of the source:

- an inline event handler in a template (``onclick=``, ``onmouseenter=``, ...):
  a control names what it does with ``data-action``, and the module that owns
  the behaviour binds it (``shared/ui/actions.js``);
- a ``style`` attribute in a template: its rule belongs in a stylesheet under
  ``frontend/static/styles``;
- a script that sets a ``style`` attribute (``setAttribute('style', ...)``):
  views style through CSSOM (``element.style``), which the policy allows, and
  ``shared/ui/dom.js`` ``el()`` applies its ``style`` option that way;
- markup in a script that carries an ``on...=`` handler or a ``style=``
  attribute (a tag written in a string, as the MDS raw-data popup once was).

Each ``ALLOWED_*`` dict names what still does, each with the reason. It may only
shrink: an entry that no longer matches fails the test, so a converted file must
also leave the list.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS = _ROOT / "frontend" / "static" / "scripts"
_TEMPLATES = _ROOT / "frontend" / "templates"

_STYLE_ATTRIBUTE = re.compile(r"""\bsetAttribute\s*\(\s*(['"`])style\1""")
# A tag written out in a string: ``<name``, attributes, then an inline handler or style.
_MARKUP_ATTRIBUTE = re.compile(
    r"""<[a-zA-Z][\w-]*(?:\s+[\w:-]+(?:\s*=\s*(?:\\?"[^"<>]*\\?"|'[^'<>]*'))?)*\s+(on[a-zA-Z]+|style)\s*="""
)

# path under frontend/static/scripts -> reason.
ALLOWED_STYLE_ATTRIBUTES: dict[str, str] = {}

# (path under frontend/static/scripts, attribute) -> reason.
ALLOWED_MARKUP_ATTRIBUTES: dict[tuple[str, str], str] = {}

# (path under frontend/templates, attribute) -> reason.
ALLOWED_TEMPLATE_ATTRIBUTES: dict[tuple[str, str], str] = {}


class _Tags(HTMLParser):
    """Every start tag of a template: (line, tag, attributes)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[int, str, list[tuple[str, str | None]]]] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((self.getpos()[0], tag, attrs))

    handle_startendtag = handle_starttag


def template_tags(text: str) -> list[tuple[int, str, list[tuple[str, str | None]]]]:
    parser = _Tags()
    parser.feed(text)
    parser.close()
    return parser.tags


def find_inline_attributes(text: str) -> list[tuple[int, str]]:
    """(line, attribute) for each attribute of ``text`` a strict policy refuses."""

    return [
        (line, name)
        for line, _tag, attrs in template_tags(text)
        for name, _value in attrs
        if name == "style" or name.startswith("on")
    ]


def _template_attributes() -> list[tuple[str, int, str]]:
    return [
        (path.relative_to(_TEMPLATES).as_posix(), line, name)
        for path in sorted(_TEMPLATES.rglob("*.html"))
        for line, name in find_inline_attributes(path.read_text(encoding="utf-8"))
    ]


def test_templates_carry_no_inline_attributes():
    found = [
        f"{path}:{line} {name}="
        for path, line, name in _template_attributes()
        if (path, name) not in ALLOWED_TEMPLATE_ATTRIBUTES
    ]

    assert found == [], "name the action with data-action, and move a style into a stylesheet"


def test_allowed_template_attributes_still_exist():
    current = {(path, name) for path, _line, name in _template_attributes()}

    stale = sorted(f"{path} {name}=" for path, name in ALLOWED_TEMPLATE_ATTRIBUTES if (path, name) not in current)

    assert stale == [], "no longer there: remove these entries from ALLOWED_TEMPLATE_ATTRIBUTES"


def test_the_template_reader_finds_inline_attributes():
    source = "\n".join([
        '<p style="color: red">x</p>',
        '<p class="muted" data-style="x">{{ value }}</p>',
        '{% include \'part.html\' %}',
        '<input readonly STYLE="a: b">',
        '<!-- <p style="in a comment"> -->',
        '<button type="button" onclick="go()" data-action="go">Go</button>',
        '<div class="info-icon" onMouseEnter="show(this)" data-onclick="x"></div>',
    ])

    assert find_inline_attributes(source) == [(1, "style"), (4, "style"), (6, "onclick"), (7, "onmouseenter")]


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


def find_markup_attributes(text: str) -> list[tuple[int, str]]:
    """(line, attribute) for each tag written in ``text`` with a handler or a style."""

    return [
        (number, match.group(1).lower())
        for number, code in _code_lines(text)
        for match in _MARKUP_ATTRIBUTE.finditer(code)
    ]


def _script_markup_attributes() -> list[tuple[str, int, str]]:
    return [
        (path.relative_to(_SCRIPTS).as_posix(), line, name)
        for path in sorted(_SCRIPTS.rglob("*.js"))
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
