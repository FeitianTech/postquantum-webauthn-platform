"""The new UI in ``web/src`` keeps the same rules as the legacy scripts, and keeps one copy of the logic.

What ships from ``web/src`` (everything but its tests) is held to what the strict
CSP and the Trusted Types report-only policy need, with the legacy guards' own
readers (``test_html_sinks.py``, ``test_inline_code.py``):

- no markup sink (``innerHTML``, ``document.write``, ...) and no
  ``dangerouslySetInnerHTML``, ``DOMParser`` or ``srcdoc``: React builds the DOM;
- no ``style=`` prop: the static export would render it as a ``style`` attribute,
  which the policy refuses (a component that must place something at run time
  sets ``element.style`` through a ref, as the CSSOM is allowed), no
  ``setAttribute('style')``, and no ``<style>`` or ``<script>`` element;
- no ``next/script``, no ``eval`` or ``new Function`` (no ``'unsafe-eval'``);
- nothing written to ``window`` / ``globalThis`` / ``self``, and no ``atob``
  (``shared/utils/base64.js`` decodes strictly).

And the Analyze Browser's logic (``frontend/static/scripts/shared/browser``) is
imported, never copied (docs/UI_MIGRATION.md): no module in ``web/src`` defines a
name those modules export, or carries one of their sentences.

Each ``ALLOWED`` dict may only shrink; an entry that no longer matches fails.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests.app.tooling.test_html_sinks import find_sinks
from tests.app.tooling.test_inline_code import find_global_writes, find_style_attributes

_ROOT = Path(__file__).resolve().parents[3]
_WEB_SRC = _ROOT / "web" / "src"
_LEGACY_LOGIC = _ROOT / "frontend" / "static" / "scripts" / "shared" / "browser"
LOGIC_MODULES = ("identity.js", "probe.js", "report.js", "webauthn-facts.js")

_RULES: dict[str, re.Pattern[str]] = {
    "dangerouslySetInnerHTML": re.compile(r"\bdangerouslySetInnerHTML\b"),
    "DOMParser": re.compile(r"\bDOMParser\b"),
    "srcdoc": re.compile(r"\bsrcDoc\b|\bsrcdoc\b"),
    "style prop": re.compile(r"(?<=\s)style=\{"),
    "<style> or <script> element": re.compile(r"<(?:style|script)\b"),
    "next/script": re.compile(r"""['"]next/script['"]"""),
    "eval": re.compile(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\("),
    "atob": re.compile(r"(?<![\w$.])atob\s*\("),
}

# (path under web/src, rule) -> reason.
ALLOWED: dict[tuple[str, str], str] = {}


def _shipped_sources() -> list[Path]:
    return sorted(
        path
        for path in _WEB_SRC.rglob("*")
        if path.suffix in {".ts", ".tsx"}
        and ".test." not in path.name
        and "test" not in path.relative_to(_WEB_SRC).parts[:-1]
    )


_LINE_COMMENT = re.compile(r"(?:^|\s)//.*$")


def _code_lines(text: str) -> list[tuple[int, str]]:
    """Each line without its ``//`` comment (not a URL's ``://``); comment lines are skipped."""

    return [
        (number, _LINE_COMMENT.sub("", line))
        for number, line in enumerate(text.splitlines(), 1)
        if not line.lstrip().startswith(("*", "/*", "{/*"))
    ]


def find_rule_breaks(text: str) -> list[tuple[int, str]]:
    """(line, rule) for each rule ``text`` breaks, with the legacy guards' readers too."""

    found = [(number, rule) for number, code in _code_lines(text) for rule, pattern in _RULES.items() if pattern.search(code)]
    found += [(number, "markup sink") for number, _line in find_sinks(text)]
    found += [(number, "setAttribute('style')") for number in find_style_attributes(text)]
    found += [(number, "write to window") for number in find_global_writes(text)]
    return sorted(found)


def _breaks() -> dict[tuple[str, str], list[int]]:
    found: dict[tuple[str, str], list[int]] = {}
    for path in _shipped_sources():
        for number, rule in find_rule_breaks(path.read_text(encoding="utf-8")):
            found.setdefault((path.relative_to(_WEB_SRC).as_posix(), rule), []).append(number)
    return found


def test_web_sources_keep_the_csp_and_trusted_types_rules():
    assert _shipped_sources(), "web/src holds no sources"
    found = {key: lines for key, lines in _breaks().items() if key not in ALLOWED}
    assert found == {}


def test_allowed_rule_breaks_still_exist():
    stale = sorted(set(ALLOWED) - set(_breaks()))
    assert stale == [], "no longer breaks the rule: remove these entries from ALLOWED"


def test_the_reader_finds_each_rule_break():
    source = "\n".join(
        [
            "<div dangerouslySetInnerHTML={{ __html: x }} />",
            "const doc = new DOMParser();",
            "<iframe srcDoc={page} />",
            "<p style={{ color: 'red' }} />",
            "<style>{css}</style>",
            "import Script from 'next/script';",
            "eval(code); const f = new Function('a', 'b');",
            "const bytes = atob(text);",
            "node.innerHTML = markup;",
            "node.setAttribute('style', 'x');",
            "window.helper = helper;",
            "// node.innerHTML = 'a comment';",
            "const ok = element.style; ref.current.style.transform = 'none'; decodeAtob(x);",
        ]
    )

    assert find_rule_breaks(source) == [
        (1, "dangerouslySetInnerHTML"),
        (2, "DOMParser"),
        (3, "srcdoc"),
        (4, "style prop"),
        (5, "<style> or <script> element"),
        (6, "next/script"),
        (7, "eval"),
        (8, "atob"),
        (9, "markup sink"),
        (10, "setAttribute('style')"),
        (11, "write to window"),
    ]


def _logic_exports() -> set[str]:
    names: set[str] = set()
    for module in LOGIC_MODULES:
        text = (_LEGACY_LOGIC / module).read_text(encoding="utf-8")
        names.update(re.findall(r"^export\s+(?:async\s+)?(?:function|const|let|class)\s+([A-Za-z_$][\w$]*)", text, re.M))
    return names


def _logic_sentences() -> set[str]:
    sentences: set[str] = set()
    for module in LOGIC_MODULES:
        text = (_LEGACY_LOGIC / module).read_text(encoding="utf-8")
        for match in re.finditer(r"'((?:[^'\\\n]|\\.){24,})'|\"((?:[^\"\\\n]|\\.){24,})\"", text):
            literal = match.group(1) or match.group(2)
            if " " in literal and "${" not in literal:
                sentences.add(literal.replace("\\'", "'"))
    return sentences


def test_the_logic_modules_are_imported_not_copied():
    names = _logic_exports()
    sentences = _logic_sentences()
    assert {"readIdentityInputs", "determineIdentity", "gatherWebAuthnFacts", "gatherAnalysis"} <= names
    assert "from User-Agent Client Hints" in sentences

    definition = re.compile(r"\b(?:function|const|let|var|class)\s+(" + "|".join(sorted(names)) + r")\b")
    copied = {}
    for path in _shipped_sources():
        text = path.read_text(encoding="utf-8")
        found = sorted({match.group(1) for match in definition.finditer(text)})
        found += sorted(sentence for sentence in sentences if sentence in text)
        if found:
            copied[path.relative_to(_WEB_SRC).as_posix()] = found
    assert copied == {}
