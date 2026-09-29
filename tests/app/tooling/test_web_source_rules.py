"""The UI's sources in ``web/src`` keep the CSP's rules, and keep one copy of the logic.

What ships from ``web/src`` (everything but its tests) is held to what the strict
CSP and the Trusted Types report-only policy need, with the logic modules' guards'
own readers (``test_html_sinks.py``, ``test_inline_code.py``):

- no markup sink (``innerHTML``, ``document.write``, ...) and no
  ``dangerouslySetInnerHTML``, ``DOMParser`` or ``srcdoc``: React builds the DOM;
- no ``style=`` prop: the static export would render it as a ``style`` attribute,
  which the policy refuses (a component that must place something at run time
  sets ``element.style`` through a ref, as the CSSOM is allowed), no
  ``setAttribute('style')``, and no ``<style>`` or ``<script>`` element;
- no ``next/script``, no ``eval`` or ``new Function`` (no ``'unsafe-eval'``);
- nothing written to ``window`` / ``globalThis`` / ``self``, and no ``atob``
  (``shared/utils/base64.js`` decodes strictly).

And the logic is imported, never copied: no module in ``web/src`` defines a name
the logic modules export, or carries one of their sentences. The logic modules
are the ``.js`` files under ``web/src/logic`` (their tests aside), which import
only each other; web/'s components reach them as ``@/logic/…``. None of them
touches the DOM: the export pre-renders them in Node.

Each ``ALLOWED`` dict may only shrink; an entry that no longer matches fails.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests.app.tooling.test_html_sinks import LOGIC_ROOT, find_sinks
from tests.app.tooling.test_html_sinks import logic_modules as _logic_files
from tests.app.tooling.test_inline_code import find_global_writes, find_style_attributes

_ROOT = Path(__file__).resolve().parents[3]
_WEB_SRC = _ROOT / "web" / "src"
_LOGIC_ALIAS = "@/logic/"

_RULES: dict[str, re.Pattern[str]] = {
    "dangerouslySetInnerHTML": re.compile(r"\bdangerouslySetInnerHTML\b"),
    "DOMParser": re.compile(r"\bDOMParser\b"),
    "srcdoc": re.compile(r"\bsrcDoc\b|\bsrcdoc\b"),
    "style prop": re.compile(r"(?<=\s)style=\{"),
    "<style> or <script> element": re.compile(r"<(?:style|script)\b"),
    "next/script": re.compile(r"""['"]next/script['"]"""),
    # Next's router adds page scripts after following a next/link, which the
    # Trusted Types policy reports, and it keeps the browser's Back on the app: links are <a>.
    "next/link": re.compile(r"""['"]next/link['"]"""),
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
    """(line, rule) for each rule ``text`` breaks, with the logic modules' guards' readers too."""

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
            "import Link from \"next/link\";",
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
        (7, "next/link"),
        (8, "eval"),
        (9, "atob"),
        (10, "markup sink"),
        (11, "setAttribute('style')"),
        (12, "write to window"),
    ]


_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
# `import ... from '...'`, `export ... from '...'` (across lines) and `import '...'`.
_IMPORT = re.compile(r"""^\s*(?:import|export)\b[^;'"`]*?\bfrom\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]""", re.M)
_DOM = re.compile(r"\bdocument\b|\brequestAnimationFrame\b|\bcreateElement\b|\bHTMLElement\b")


def _without_comments(text: str) -> str:
    return "\n".join(code for _number, code in _code_lines(_BLOCK_COMMENT.sub("", text)))


def _imports(text: str) -> list[str]:
    return [match.group(1) or match.group(2) for match in _IMPORT.finditer(_without_comments(text))]


def _web_logic_imports() -> set[str]:
    return {
        specifier.removeprefix(_LOGIC_ALIAS)
        for path in _shipped_sources()
        for specifier in _imports(path.read_text(encoding="utf-8"))
        if specifier.startswith(_LOGIC_ALIAS)
    }


def logic_modules() -> list[Path]:
    """The logic modules, each checked to import only modules of the tree that exist."""

    modules = [path.resolve() for path in _logic_files()]
    root = LOGIC_ROOT.resolve()
    for path in modules:
        for spec in _imports(path.read_text(encoding="utf-8")):
            assert spec.startswith("."), f"{path.relative_to(root)} imports {spec}, outside the logic"
            target = (path.parent / spec).resolve()
            assert target.is_relative_to(root), f"{path.relative_to(root)} imports {spec}, outside the logic"
            assert target.is_file(), f"{path.relative_to(root)} imports {spec}, which does not exist"
    return modules


def _logic_exports() -> set[str]:
    names: set[str] = set()
    for path in logic_modules():
        text = _without_comments(path.read_text(encoding="utf-8"))
        names.update(re.findall(r"^export\s+(?:async\s+)?(?:function\*?|const|let|class)\s+([A-Za-z_$][\w$]*)", text, re.M))
        for listed in re.findall(r"^export\s*\{([^}]*)\}", text, re.M):
            for item in listed.split(","):
                name = item.split(" as ")[-1].strip()
                if name and name != "default":
                    names.add(name)
    return names


def _logic_sentences() -> set[str]:
    sentences: set[str] = set()
    for path in logic_modules():
        text = _without_comments(path.read_text(encoding="utf-8"))
        for match in re.finditer(r"'((?:[^'\\\n]|\\.){24,})'|\"((?:[^\"\\\n]|\\.){24,})\"|`((?:[^`\\\n]|\\.){24,})`", text):
            literal = match.group(1) or match.group(2) or match.group(3)
            if " " in literal and "${" not in literal:
                sentences.add(literal.replace("\\'", "'"))
    return sentences


def test_the_logic_modules_touch_no_dom():
    touching = {}
    for path in logic_modules():
        text = _without_comments(path.read_text(encoding="utf-8"))
        found = sorted({match.group(0) for match in _DOM.finditer(text)})
        found += sorted(spec for spec in _imports(text) if "/ui/" in spec or spec.startswith("../ui/"))
        if found:
            touching[path.relative_to(LOGIC_ROOT.resolve()).as_posix()] = found
    assert touching == {}


def test_the_reader_follows_imports_and_reads_every_export():
    text = "\n".join(
        [
            "import {",
            "    a,",
            "    b,",
            "} from './one.js';",
            "import './two.js';",
            "export { c } from './three.js';",
            "// import { d } from './comment.js';",
            "/* import { e } from './block.js'; */",
        ]
    )
    assert _imports(text) == ["./one.js", "./two.js", "./three.js"]
    assert _without_comments("const a = 1; // note\n/* gone */const b = 'https://x';") == "const a = 1;\nconst b = 'https://x';"


def test_every_logic_module_web_imports_is_found():
    found = {path.relative_to(LOGIC_ROOT.resolve()).as_posix() for path in logic_modules()}
    assert len(found) > 90
    assert _web_logic_imports()
    assert _web_logic_imports() <= found


def test_the_logic_modules_are_imported_not_copied():
    names = _logic_exports()
    sentences = _logic_sentences()
    assert {"readIdentityInputs", "determineIdentity", "gatherWebAuthnFacts", "gatherAnalysis"} <= names
    assert {"formatKey", "describeCodecResult", "classifyCodecValue", "requestCodec", "readFailedResponse"} <= names
    assert "from User-Agent Client Hints" in sentences
    assert "Decoded in lenient mode (best effort); skipped items are listed below." in sentences
    assert "Attestation statement (interpreted)" in sentences
    assert {"matchesExplorerFilters", "requestExplorerSnapshot", "buildLoadedStatus", "describeUploadAnswer"} <= names
    assert "No authenticators match the selected filters." in sentences
    assert "Packaged FIDO metadata is available. Explorer data is loading in the background." in sentences

    definition = re.compile(r"\b(?:function|const|let|var|class)\s+(" + "|".join(sorted(names)) + r")\b")
    copied = {}
    for path in _shipped_sources():
        text = path.read_text(encoding="utf-8")
        found = sorted({match.group(1) for match in definition.finditer(text)})
        found += sorted(sentence for sentence in sentences if sentence in text)
        if found:
            copied[path.relative_to(_WEB_SRC).as_posix()] = found
    assert copied == {}
