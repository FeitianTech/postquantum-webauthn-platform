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

In every source that ships, the logic modules too, what the platform does itself
is not written by hand: no ``btoa`` (``base64.js`` encodes), no deep copy through
``JSON.parse(JSON.stringify(…))`` (``structuredClone``), no
``hasOwnProperty.call`` (``Object.hasOwn``). And nothing writes to the console:
the page says what happens in words.

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
    "eval": re.compile(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\("),
    "atob": re.compile(r"(?<![\w$.])atob\s*\("),
}

# Modules no source may import, by the rule each breaks. Next's router adds page
# scripts after following a next/link, which the Trusted Types policy reports, and
# it keeps the browser's Back on the app: links are <a>.
_IMPORT_RULES = {"next/script": "next/script", "next/link": "next/link"}

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


_IDENTIFIER = re.compile(r"[\w$]")
# After one of these, a `/` starts a regular expression rather than a division.
_BEFORE_REGEX = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_KEYWORDS = ("return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield", "await")


def _mask(text: str, keep_strings: bool = False) -> str:
    """``text`` with its comments blanked, and the insides of its strings, template
    literals and regular expressions too unless ``keep_strings``: what is left is
    the code. Newlines and every other offset stay where they were, and a template
    literal's ``${…}`` stays code.

    A quote right after a letter or digit is JSX text (``Don't``), not a string."""

    out = list(text)
    length = len(text)

    def blank(start: int, end: int, always: bool = False) -> None:
        if always or not keep_strings:
            for index in range(start, end):
                if out[index] != "\n":
                    out[index] = " "

    def previous_code(index: int) -> str:
        back = index - 1
        while back >= 0 and out[back] in " \t\n":
            back -= 1
        if back < 0:
            return ""
        if _IDENTIFIER.match(out[back]):
            word_end = back + 1
            while back >= 0 and _IDENTIFIER.match(out[back]):
                back -= 1
            return "".join(out[back + 1 : word_end])
        return out[back]

    def scan(index: int, closing: str | None) -> int:
        """Mask from ``index`` to the ``closing`` brace of a template's ``${``
        (or the end); return the index just past it."""

        depth = 0
        while index < length:
            char = text[index]
            if closing and char == "}" and depth == 0:
                return index + 1
            if char in "{([":
                depth += 1
            elif char in "})]":
                depth -= 1
            if text.startswith("//", index):
                end = text.find("\n", index)
                end = length if end == -1 else end
                blank(index, end, always=True)
                index = end
                continue
            if text.startswith("/*", index):
                end = text.find("*/", index + 2)
                end = length if end == -1 else end + 2
                blank(index, end, always=True)
                index = end
                continue
            if char in "'\"" and not (index > 0 and _IDENTIFIER.match(text[index - 1])):
                end = index + 1
                while end < length and text[end] not in (char, "\n"):
                    end += 2 if text[end] == "\\" else 1
                blank(index + 1, min(end, length))
                index = end + 1
                continue
            if char == "`":
                index = template(index + 1)
                continue
            if char == "/" and text[index + 1 : index + 2] not in ("/", "*", ">") and text[index - 1 : index] != "<":
                before = previous_code(index)
                if before == "" or before in _BEFORE_REGEX or before in _REGEX_KEYWORDS:
                    end = index + 1
                    in_class = False
                    while end < length and text[end] != "\n":
                        if text[end] == "\\":
                            end += 2
                            continue
                        if text[end] == "[":
                            in_class = True
                        elif text[end] == "]":
                            in_class = False
                        elif text[end] == "/" and not in_class:
                            break
                        end += 1
                    blank(index + 1, min(end, length))
                    index = end + 1
                    continue
            index += 1
        return index

    def template(index: int) -> int:
        start = index
        while index < length:
            if text[index] == "\\":
                index += 2
                continue
            if text[index] == "`":
                blank(start, index)
                return index + 1
            if text.startswith("${", index):
                blank(start, index)
                index = scan(index + 2, "}")
                start = index
                continue
            index += 1
        blank(start, length)
        return length

    scan(0, None)
    return "".join(out)


def _code_lines(text: str) -> list[tuple[int, str]]:
    """Each line's code: comments, strings, template literals and regular
    expressions blanked."""

    return list(enumerate(_mask(text).splitlines(), 1))


def find_rule_breaks(text: str) -> list[tuple[int, str]]:
    """(line, rule) for each rule ``text`` breaks, with the logic modules' guards' readers too."""

    found = [(number, rule) for number, code in _code_lines(text) for rule, pattern in _RULES.items() if pattern.search(code)]
    found += [(number, _IMPORT_RULES[spec]) for number, spec in _import_lines(text) if spec in _IMPORT_RULES]
    # The guards' readers look for a call with its arguments ("setAttribute('style'"),
    # so they read the code with its strings.
    without_comments = _mask(text, keep_strings=True)
    found += [(number, "markup sink") for number, _line in find_sinks(without_comments)]
    found += [(number, "setAttribute('style')") for number in find_style_attributes(without_comments)]
    found += [(number, "write to window") for number in find_global_writes(without_comments)]
    return sorted(found)


# What the platform now does itself, written by hand: no source that ships, the
# logic modules included, keeps the old spelling.
_NATIVE_RULES: dict[str, re.Pattern[str]] = {
    "btoa (encode with shared/utils/base64.js)": re.compile(r"(?<![\w$.])btoa\s*\("),
    "JSON deep copy (structuredClone)": re.compile(r"\bJSON\.parse\(\s*JSON\.stringify\("),
    "hasOwnProperty.call (Object.hasOwn)": re.compile(r"\bhasOwnProperty\.call\("),
}


def find_native_rule_breaks(text: str) -> list[tuple[int, str]]:
    """(line, rule) for each hand-written stand-in for a platform feature in ``text``'s code."""

    return [(number, rule) for number, code in _code_lines(text) for rule, pattern in _NATIVE_RULES.items() if pattern.search(code)]


def test_shipped_sources_use_what_the_platform_offers():
    found: dict[str, list[tuple[int, str]]] = {}
    for path in [*_shipped_sources(), *_logic_files()]:
        for number, rule in find_native_rule_breaks(path.read_text(encoding="utf-8")):
            found.setdefault(path.relative_to(_WEB_SRC).as_posix(), []).append((number, rule))
    assert found == {}


def test_the_reader_finds_each_hand_written_stand_in():
    source = "\n".join(
        [
            "const text = btoa(String.fromCharCode(...bytes));",
            "const copy = JSON.parse(JSON.stringify(record));",
            "if (Object.prototype.hasOwnProperty.call(map, key)) {}",
            "// btoa(x); JSON.parse(JSON.stringify(y)); a comment",
            "const ok = structuredClone(record) && Object.hasOwn(map, key) && toBtoa(x);",
        ]
    )

    assert find_native_rule_breaks(source) == [
        (1, "btoa (encode with shared/utils/base64.js)"),
        (2, "JSON deep copy (structuredClone)"),
        (3, "hasOwnProperty.call (Object.hasOwn)"),
    ]


# The page says what happens in words; nothing ships that writes to the console.
_CONSOLE = re.compile(r"(?<![\w$.])console\s*\.")


def find_console_writes(text: str) -> list[int]:
    """The lines of ``text`` whose code writes to the console."""

    return [number for number, code in _code_lines(text) if _CONSOLE.search(code)]


def test_shipped_sources_write_nothing_to_the_console():
    found = {
        path.relative_to(_WEB_SRC).as_posix(): lines
        for path in [*_shipped_sources(), *_logic_files()]
        if (lines := find_console_writes(path.read_text(encoding="utf-8")))
    }
    assert found == {}, "say it on the page, or nothing"


def test_the_reader_finds_console_writes_in_code_only():
    source = "console.log(value);\n// console.warn('a comment');\nconst text = 'console.error';\nmyconsole.log(x);\n"

    assert find_console_writes(source) == [1]


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


# `import ... from '...'`, `export ... from '...'` (across lines), `import '...'`
# and `import('...')`.
_IMPORT = re.compile(
    r"""^\s*(?:import|export)\b[^;'"`]*?\bfrom\s*['"]([^'"]+)['"]|^\s*import\s*['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.M,
)
_DOM = re.compile(r"\bdocument\b|\brequestAnimationFrame\b|\bcreateElement\b|\bHTMLElement\b")


def _without_comments(text: str) -> str:
    return _mask(text, keep_strings=True)


def _import_lines(text: str) -> list[tuple[int, str]]:
    code = _without_comments(text)
    return [
        (code.count("\n", 0, match.start()) + 1, match.group(1) or match.group(2) or match.group(3))
        for match in _IMPORT.finditer(code)
    ]


def _imports(text: str) -> list[str]:
    return [spec for _number, spec in _import_lines(text)]


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


def _copies(text: str, names: set[str], sentences: set[str]) -> list[str]:
    """The logic exports ``text`` defines and the logic sentences it carries."""

    found = []
    if names:
        definition = re.compile(r"\b(?:function|const|let|var|class)\s+(" + "|".join(sorted(names)) + r")\b")
        code = _mask(text)
        # Only a module-level definition is a copy: a local that happens to share an
        # export's name (``const state`` inside a function) is not.
        found += sorted(
            {
                match.group(1)
                for match in definition.finditer(code)
                if code.count("{", 0, match.start()) == code.count("}", 0, match.start())
            }
        )
    # A sentence counts in the code's strings and JSX text, not in a comment.
    code = _without_comments(text)
    found += sorted(sentence for sentence in sentences if sentence in code)
    return found


def test_only_a_module_level_definition_is_a_copy():
    names = {"state", "formatKey"}

    assert _copies("const state = {};\nexport function formatKey(key) {}\n", names, set()) == ["formatKey", "state"]
    assert _copies("function view() {\n  const state = useState();\n}\n", names, set()) == []
    assert _copies("const View = () => {\n  let formatKey = (k) => k;\n  return <p>{formatKey('a')}</p>;\n};\n", names, set()) == []
    assert _copies("const note = '{';\nconst state = 1;\n", names, set()) == ["state"]


def test_the_logic_modules_touch_no_dom():
    touching = {}
    for path in logic_modules():
        text = path.read_text(encoding="utf-8")
        found = sorted({match.group(0) for match in _DOM.finditer(_mask(text))})
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
    assert _imports("const lazy = import('./four.js');") == ["./four.js"]
    kept = _without_comments("const a = 1; // note\n/* gone */const b = 'https://x';")
    assert kept.split() == ["const", "a", "=", "1;", "const", "b", "=", "'https://x';"]
    assert kept.count("\n") == 1


def test_the_reader_reads_code_not_comments_or_strings():
    source = "\n".join(
        [
            "const text = 'eval(x), atob(y) and <script>';",
            "// window.helper = helper; eval(code);",
            "/* <style>{css}</style>",
            "   style={{ color: 'red' }} */",
            "const url = 'https://example.com'; eval(code);",
            "const pattern = /['\"]<script/g;",
            "const tpl = `atob(${atob(x)})`;",
            "const named = 'next/script';",
            "import Script from 'next/script';",
            "const nested = `a ${`b ${eval(c)}`}`;",
            "<p>Don't worry</p>; <br />; <Foo bar={x} />; const ratio = a / b / 2;",
        ]
    )

    assert find_rule_breaks(source) == [(5, "eval"), (7, "atob"), (9, "next/script"), (10, "eval")]


def test_a_block_comment_opened_inside_a_line_comment_hides_nothing():
    text = "// the leaves under explorer/*.js\nimport { a } from './a.js';\n"

    assert _imports(text) == ["./a.js"]
    assert _code_lines(text)[1] == (2, "import { a } from '      ';")


def test_a_logic_sentence_counts_as_a_copy_in_code_not_in_a_comment():
    sentences = {"No authenticators match the selected filters."}

    assert _copies("// No authenticators match the selected filters.\n", set(), sentences) == []
    assert _copies("/* No authenticators match the selected filters. */", set(), sentences) == []
    assert _copies("const empty = 'No authenticators match the selected filters.';", set(), sentences) == [
        "No authenticators match the selected filters."
    ]
    assert _copies("<p>No authenticators match the selected filters.</p>", set(), sentences) == [
        "No authenticators match the selected filters."
    ]


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

    copied = {}
    for path in _shipped_sources():
        found = _copies(path.read_text(encoding="utf-8"), names, sentences)
        if found:
            copied[path.relative_to(_WEB_SRC).as_posix()] = found
    assert copied == {}
