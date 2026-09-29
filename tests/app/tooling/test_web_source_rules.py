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

And the logic both UIs share is imported, never copied (docs/UI_MIGRATION.md):
no module in ``web/src`` defines a name the logic modules export, or carries one
of their sentences. The logic modules are ``LOGIC_ROOTS`` (the Analyze Browser's,
the Codec's, the failed-response reader), every module ``web/src`` imports through
``@legacy/``, and everything those import in turn. None of them touches the DOM:
the legacy UI's views stay in their own modules, and the export pre-renders these
in Node.

Each ``ALLOWED`` dict may only shrink; an entry that no longer matches fails.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests.app.tooling.test_html_sinks import find_sinks
from tests.app.tooling.test_inline_code import find_global_writes, find_style_attributes

_ROOT = Path(__file__).resolve().parents[3]
_WEB_SRC = _ROOT / "web" / "src"
_SCRIPTS = _ROOT / "frontend" / "static" / "scripts"

# Paths under frontend/static/scripts. A later surface adds its logic here when it
# splits it out of a view, before web/ imports it.
LOGIC_ROOTS = (
    "shared/browser/identity.js",
    "shared/browser/probe.js",
    "shared/browser/report.js",
    "shared/browser/webauthn-facts.js",
    "shared/api/failed-response.js",
    "decoder/codec/constants.js",
    "decoder/codec/labels.js",
    "decoder/codec/request.js",
    "decoder/codec/result.js",
    "decoder/codec/values.js",
    "decoder/codec/encoding/binary.js",
    "decoder/codec/encoding/can-encode.js",
    "decoder/codec/encoding/format.js",
    "decoder/codec/encoding/summary.js",
    "advanced/mds/constants.js",
    "advanced/mds/metadata/explorer-source.js",
    "advanced/mds/explorer/certificate.js",
    "advanced/mds/explorer/columns.js",
    "advanced/mds/explorer/custom-metadata.js",
    "advanced/mds/explorer/detail.js",
    "advanced/mds/explorer/entry-link.js",
    "advanced/mds/explorer/filter-sort.js",
    "advanced/mds/explorer/loading.js",
    "advanced/mds/explorer/options.js",
    "advanced/mds/explorer/rows.js",
    "advanced/mds/explorer/status.js",
    "advanced/mds/raw-data.js",
    "advanced/mds/raw-stringify.js",
    # The saved credentials' storage.
    "shared/storage/records.js",
    "shared/storage/artifacts-client.js",
    "shared/storage/local/advanced-credentials.js",
    "shared/storage/local/advanced-server-payload.js",
    "shared/storage/local/advanced-snapshot-update.js",
    "shared/storage/local/advanced-storage-shaping.js",
    "shared/storage/local/advanced-sync.js",
    "shared/storage/local/common.js",
    "shared/storage/local/constants.js",
    "shared/storage/local/id-utils.js",
    "shared/storage/local/partition-core.js",
    "shared/storage/local/record-migration.js",
    "shared/storage/local/simple-credentials.js",
    "shared/storage/local/snapshot-sanitize.js",
    "shared/storage/local/storage-core.js",
    # The Simple tab's ceremonies and the result panel's sentences (the WebAuthn
    # ponyfill, the debug printer and the byte helpers are followed from there).
    "simple/ceremony.js",
    "shared/ceremony/result.js",
    "shared/auth/random-username.js",
    # What a saved credential's card shows, deleting and clearing, and the
    # algorithm's names (the credential helpers they use are followed from there).
    "advanced/credentials/saved-list.js",
    "advanced/credentials/delete-flow.js",
    "advanced/credentials/algorithm-tag.js",
    "advanced/credentials/utils.js",
    "advanced/credential-display/attestation-context.js",
    "advanced/cose-labels.js",
    # A saved credential's details and registration view: the registration's
    # state, the decode, the certificate's text, the sanitisers and the saved
    # snapshot's context.
    "advanced/credential-display/decode-payload.js",
    "advanced/credential-display/certificate-text.js",
    "advanced/credential-display/registration-state.js",
    "advanced/credential-display/state.js",
    "advanced/credential-display/sanitize-attestation-object.js",
    "advanced/credential-display/sanitize-common.js",
    "advanced/credential-display/data-utils.js",
    "advanced/credential-display/credential-detail-runtime/snapshot-context.js",
    # What the details and the registration view show, composed, and the
    # artifact's hydration.
    "advanced/credential-display/registration-view.js",
    "advanced/credential-display/credential-detail-runtime/compose.js",
    "advanced/credential-display/credential-detail-runtime/detail-sections.js",
    "advanced/credential-display/credential-detail-runtime/registration-context.js",
    "advanced/credential-display/credential-detail-runtime/registration-candidates.js",
    "advanced/credential-display/credential-detail-runtime/helpers.js",
    "advanced/credentials/hydrate.js",
    # The Advanced tab's form with no page: the hints' rules, the fake credential
    # IDs, the byte fields' check, the JSON editor's key edits, the algorithms.
    "advanced/auth/hint-rules.js",
    "advanced/auth/fake-credentials.js",
    "advanced/auth/hex-input.js",
    "advanced/editor/json-editing.js",
    "advanced/json-editor/algorithm-options.js",
    # The registration's request and the JSON editor with no page: the settings,
    # the request they build and the settings a request says, the editor's
    # sentences and parsing, and the checks an edit passes.
    "advanced/json-editor/registration-request.js",
    "advanced/json-editor/editor-model.js",
    "advanced/json-editor/schema.js",
    "advanced/json-editor/validation-common.js",
    "advanced/json-editor/validation-registration.js",
    "advanced/json-editor/validation-authentication.js",
    # The Advanced tab's registration and authentication ceremonies, and the
    # snapshot a registration's result keeps.
    "advanced/auth/ceremony.js",
    "advanced/auth/assertion.js",
    "advanced/credential-display/registration-snapshot.js",
    # The authentication's request and the form's settings, the Allow Credentials
    # choices, and whether the saved credentials can use largeBlob and prf.
    "advanced/json-editor/authentication-request.js",
    "advanced/auth/allow-credentials.js",
    "advanced/auth/capabilities.js",
    # A form change applied to the request the editor holds.
    "advanced/json-editor/request-patch.js",
)

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


def _web_legacy_imports() -> set[str]:
    return {
        specifier.removeprefix("@legacy/")
        for path in _shipped_sources()
        for specifier in _imports(path.read_text(encoding="utf-8"))
        if specifier.startswith("@legacy/")
    }


def logic_modules() -> list[Path]:
    """LOGIC_ROOTS, what web/src imports through @legacy/, and all they import, as paths."""

    scripts = _SCRIPTS.resolve()
    queue = [scripts / name for name in (*LOGIC_ROOTS, *_web_legacy_imports())]
    seen: set[Path] = set()
    while queue:
        path = queue.pop().resolve()
        if path in seen:
            continue
        assert path.is_relative_to(scripts), f"{path} is outside frontend/static/scripts"
        assert path.is_file(), f"{path.relative_to(scripts)} does not exist"
        seen.add(path)
        queue += [path.parent / spec for spec in _imports(path.read_text(encoding="utf-8")) if spec.startswith(".")]
    return sorted(seen)


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
            touching[path.relative_to(_SCRIPTS.resolve()).as_posix()] = found
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


def test_every_logic_module_is_found():
    found = {path.relative_to(_SCRIPTS.resolve()).as_posix() for path in logic_modules()}
    assert set(LOGIC_ROOTS) <= found
    assert _web_legacy_imports() <= found


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
