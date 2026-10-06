"""Test files and tests are named for what they test, not for how they were written.

A file or a test named for the pass that produced it -- an "uplift", a "batch", the
"residual" or "remaining" branches, a "coverage" or "focus" round -- says nothing about
the behaviour it checks, and invites the next pass to add another like it. This reads
the name of every file under ``tests/`` and of every ``test_*`` function, split on
``_``, and fails on any of those words. A few phrases use one in its own sense; they
are allowed as phrases, each with where it comes from, and a phrase no name uses any
more fails too.

The web's tests have their own half: every ``*.test.{js,ts,tsx}`` under ``web/src``
and ``web/scripts`` is named for a module beside it, and neither its name (split on
``-``, ``.`` and camelCase) nor any ``describe`` / ``it`` / ``test`` title (split on
anything but letters) holds a process word or says "edge cases". "focus" is a UI
word there (where the keyboard focus goes), so the web half leaves it out. The
titles are read as text, string literals only, so the check runs without Node.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = TESTS_ROOT.parent

PROCESS_WORDS = frozenset(
    {
        "uplift",
        "batch",
        "residual",
        "branch",
        "branches",
        "branchy",
        "focus",
        "coverage",
        "unreferenced",
        "remaining",
        "additional",
        "cover",
        "covers",
    }
)

ALLOWED_PHRASES: dict[tuple[str, ...], str] = {
    ("additional", "information"): "the low five bits of a CBOR head (RFC 8949, section 3)",
    ("report", "to", "batch"): "the Reporting API delivers Report-To reports in batches",
}


def _process_words(name: str) -> list[str]:
    """The process words in ``name`` outside an allowed phrase."""

    words = name.lower().split("_")
    allowed = set()
    for phrase in ALLOWED_PHRASES:
        for start in range(len(words) - len(phrase) + 1):
            if tuple(words[start : start + len(phrase)]) == phrase:
                allowed.update(range(start, start + len(phrase)))
    return [word for index, word in enumerate(words) if word in PROCESS_WORDS and index not in allowed]


def _test_names(tree: ast.AST) -> list[str]:
    return [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test")
    ]


def _names() -> list[tuple[str, str]]:
    """Every file's name and every test's, with where it is."""

    found = []
    for source in sorted(TESTS_ROOT.rglob("*.py")):
        path = source.relative_to(REPO_ROOT).as_posix()
        found.append((path, source.stem))
        for name in _test_names(ast.parse(source.read_text(), filename=path)):
            found.append((f"{path}::{name}", name))
    return found


def test_no_python_file_uses_a_broad_contracts_or_edges_suffix():
    vague = [
        str(source.relative_to(REPO_ROOT))
        for source in sorted(TESTS_ROOT.rglob("*.py"))
        if source.stem.endswith(("_contracts", "_edges"))
    ]
    assert not vague, "Name these files for their module or behavior:\n" + "\n".join(vague)


def test_no_file_or_test_is_named_for_how_it_was_written():
    found = [
        f"{where}: {', '.join(words)}"
        for where, name in _names()
        if (words := _process_words(name))
    ]
    assert not found, "Name these for the behaviour they test:\n" + "\n".join(found)


def test_every_allowed_phrase_is_still_used():
    used = {phrase for phrase in ALLOWED_PHRASES for _where, name in _names() if "_".join(phrase) in name.lower()}
    stale = sorted("_".join(phrase) for phrase in set(ALLOWED_PHRASES) - used)
    assert not stale, f"ALLOWED_PHRASES lists phrases no name uses any more; remove them: {stale}"


def test_the_check_finds_every_process_word_and_spares_the_phrases():
    for word in sorted(PROCESS_WORDS):
        assert _process_words(f"test_decoder_{word}_contracts") == [word]
        assert _process_words(f"test_{word}") == [word]
    assert _process_words("test_attestation_branch_uplift_batch_four") == ["branch", "uplift", "batch"]
    assert _process_words("test_reads_the_additional_information_of_a_head") == []
    assert _process_words("test_additional_information_then_additional_cases") == ["additional"]
    assert _process_words("test_a_report_to_batch_is_logged") == []
    assert _process_words("test_a_large_batch_is_logged") == ["batch"]
    assert _process_words("test_recovers_an_uncovered_discovery") == []


def test_the_check_reads_test_functions_and_methods_only():
    source = (
        "def test_residual_cases(): pass\n"
        "def _coverage_helper(): pass\n"
        "class TestCodec:\n"
        "    def test_branch_cases(self): pass\n"
        "    async def test_focus(self): pass\n"
    )
    assert _test_names(ast.parse(source)) == ["test_residual_cases", "test_branch_cases", "test_focus"]


WEB_ROOTS = (REPO_ROOT / "web" / "src", REPO_ROOT / "web" / "scripts")
WEB_TEST = re.compile(r"\.test\.(js|ts|tsx)$")
WEB_MODULE_EXTENSIONS = (".js", ".ts", ".tsx", ".mjs")
WEB_PROCESS_WORDS = PROCESS_WORDS - {"focus"}
WEB_FORBIDDEN_PHRASES: frozenset[tuple[str, ...]] = frozenset({("edge", "cases")})
WEB_ALLOWED_PHRASES: dict[tuple[str, ...], str] = {
    ("a", "certificate", "covers"): "a certificate's page covers the MDS entry's (EntryPage.test.tsx)",
}
# Test files named for no module beside them. It may only shrink.
WEB_ALLOWED_UNNAMED: frozenset[str] = frozenset()

_WEB_CALL = re.compile(r"\b(?:describe|it|test)(?:\.(?:only|skip|todo|concurrent))?(\.each)?\s*\(")


def _web_test_files() -> list[Path]:
    return sorted(path for root in WEB_ROOTS for path in root.rglob("*") if WEB_TEST.search(path.name))


def _string_at(text: str, index: int) -> str | None:
    """The string literal starting at ``index`` (whitespace first), unescaped; None for anything else."""

    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] not in "'\"`":
        return None
    quote, index, found = text[index], index + 1, []
    while index < len(text):
        if text[index] == "\\":
            found.append(text[index + 1 : index + 2])
            index += 2
            continue
        if text[index] == quote:
            return "".join(found)
        found.append(text[index])
        index += 1
    return None


def _after_parentheses(text: str, index: int) -> int:
    """Where the parenthesis at ``index`` closes (strings and nesting skipped)."""

    depth = 0
    while index < len(text):
        character = text[index]
        if character in "'\"`":
            quote, index = character, index + 1
            while index < len(text) and text[index] != quote:
                index += 2 if text[index] == "\\" else 1
        elif character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return index


def _web_titles(text: str) -> list[str]:
    """Each describe, it and test title written as a string (``it.each(...)('... %s')`` too),
    but a template that interpolates."""

    titles = []
    for call in _WEB_CALL.finditer(text):
        index = call.end()
        if call.group(1):
            index = _after_parentheses(text, call.end() - 1)
            while index < len(text) and text[index].isspace():
                index += 1
            if index >= len(text) or text[index] != "(":
                continue
            index += 1
        title = _string_at(text, index)
        if title is not None and "${" not in title:
            titles.append(title)
    return titles


def _web_words(name: str) -> list[str]:
    """A file name's words: split on ``-`` and ``.`` and between camelCase words."""

    return [word.lower() for word in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", name)]


def _web_problems(words: list[str]) -> list[str]:
    """The process words and forbidden phrases in ``words``, outside an allowed phrase."""

    allowed = set()
    for phrase in WEB_ALLOWED_PHRASES:
        for start in range(len(words) - len(phrase) + 1):
            if tuple(words[start : start + len(phrase)]) == phrase:
                allowed.update(range(start, start + len(phrase)))
    found = [word for index, word in enumerate(words) if word in WEB_PROCESS_WORDS and index not in allowed]
    for phrase in sorted(WEB_FORBIDDEN_PHRASES):
        if any(tuple(words[start : start + len(phrase)]) == phrase for start in range(len(words))):
            found.append(" ".join(phrase))
    return found


def _web_names() -> list[tuple[str, list[str]]]:
    """Every web test file's name and every title in it, as words, with where it is."""

    found = []
    for source in _web_test_files():
        path = source.relative_to(REPO_ROOT).as_posix()
        found.append((path, _web_words(WEB_TEST.sub("", source.name))))
        for title in _web_titles(source.read_text(encoding="utf-8")):
            found.append((f"{path}: {title!r}", re.findall(r"[a-z]+", title.lower())))
    return found


def test_no_web_test_file_or_test_is_named_for_how_it_was_written():
    found = [f"{where}: {', '.join(problems)}" for where, words in _web_names() if (problems := _web_problems(words))]
    assert not found, "Name these for the behaviour they test:\n" + "\n".join(found)


def test_every_web_test_file_is_named_for_a_module_beside_it():
    files = _web_test_files()
    assert len(files) > 100
    unnamed = sorted(
        path.relative_to(REPO_ROOT).as_posix()
        for path in files
        if not any(path.with_name(WEB_TEST.sub(extension, path.name)).exists() for extension in WEB_MODULE_EXTENSIONS)
    )
    assert set(unnamed) <= WEB_ALLOWED_UNNAMED, f"Name these for the module they test: {sorted(set(unnamed) - WEB_ALLOWED_UNNAMED)}"
    assert set(unnamed) == WEB_ALLOWED_UNNAMED, f"WEB_ALLOWED_UNNAMED lists files that are named now; remove them: {sorted(WEB_ALLOWED_UNNAMED - set(unnamed))}"


def test_every_web_allowed_phrase_is_still_used():
    used = {
        phrase
        for phrase in WEB_ALLOWED_PHRASES
        for _where, words in _web_names()
        if any(tuple(words[start : start + len(phrase)]) == phrase for start in range(len(words)))
    }
    stale = sorted(" ".join(phrase) for phrase in set(WEB_ALLOWED_PHRASES) - used)
    assert not stale, f"WEB_ALLOWED_PHRASES lists phrases no title uses any more; remove them: {stale}"


def test_the_web_reader_finds_every_title_written_as_a_string():
    source = (
        "describe('the codec', () => {\n"
        "  it(\"reads a head's \\\"additional\\\" bits\", () => {});\n"
        "  it('says it\\'s fine', () => {});\n"
        "  test.skip(`a template title`, () => {});\n"
        "  it(`a ${kind} title`, () => {});\n"
        "  it.each([['a', (x) => x], ['b', 2]])('cancels on %s', () => {});\n"
        "  describe.each(\n    [1, 2],\n  )(\n    'number %d',\n    () => {},\n  );\n"
        "  it(name, () => {});\n"
        "});\n"
    )
    assert _web_titles(source) == [
        "the codec",
        'reads a head\'s "additional" bits',
        "says it's fine",
        "a template title",
        "cancels on %s",
        "number %d",
    ]


def test_the_web_check_reads_file_names_and_phrases():
    assert _web_words("credential-utils-edge-cases") == ["credential", "utils", "edge", "cases"]
    assert _web_words("AnalyzeBrowserDialog") == ["analyze", "browser", "dialog"]
    assert _web_words("binary.edgeCases") == ["binary", "edge", "cases"]
    assert _web_words("CBORDecoder2") == ["cbor", "decoder", "2"]
    assert _web_problems(["artifacts", "client", "coverage"]) == ["coverage"]
    assert _web_problems(["local", "storage", "edge", "cases"]) == ["edge cases"]
    assert _web_problems(["takes", "focus"]) == []
    assert _web_problems(["while", "a", "certificate", "covers", "the", "entry"]) == []
    assert _web_problems(["the", "test", "covers", "it"]) == ["covers"]
