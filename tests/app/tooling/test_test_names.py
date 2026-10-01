"""Test files and tests are named for what they test, not for how they were written.

A file or a test named for the pass that produced it -- an "uplift", a "batch", the
"residual" or "remaining" branches, a "coverage" or "focus" round -- says nothing about
the behaviour it checks, and invites the next pass to add another like it. This reads
the name of every file under ``tests/`` and of every ``test_*`` function, split on
``_``, and fails on any of those words. A few phrases use one in its own sense; they
are allowed as phrases, each with where it comes from, and a phrase no name uses any
more fails too.
"""
from __future__ import annotations

import ast
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
