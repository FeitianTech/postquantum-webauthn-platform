#!/usr/bin/env python3
"""Check commit messages against the repository's rule for them.

A message is one line of at most 72 characters, with no trailers (AGENTS.md,
"Commits"; what it says of the words is for people, not this check).

usage: commit_messages.py BEFORE AFTER

Checks the commits a push added: ``BEFORE..AFTER``, or ``AFTER`` alone when
``BEFORE`` is all zeros, is not in the clone, or is not an ancestor of ``AFTER``
(a new branch, a force push). Exits 1 naming each commit whose message breaks the
rule.
"""

from __future__ import annotations

import re
import subprocess
import sys

MAX_LENGTH = 72

# Git's trailer keys people and tools add; any of them on a line of its own.
_TRAILER = re.compile(
    r"^(?:co-authored-by|signed-off-by|reviewed-by|acked-by|tested-by|reported-by|"
    r"suggested-by|helped-by|change-id|cc)\s*:",
    re.IGNORECASE,
)


def problems(message: str) -> list[str]:
    """What is wrong with ``message``, the text git stores (one trailing newline)."""

    text = message[:-1] if message.endswith("\n") else message
    if not text.strip():
        return ["the message is empty"]
    lines = text.split("\n")
    found = []
    if len(lines) > 1:
        found.append(f"{len(lines)} lines: a message is one line")
    if len(lines[0]) > MAX_LENGTH:
        found.append(f"{len(lines[0])} characters: at most {MAX_LENGTH}")
    trailers = [line.split(":", 1)[0] for line in lines if _TRAILER.match(line)]
    if trailers:
        found.append(f"a trailer ({', '.join(trailers)}): none is allowed")
    return found


def _git(*args: str, cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")


def pushed_commits(before: str, after: str, cwd: str | None = None) -> tuple[list[str], str | None]:
    """The commits a push from ``before`` to ``after`` added, oldest first, and a
    note when only ``after`` could be checked."""

    if set(before) == {"0"}:
        return [after], "no earlier commit (a new branch): only the pushed commit is checked"
    if _git("cat-file", "-e", f"{before}^{{commit}}", cwd=cwd).returncode != 0:
        return [after], f"{before} is not in the clone: only the pushed commit is checked"
    if _git("merge-base", "--is-ancestor", before, after, cwd=cwd).returncode != 0:
        return [after], f"{before} is not an ancestor (a force push): only the pushed commit is checked"
    listed = _git("rev-list", "--reverse", f"{before}..{after}", cwd=cwd)
    listed.check_returncode()
    return listed.stdout.split(), None


def message_of(commit: str, cwd: str | None = None) -> str:
    """The message exactly as git stores it."""

    raw = _git("cat-file", "commit", commit, cwd=cwd)
    raw.check_returncode()
    return raw.stdout.partition("\n\n")[2]


def main(argv: list[str], cwd: str | None = None) -> int:
    if len(argv) != 2:
        print("usage: commit_messages.py BEFORE AFTER", file=sys.stderr)
        return 2
    commits, note = pushed_commits(*argv, cwd=cwd)
    if note:
        print(note)
    failed = 0
    for commit in commits:
        message = message_of(commit, cwd=cwd)
        subject = message.split("\n", 1)[0]
        for problem in problems(message):
            print(f"::error title=Commit message::{commit[:8]} {subject!r}: {problem}")
            failed += 1
    print(f"Checked {len(commits)} commit message(s): {'all one line' if not failed else f'{failed} problem(s)'}.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
