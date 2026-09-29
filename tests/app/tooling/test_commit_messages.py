"""The commit message check CI runs on every push (tools/commit_messages.py)."""
from __future__ import annotations

import shutil
import subprocess

import pytest

from tools import commit_messages
from tools.commit_messages import problems


@pytest.mark.parametrize(
    "message",
    [
        "Serve the web export at the site root\n",
        "Read a 22-character AAGUID as base64url",
        "x" * 72 + "\n",
        "Name the setting for what it does… and nothing else\n",
        "Docs: say where the snapshot is\n",
    ],
)
def test_one_line_of_at_most_72_characters_passes(message):
    assert problems(message) == []


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("", ["the message is empty"]),
        ("\n", ["the message is empty"]),
        ("   \n", ["the message is empty"]),
        ("x" * 73 + "\n", ["73 characters: at most 72"]),
        ("Subject\n\nA body.\n", ["3 lines: a message is one line"]),
        ("Subject\nSecond line\n", ["2 lines: a message is one line"]),
        ("Subject\n\n", ["2 lines: a message is one line"]),
        (
            "Subject\n\nCo-Authored-By: Someone <someone@example.com>\n",
            ["3 lines: a message is one line", "a trailer (Co-Authored-By): none is allowed"],
        ),
        (
            "y" * 80 + "\n\nSigned-off-by: A <a@example.com>\nchange-id: I1\n",
            [
                "4 lines: a message is one line",
                "80 characters: at most 72",
                "a trailer (Signed-off-by, change-id): none is allowed",
            ],
        ),
    ],
)
def test_what_breaks_the_rule_is_named(message, expected):
    assert problems(message) == expected


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def _commit(repo, message):
    _git(repo, "commit", "--allow-empty", "--no-verify", "-q", "--cleanup=verbatim", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path):
    # Cloud Build's gate runs pytest in python:3.12-slim, which has no git; GitHub's
    # runners, where the check itself runs, have it.
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def test_a_push_of_good_commits_passes(repo, capsys):
    before = _commit(repo, "Start the repository")
    _commit(repo, "Add the first change")
    after = _commit(repo, "Add the second change")

    assert commit_messages.main([before, after], cwd=str(repo)) == 0
    assert "Checked 2 commit message(s): all one line." in capsys.readouterr().out


def test_every_pushed_commit_is_checked_and_a_bad_one_named(repo, capsys):
    before = _commit(repo, "Start the repository")
    bad = _commit(repo, "Add a change\n\nWith a body explaining it.")
    after = _commit(repo, "Add another change")

    assert commit_messages.main([before, after], cwd=str(repo)) == 1
    out = capsys.readouterr().out
    assert f"::error title=Commit message::{bad[:8]} 'Add a change': 3 lines: a message is one line" in out
    assert "Checked 2 commit message(s): 1 problem(s)." in out


@pytest.mark.parametrize("kind", ["new branch", "missing", "force push"])
def test_without_a_usable_earlier_commit_only_the_pushed_one_is_checked(repo, capsys, kind):
    base = _commit(repo, "Start the repository\n\nwith a body the check must not reach")
    replaced = _commit(repo, "Add a change")
    _git(repo, "reset", "-q", "--hard", base)
    after = _commit(repo, "Add the change again")
    before = {"new branch": "0" * 40, "missing": "1" * 40, "force push": replaced}[kind]

    assert commit_messages.main([before, after], cwd=str(repo)) == 0
    out = capsys.readouterr().out
    assert "only the pushed commit is checked" in out
    assert "Checked 1 commit message(s): all one line." in out


def test_the_check_takes_two_commits(capsys):
    assert commit_messages.main(["only-one"]) == 2
    assert "usage: commit_messages.py BEFORE AFTER" in capsys.readouterr().err


def test_a_commit_without_a_message_is_empty(repo):
    commit = _commit(repo, "Start the repository")
    tree = _git(repo, "rev-parse", f"{commit}^{{tree}}")
    empty = subprocess.run(
        ["git", "commit-tree", tree], cwd=repo, input="", check=True, capture_output=True, text=True
    ).stdout.strip()

    assert problems(commit_messages.message_of(empty, cwd=str(repo))) == ["the message is empty"]
