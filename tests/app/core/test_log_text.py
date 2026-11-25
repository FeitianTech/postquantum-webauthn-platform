"""Tests for log_text: a client's text as a log line carries it."""

import pytest

from server.app import log_text


@pytest.mark.parametrize(
    "value", ["authenticator.json", "metadata/My_Key-2.json", "example.com", "user@example.com", "/api/mds/metadata/custom/a.json"]
)
def test_a_plain_word_reads_as_sent(value):
    assert log_text.client_text(value) == value


@pytest.mark.parametrize(
    ("value", "written"),
    [
        ("a\nb", "'a\\nb'"),
        ("a\rb", "'a\\rb'"),
        ("\x1b[31mred", "'\\x1b[31mred'"),
        ("a b\x85c", "'a\\u2028b\\x85c'"),
        ("My Key.json", "'My Key.json'"),
        ("it's", '"it\'s"'),
        ("", "''"),
    ],
)
def test_anything_else_is_quoted_with_its_line_breaks_and_escapes_written_out(value, written):
    assert log_text.client_text(value) == written


def test_a_long_value_is_cut_to_the_limit_and_says_how_long_it_was():
    value = "a" * (log_text.LIMIT + 1)

    assert log_text.client_text(value) == f"'{'a' * log_text.LIMIT}'... (201 characters)"
    assert log_text.client_text("b\n" * 40_000).endswith("... (80,000 characters)")
    assert len(log_text.client_text("c" * 65_536)) < 2 * log_text.LIMIT


def test_a_value_that_is_not_text_is_written_as_its_text():
    assert log_text.client_text(None) == "None"
    assert log_text.client_text(7) == "7"
