"""Tests for the username a Simple ceremony is for (``routes/simple/account.py``)."""
from __future__ import annotations

import pytest

from server.app.routes.simple import account


@pytest.mark.parametrize("value", [None, "", "   "])
def test_a_missing_or_blank_username_is_asked_for(value):
    assert account.read_username(value) == (None, "Please enter a username.")


@pytest.mark.parametrize("value", ["a/b", "a\\b", ".alice", "a..b", "../escape", "a\x00b", "a\tb", "a\x7fb"])
def test_a_name_the_store_refuses_is_refused_with_the_rules(value):
    assert account.read_username(value) == (None, account.USERNAME_RULES)


def test_a_username_is_trimmed_as_the_store_trims_it():
    assert account.read_username("  alice@example.com \n") == ("alice@example.com", None)


def test_a_username_may_be_64_bytes_long_and_no_longer():
    assert account.read_username("a" * 64) == ("a" * 64, None)
    assert account.read_username("a" * 65) == (None, account.USERNAME_RULES)
    # Bytes of UTF-8, not characters: sixteen four-byte characters are 64 bytes.
    assert account.read_username("😀" * 16) == ("😀" * 16, None)
    assert account.read_username("😀" * 16 + "a") == (None, account.USERNAME_RULES)
