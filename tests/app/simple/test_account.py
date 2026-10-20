"""Tests for the username a Simple ceremony is for (``routes/simple/account.py``)."""
from __future__ import annotations

import hashlib
import hmac

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


def _handle(app, namespace: str, username: str) -> bytes:
    with app.test_request_context("/"):
        return account.user_handle(namespace, username)


def test_a_user_handle_is_an_hmac_of_the_namespace_and_the_username_under_the_apps_secret(make_app):
    app = make_app({"SECRET_KEY": "secret-0123456789abcdef"})
    expected = hmac.new(
        b"secret-0123456789abcdef", b"simple-user-handle\x00namespace-a\x00alice@example.com", hashlib.sha256
    ).digest()

    assert _handle(app, "namespace-a", "alice@example.com") == expected
    assert len(expected) == 32


def test_another_name_namespace_or_secret_gives_another_user_handle(make_app):
    app = make_app()
    handles = {
        _handle(app, "namespace-a", "alice@example.com"),
        _handle(app, "namespace-a", "bob@example.com"),
        _handle(app, "namespace-b", "alice@example.com"),
        _handle(make_app({"SECRET_KEY": "another-secret-0123456789abcdef"}), "namespace-a", "alice@example.com"),
    }

    assert len(handles) == 4


def test_a_secret_held_as_bytes_keys_the_user_handle_as_its_text_does(make_app):
    as_text = make_app({"SECRET_KEY": "secret-0123456789abcdef"})
    as_bytes = make_app({"SECRET_KEY": b"secret-0123456789abcdef"})

    assert _handle(as_text, "namespace-a", "alice") == _handle(as_bytes, "namespace-a", "alice")
