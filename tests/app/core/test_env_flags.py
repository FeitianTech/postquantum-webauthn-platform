"""Every boolean setting is read by the one parser, ``server.app.env_flags``.

``ENABLE_GITHUB_LOGGING=enabled`` used to read False while
``FIDO_SERVER_GCS_ENABLED=enabled`` read True: three parsers, three rules.
"""
from __future__ import annotations

import logging

import pytest

from server.app import device_logs, env_flags, github_client
from server.app.storage import cloud

_FLAGS = ("FIDO_SERVER_GCS_ENABLED", "ENABLE_GITHUB_LOGGING", "GITHUB_LOG_ASYNC")


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setattr(env_flags, "_warned", set())
    monkeypatch.delenv("K_SERVICE", raising=False)
    for name in _FLAGS:
        monkeypatch.delenv(name, raising=False)


def _readings() -> tuple[bool, bool, bool]:
    return cloud.gcs_enabled(), github_client.is_logging_enabled(), device_logs._should_upload_async()


@pytest.mark.parametrize("value", ["1", "true", "YES", " on "])
def test_every_flag_reads_the_same_true_spellings(monkeypatch, value):
    for name in _FLAGS:
        monkeypatch.setenv(name, value)

    assert [env_flags.parse_env_flag(name) for name in _FLAGS] == [True, True, True]
    assert _readings() == (True, True, True)


@pytest.mark.parametrize("value", ["0", "false", "No", " off ", ""])
def test_every_flag_reads_the_same_false_spellings(monkeypatch, value):
    for name in _FLAGS:
        monkeypatch.setenv(name, value)

    assert [env_flags.parse_env_flag(name) for name in _FLAGS] == [False, False, False]
    assert _readings() == (False, False, False)


def test_an_unknown_value_is_no_setting_and_is_warned_about_once(monkeypatch, caplog):
    for name in _FLAGS:
        monkeypatch.setenv(name, "enabled")

    with caplog.at_level(logging.WARNING, logger="server.app.env_flags"):
        assert [env_flags.parse_env_flag(name) for name in _FLAGS] == [None, None, None]
        # Each flag keeps its default: GCS off, GitHub logging on, uploads in the background.
        assert _readings() == (False, True, True)
        assert _readings() == (False, True, True)

    warnings = [record.getMessage() for record in caplog.records if record.name == "server.app.env_flags"]
    assert len(warnings) == len(_FLAGS)
    assert all("'enabled'" in warning for warning in warnings)


def test_an_unset_flag_is_no_setting():
    assert [env_flags.parse_env_flag(name) for name in _FLAGS] == [None, None, None]
