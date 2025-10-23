import importlib
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple

from unittest.mock import patch

import pytest


os.environ.setdefault("REGISTRATION_LOG_EMAIL_ENABLED", "0")

device_logs = importlib.import_module("server.server.device_logs")


def _fake_email_recorder(container: List[Tuple[str, str]]):
    def _deliver_email(self, subject: str, body: str) -> bool:
        container.append((subject, body))
        return True

    return _deliver_email


def _base_env(tmp_path: Path) -> dict:
    return {
        "REGISTRATION_LOG_DIRECTORY": str(tmp_path),
        "REGISTRATION_LOG_GMAIL_ADDRESS": "test@example.com",
        "REGISTRATION_LOG_GMAIL_CLIENT_ID": "client-id",
        "REGISTRATION_LOG_GMAIL_CLIENT_SECRET": "client-secret",
        "REGISTRATION_LOG_GMAIL_REFRESH_TOKEN": "refresh-token",
        "REGISTRATION_LOG_EMAIL_RETRY_ATTEMPTS": "1",
        "REGISTRATION_LOG_EMAIL_ENABLED": "1",
    }


def _beijing_time(year: int, month: int, day: int, hour: int = 9) -> datetime:
    return datetime(year, month, day, hour, 0, 0, tzinfo=device_logs.BEIJING_TZ)


@pytest.fixture(autouse=True)
def cleanup_manager_state():
    # Ensure the global manager created at import time does not interfere with tests.
    original_manager = device_logs._MANAGER
    yield
    device_logs._MANAGER = original_manager


def test_startup_sends_single_verification_email(tmp_path):
    sent: List[Tuple[str, str]] = []
    env = _base_env(tmp_path)
    now = _beijing_time(2024, 1, 2)

    with patch.dict(os.environ, env, clear=True):
        with patch.object(
            device_logs.RegistrationLogManager,
            "_deliver_email",
            _fake_email_recorder(sent),
        ), patch.object(
            device_logs.RegistrationLogManager, "_current_time", return_value=now
        ):
            device_logs.RegistrationLogManager()

    assert len(sent) == 1
    assert "verification" in sent[0][0].lower()

    sent.clear()
    later = now + timedelta(minutes=30)
    with patch.dict(os.environ, env, clear=True):
        with patch.object(
            device_logs.RegistrationLogManager,
            "_deliver_email",
            _fake_email_recorder(sent),
        ), patch.object(
            device_logs.RegistrationLogManager, "_current_time", return_value=later
        ):
            device_logs.RegistrationLogManager()

    assert sent == []


def test_daily_report_respects_one_per_day_and_clears_logs(tmp_path):
    sent: List[Tuple[str, str]] = []
    env = _base_env(tmp_path)

    log_path = Path(tmp_path) / device_logs.LOG_FILENAME
    log_path.write_text("2024-01-01 09:00:00 (CST) | aaguid | device\n", encoding="utf-8")

    day_one = _beijing_time(2024, 1, 1)
    with patch.dict(os.environ, env, clear=True):
        with patch.object(
            device_logs.RegistrationLogManager,
            "_deliver_email",
            _fake_email_recorder(sent),
        ), patch.object(
            device_logs.RegistrationLogManager, "_current_time", return_value=day_one
        ):
            device_logs.RegistrationLogManager()

    assert len(sent) == 1
    assert "verification" in sent[0][0].lower()
    assert log_path.read_text(encoding="utf-8") == ""

    sent.clear()
    log_path.write_text(
        "2024-01-02 09:10:00 (CST) | aaguid | other\n", encoding="utf-8"
    )

    day_two = _beijing_time(2024, 1, 2)
    with patch.dict(os.environ, env, clear=True):
        with patch.object(
            device_logs.RegistrationLogManager,
            "_deliver_email",
            _fake_email_recorder(sent),
        ), patch.object(
            device_logs.RegistrationLogManager, "_current_time", return_value=day_two
        ):
            device_logs.RegistrationLogManager()

    assert len(sent) == 1
    assert "beijing time" in sent[0][0].lower()
    assert log_path.read_text(encoding="utf-8") == ""

    sent.clear()
    log_path.write_text(
        "2024-01-02 10:00:00 (CST) | aaguid | later\n", encoding="utf-8"
    )

    later_same_day = day_two + timedelta(hours=2)
    with patch.dict(os.environ, env, clear=True):
        with patch.object(
            device_logs.RegistrationLogManager,
            "_deliver_email",
            _fake_email_recorder(sent),
        ), patch.object(
            device_logs.RegistrationLogManager,
            "_current_time",
            return_value=later_same_day,
        ):
            device_logs.RegistrationLogManager()

    assert sent == []
    # Log contents remain because no email was sent.
    assert "later" in log_path.read_text(encoding="utf-8")
