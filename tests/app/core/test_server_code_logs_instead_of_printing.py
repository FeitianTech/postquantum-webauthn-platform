"""Server code logs through module loggers; nothing it runs prints to stdout.

stdout bypasses the log handlers, levels and formats ``config/logs.py`` sets
up, and one of the prints wrote parse errors from a caller's registration data
to it unconditionally.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path

from server.app.storage import github_mirror
from server.app.storage.github_outbox import OutboxEntry
from server.app.webauthn.attestation import certificates

SERVER = Path(__file__).resolve().parents[3] / "server"


def test_no_server_module_calls_print():
    calls = []
    for path in sorted(SERVER.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                calls.append(f"{path.relative_to(SERVER)}:{node.lineno}")

    assert calls == []


def _log_entry() -> OutboxEntry:
    return OutboxEntry("registration", "logs/x.json", "add: x.json (AAGUID=unknown)", b"{}")


def test_a_failed_log_delivery_is_a_warning(monkeypatch, caplog, capsys):
    def _fail(_method, _url, _body=None):
        raise OSError("github unreachable")

    monkeypatch.setattr(github_mirror, "_request", _fail)

    with caplog.at_level(logging.INFO, logger=github_mirror.__name__):
        github_mirror.deliver(_log_entry())

    assert capsys.readouterr().out == ""
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    assert "GitHub could not take logs/x.json now; it stays queued: github unreachable" in record.getMessage()


def test_a_delivered_log_is_info(monkeypatch, caplog, capsys):
    monkeypatch.setattr(github_mirror, "_request", lambda _method, _url, _body=None: (201, b"{}"))

    with caplog.at_level(logging.INFO, logger=github_mirror.__name__):
        github_mirror.deliver(_log_entry())

    assert capsys.readouterr().out == ""
    (record,) = caplog.records
    assert record.levelno == logging.INFO
    assert record.getMessage() == "Delivered logs/x.json to the credential log"


def test_unparseable_registration_data_is_logged_at_debug(caplog, capsys):
    with caplog.at_level(logging.DEBUG, logger=certificates.__name__):
        certificates.extract_attestation_details({"response": "not a registration response"})

    assert capsys.readouterr().out == ""
    assert [record.levelno for record in caplog.records] == [logging.DEBUG]
    assert caplog.records[0].getMessage().startswith("Failed to parse registration response for attestation:")
