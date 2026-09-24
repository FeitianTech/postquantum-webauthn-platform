"""Server code logs through module loggers; nothing it runs prints to stdout.

stdout bypasses the log handlers, levels and formats ``config/logs.py`` sets
up, and one of the prints wrote parse errors from a caller's registration data
to it unconditionally.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path

from server.app import device_logs
from server.app.webauthn.attestation import certificates

SERVER = Path(__file__).resolve().parents[3] / "server"


def test_no_server_module_calls_print():
    calls = []
    for path in sorted(SERVER.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                calls.append(f"{path.relative_to(SERVER)}:{node.lineno}")

    assert calls == []


def test_a_failed_log_upload_is_a_warning(monkeypatch, caplog, capsys):
    def _fail(_path, _payload):
        raise OSError("github unreachable")

    monkeypatch.setattr(device_logs, "github_upload_json", _fail)

    with caplog.at_level(logging.INFO, logger=device_logs.__name__):
        device_logs._upload_worker("logs/x.json", {}, {"timestamp": "t", "aaguid": "a"})

    assert capsys.readouterr().out == ""
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    assert "Failed to upload credential log logs/x.json: github unreachable" in record.getMessage()


def test_an_uploaded_log_is_info(monkeypatch, caplog, capsys):
    monkeypatch.setattr(device_logs, "github_upload_json", lambda _path, _payload: None)

    with caplog.at_level(logging.INFO, logger=device_logs.__name__):
        device_logs._upload_worker("logs/x.json", {}, {"timestamp": "t", "aaguid": "a", "device": "d", "action": "create"})

    assert capsys.readouterr().out == ""
    (record,) = caplog.records
    assert record.levelno == logging.INFO
    assert "AAGUID=a device=d action=create" in record.getMessage()


def test_unparseable_registration_data_is_logged_at_debug(caplog, capsys):
    with caplog.at_level(logging.DEBUG, logger=certificates.__name__):
        certificates.extract_attestation_details({"response": "not a registration response"})

    assert capsys.readouterr().out == ""
    assert [record.levelno for record in caplog.records] == [logging.DEBUG]
    assert caplog.records[0].getMessage().startswith("Failed to parse registration response for attestation:")
