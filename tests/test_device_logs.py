import sys
import types
import uuid
from datetime import datetime, timezone
from pathlib import Path

import cbor2
import pytest

_ROOT = Path(__file__).resolve().parents[1]

server_pkg = types.ModuleType("server")
server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", server_pkg)

server_server_pkg = types.ModuleType("server.server")
server_server_pkg.__path__ = [str(_ROOT / "server" / "server")]
sys.modules.setdefault("server.server", server_server_pkg)

from server.server import device_logs


class ImmediateThread:
    def __init__(self, target, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


def test_record_registration_event_uploads_json(monkeypatch, capsys):
    uploads = []

    def fake_upload(path, payload, **kwargs):
        uploads.append((path, payload, kwargs))

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setattr(device_logs, "github_upload_json", fake_upload)
    monkeypatch.setattr(device_logs.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(device_logs, "random_shortid", lambda length=8: "abcdef12")

    attestation_object = cbor2.dumps({"test": b"value"})
    client_data_json = b'{"type":"webauthn.create"}'
    event = device_logs.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        rp_id="example.com",
        user_id=b"user-id",
        user_name="alice",
        user_display_name="Alice",
        credential_id=b"credential-id",
        public_key_cose={1: -7, -2: b"\x01\x02"},
        sign_count=5,
        transports=["usb", "ble"],
        aaguid=uuid.UUID("7701a390-8b53-4ce0-bf7c-b331569b8d1a").bytes,
        device_name_mds="Example Authenticator",
        attestation_format="packed",
        attestation_object=attestation_object,
        client_data_json=client_data_json,
        signature_valid=True,
        root_valid=True,
        rp_id_hash_valid=True,
        aaguid_match=True,
    )

    device_logs.record_registration_event(event)

    out = capsys.readouterr().out.strip()
    assert "Uploaded credential log" in out
    assert "AAGUID=7701a390-8b53-4ce0-bf7c-b331569b8d1a" in out

    assert len(uploads) == 1
    path, payload, kwargs = uploads[0]

    assert path == (
        "logs/7701a390-8b53-4ce0-bf7c-b331569b8d1a/20251023T094110Z_abcdef12.json"
    )

    assert kwargs == {}

    assert payload["timestamp"] == "2025-10-23T17:41:10+08:00"
    assert payload["rp_id"] == "example.com"
    assert payload["aaguid"] == "7701a390-8b53-4ce0-bf7c-b331569b8d1a"
    assert payload["device_name_mds"] == "Example Authenticator"
    assert payload["raw_attestation_object"] == device_logs.to_b64url(attestation_object)
    assert payload["decoded_attestation_object"] == {"test": device_logs.to_b64url(b"value")}
    # Verify attestation check fields are included
    assert payload["signature_valid"] is True
    assert payload["root_valid"] is True
    assert payload["rp_id_hash_valid"] is True
    assert payload["aaguid_match"] is True


def test_record_registration_event_creates_unique_files(monkeypatch, capsys):
    uploads = []

    def fake_upload(path, payload, **kwargs):
        uploads.append((path, payload, kwargs))

    short_ids = iter(["firstid", "secondid"])

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setattr(device_logs, "github_upload_json", fake_upload)
    monkeypatch.setattr(device_logs.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(device_logs, "random_shortid", lambda length=8: next(short_ids))

    attestation_object = cbor2.dumps({"another": "value"})

    base_event_kwargs = dict(
        rp_id="example.com",
        user_id=b"user-id",
        user_name="alice",
        user_display_name="Alice",
        credential_id=b"credential-id",
        public_key_cose={1: -7},
        sign_count=0,
        transports=None,
        aaguid=uuid.UUID("7701a390-8b53-4ce0-bf7c-b331569b8d1a").bytes,
        device_name_mds="Example Authenticator",
        attestation_format="packed",
        attestation_object=attestation_object,
        client_data_json=b"{}",
    )

    event1 = device_logs.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        **base_event_kwargs,
    )
    event2 = device_logs.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 45, 10, tzinfo=timezone.utc),
        **base_event_kwargs,
    )

    device_logs.record_registration_event(event1)
    device_logs.record_registration_event(event2)

    out_lines = [line.strip() for line in capsys.readouterr().out.strip().splitlines() if line.strip()]
    assert len(out_lines) == 2
    for line in out_lines:
        assert "Uploaded credential log" in line
        assert "action=create" in line

    assert len(uploads) == 2
    paths = [entry[0] for entry in uploads]
    assert paths[0] == "logs/7701a390-8b53-4ce0-bf7c-b331569b8d1a/20251023T094110Z_firstid.json"
    assert paths[1] == "logs/7701a390-8b53-4ce0-bf7c-b331569b8d1a/20251023T094510Z_secondid.json"

    for _path, payload, kwargs in uploads:
        assert kwargs == {}


def test_record_registration_event_disabled(monkeypatch):
    monkeypatch.delenv("ENABLE_GITHUB_LOGGING", raising=False)

    def disabled_logging():
        return False

    monkeypatch.setattr(device_logs, "is_logging_enabled", disabled_logging)

    def fail_upload(*_args, **_kwargs):
        raise AssertionError("github_upload_json should not be called when logging is disabled")

    monkeypatch.setattr(device_logs, "github_upload_json", fail_upload)

    event = device_logs.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        rp_id="example.com",
        user_id=b"user-id",
        user_name="alice",
        user_display_name="Alice",
        credential_id=b"credential-id",
        public_key_cose={1: -7},
        sign_count=0,
        transports=None,
        aaguid=None,
        device_name_mds=None,
        attestation_format="packed",
        attestation_object=cbor2.dumps({}),
        client_data_json=b"{}",
    )

    device_logs.record_registration_event(event)


def test_record_registration_event_uploads_inline_on_cloud_run(monkeypatch, capsys):
    uploads = []

    def fake_upload(path, payload, **kwargs):
        uploads.append((path, payload, kwargs))

    def fail_thread(*_args, **_kwargs):
        raise AssertionError("Threaded upload should not be used on Cloud Run by default")

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setenv("K_SERVICE", "pqc-webauthn")
    monkeypatch.delenv("GITHUB_LOG_ASYNC", raising=False)
    monkeypatch.setattr(device_logs, "github_upload_json", fake_upload)
    monkeypatch.setattr(device_logs.threading, "Thread", fail_thread)
    monkeypatch.setattr(device_logs, "random_shortid", lambda length=8: "inline01")

    event = device_logs.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        rp_id="example.com",
        user_id=b"user-id",
        user_name="alice",
        user_display_name="Alice",
        credential_id=b"credential-id",
        public_key_cose={1: -7},
        sign_count=0,
        transports=None,
        aaguid=uuid.UUID("7701a390-8b53-4ce0-bf7c-b331569b8d1a").bytes,
        device_name_mds="Example Authenticator",
        attestation_format="packed",
        attestation_object=cbor2.dumps({}),
        client_data_json=b"{}",
    )

    device_logs.record_registration_event(event)

    out = capsys.readouterr().out.strip()
    assert "Uploaded credential log" in out
    assert len(uploads) == 1
    assert uploads[0][0].endswith("_inline01.json")


@pytest.mark.parametrize(
    "payload",
    [b"not-cbor", "", None],
)
def test_safe_cbor_decode_failure(payload):
    assert device_logs.safe_cbor_decode(payload) == {"error": "decode_failed"}
