import base64
import uuid
from datetime import datetime, timezone

import cbor2
import pytest

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

    def fake_upload(path, payload):
        uploads.append((path, payload))

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
    )

    device_logs.record_registration_event(event)

    out = capsys.readouterr().out.strip()
    assert "Uploaded credential log" in out
    assert "AAGUID=7701a390-8b53-4ce0-bf7c-b331569b8d1a" in out

    assert len(uploads) == 1
    path, payload = uploads[0]
    assert path == (
        "logs/2025-10-23T09-41-10Z_7701a390-8b53-4ce0-bf7c-b331569b8d1a_abcdef12.json"
    )

    assert payload["timestamp"] == "2025-10-23T09:41:10Z"
    assert payload["rp_id"] == "example.com"
    assert payload["user"]["id"] == base64.urlsafe_b64encode(b"user-id").decode("ascii").rstrip("=")
    assert payload["credential"]["aaguid"] == "7701a390-8b53-4ce0-bf7c-b331569b8d1a"
    assert payload["credential"]["device_name_mds"] == "Example Authenticator"
    assert payload["credential"]["transports"] == ["usb", "ble"]
    assert payload["credential"]["public_key_cose"]["-2"] == device_logs.to_b64url(b"\x01\x02")
    assert payload["attestation"]["format"] == "packed"
    assert payload["attestation"]["raw_attestation_object"] == device_logs.to_b64url(attestation_object)
    assert payload["attestation"]["decoded"] == {"test": device_logs.to_b64url(b"value")}
    assert payload["client_data_json"] == device_logs.to_b64url(client_data_json)


def test_record_registration_event_disabled(monkeypatch):
    monkeypatch.delenv("ENABLE_GITHUB_LOGGING", raising=False)

    def disabled_logging():
        return False

    monkeypatch.setattr(device_logs, "is_logging_enabled", disabled_logging)

    def fail_schedule():
        raise AssertionError("cleanup workflow should not be scheduled when logging is disabled")

    monkeypatch.setattr(device_logs, "_schedule_cleanup_workflow_check", fail_schedule)

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


@pytest.mark.parametrize(
    "payload",
    [b"not-cbor", "", None],
)
def test_safe_cbor_decode_failure(payload):
    assert device_logs.safe_cbor_decode(payload) == {"error": "decode_failed"}
