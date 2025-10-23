import hashlib
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

    def fake_upload(path, payload, *, sha=None, message=None):
        uploads.append((path, payload, sha, message))

    def fake_get_json(_path):
        return None

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setattr(device_logs, "github_upload_json", fake_upload)
    monkeypatch.setattr(device_logs, "github_get_json", fake_get_json)
    monkeypatch.setattr(device_logs.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(device_logs, "_schedule_cleanup_workflow_check", lambda: None)

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
    assert "times=1" in out
    assert "AAGUID=7701a390-8b53-4ce0-bf7c-b331569b8d1a" in out

    assert len(uploads) == 1
    path, payload, sha, message = uploads[0]

    digest = hashlib.sha256(attestation_object).hexdigest()[:16]
    assert path == f"logs/{digest}_7701a390-8b53-4ce0-bf7c-b331569b8d1a.json"
    assert sha is None
    assert message.startswith("add:")

    assert payload == {
        "timestamp": "2025-10-23T09:41:10Z",
        "rp_id": "example.com",
        "aaguid": "7701a390-8b53-4ce0-bf7c-b331569b8d1a",
        "device_name_mds": "Example Authenticator",
        "raw_attestation_object": device_logs.to_b64url(attestation_object),
        "decoded_attestation_object": {"test": device_logs.to_b64url(b"value")},
        "times_registered": 1,
    }


def test_record_registration_event_updates_existing(monkeypatch, capsys):
    uploads = []

    def fake_upload(path, payload, *, sha=None, message=None):
        uploads.append((path, payload, sha, message))

    attestation_object = cbor2.dumps({"nested": {"value": 1}})
    base_payload = {
        "timestamp": "2025-10-23T09:41:10Z",
        "rp_id": "example.com",
        "aaguid": "7701a390-8b53-4ce0-bf7c-b331569b8d1a",
        "device_name_mds": "Example Authenticator",
        "raw_attestation_object": device_logs.to_b64url(attestation_object),
        "decoded_attestation_object": {"nested": {"value": 1}},
        "times_registered": 3,
    }

    def fake_get_json(path):
        return base_payload, "sha-abc"

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setattr(device_logs, "github_upload_json", fake_upload)
    monkeypatch.setattr(device_logs, "github_get_json", fake_get_json)
    monkeypatch.setattr(device_logs.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(device_logs, "_schedule_cleanup_workflow_check", lambda: None)

    event = device_logs.RegistrationEvent(
        timestamp=datetime(2025, 10, 24, 10, 0, 0, tzinfo=timezone.utc),
        rp_id="example.com",
        user_id=b"user-id",
        user_name="alice",
        user_display_name="Alice",
        credential_id=b"credential-id",
        public_key_cose={1: -7, -2: b"\x01\x02"},
        sign_count=5,
        transports=["usb"],
        aaguid=uuid.UUID("7701a390-8b53-4ce0-bf7c-b331569b8d1a").bytes,
        device_name_mds="Example Authenticator",
        attestation_format="packed",
        attestation_object=attestation_object,
        client_data_json=b"{}",
    )

    device_logs.record_registration_event(event)

    out = capsys.readouterr().out.strip()
    assert "Updated credential log" in out
    assert "times=4" in out

    assert len(uploads) == 1
    path, payload, sha, message = uploads[0]

    digest = hashlib.sha256(attestation_object).hexdigest()[:16]
    assert path == f"logs/{digest}_7701a390-8b53-4ce0-bf7c-b331569b8d1a.json"
    assert sha == "sha-abc"
    assert message.startswith("update:")

    assert payload["timestamp"] == "2025-10-24T10:00:00Z"
    assert payload["times_registered"] == 4


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
