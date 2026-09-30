import logging
import uuid
from datetime import datetime, timezone

import cbor2
import pytest

# Imported after the sys.path bootstrap above.
from server.app.storage import github_mirror  # noqa: E402


class ImmediateThread:
    def __init__(self, target, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


def test_record_registration_event_uploads_json(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger=github_mirror.__name__)
    uploads = []

    def fake_upload(path, payload, **kwargs):
        uploads.append((path, payload, kwargs))

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setattr(github_mirror, "github_upload_json", fake_upload)
    monkeypatch.setattr(github_mirror.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(github_mirror, "random_shortid", lambda length=8: "abcdef12")

    attestation_object = cbor2.dumps({"test": b"value"})
    event = github_mirror.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        rp_id="example.com",
        aaguid=uuid.UUID("7701a390-8b53-4ce0-bf7c-b331569b8d1a").bytes,
        device_name_mds="Example Authenticator",
        attestation_object=attestation_object,
        signature_valid=True,
        root_valid=True,
        rp_id_hash_valid=True,
        aaguid_match=True,
    )

    github_mirror.record_registration_event(event)

    out = "\n".join(record.getMessage() for record in caplog.records)
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
    assert payload["raw_attestation_object"] == github_mirror.to_b64url(attestation_object)
    assert payload["decoded_attestation_object"] == {"test": github_mirror.to_b64url(b"value")}
    # Verify attestation check fields are included
    assert payload["signature_valid"] is True
    assert payload["root_valid"] is True
    assert payload["rp_id_hash_valid"] is True
    assert payload["aaguid_match"] is True


def test_record_registration_event_creates_unique_files(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger=github_mirror.__name__)
    uploads = []

    def fake_upload(path, payload, **kwargs):
        uploads.append((path, payload, kwargs))

    short_ids = iter(["firstid", "secondid"])

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setattr(github_mirror, "github_upload_json", fake_upload)
    monkeypatch.setattr(github_mirror.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(github_mirror, "random_shortid", lambda length=8: next(short_ids))

    attestation_object = cbor2.dumps({"another": "value"})

    base_event_kwargs = dict(
        rp_id="example.com",
        aaguid=uuid.UUID("7701a390-8b53-4ce0-bf7c-b331569b8d1a").bytes,
        device_name_mds="Example Authenticator",
        attestation_object=attestation_object,
    )

    event1 = github_mirror.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        **base_event_kwargs,
    )
    event2 = github_mirror.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 45, 10, tzinfo=timezone.utc),
        **base_event_kwargs,
    )

    github_mirror.record_registration_event(event1)
    github_mirror.record_registration_event(event2)

    out_lines = [record.getMessage() for record in caplog.records]
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

    monkeypatch.setattr(github_mirror, "is_logging_enabled", disabled_logging)

    def fail_upload(*_args, **_kwargs):
        raise AssertionError("github_upload_json should not be called when logging is disabled")

    monkeypatch.setattr(github_mirror, "github_upload_json", fail_upload)

    event = github_mirror.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        rp_id="example.com",
        aaguid=None,
        device_name_mds=None,
        attestation_object=cbor2.dumps({}),
    )

    github_mirror.record_registration_event(event)


def test_record_registration_event_uploads_inline_on_cloud_run(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger=github_mirror.__name__)
    uploads = []

    def fake_upload(path, payload, **kwargs):
        uploads.append((path, payload, kwargs))

    def fail_thread(*_args, **_kwargs):
        raise AssertionError("Threaded upload should not be used on Cloud Run by default")

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setenv("K_SERVICE", "pqc-webauthn")
    monkeypatch.delenv("GITHUB_LOG_ASYNC", raising=False)
    monkeypatch.setattr(github_mirror, "github_upload_json", fake_upload)
    monkeypatch.setattr(github_mirror.threading, "Thread", fail_thread)
    monkeypatch.setattr(github_mirror, "random_shortid", lambda length=8: "inline01")

    event = github_mirror.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        rp_id="example.com",
        aaguid=uuid.UUID("7701a390-8b53-4ce0-bf7c-b331569b8d1a").bytes,
        device_name_mds="Example Authenticator",
        attestation_object=cbor2.dumps({}),
    )

    github_mirror.record_registration_event(event)

    out = "\n".join(record.getMessage() for record in caplog.records)
    assert "Uploaded credential log" in out
    assert len(uploads) == 1
    assert uploads[0][0].endswith("_inline01.json")


@pytest.mark.parametrize(
    "payload",
    [b"not-cbor", "", None],
)
def test_safe_cbor_decode_failure(payload):
    assert github_mirror.safe_cbor_decode(payload) == {"error": "decode_failed"}


def test_to_b64url_returns_empty_for_empty_bytes():
    assert github_mirror.to_b64url(b"") == ""


def test_random_shortid_returns_hex_with_requested_length():
    value = github_mirror.random_shortid(7)

    assert len(value) == 7
    int(value, 16)


@pytest.mark.parametrize("length", [0, -1])
def test_random_shortid_rejects_non_positive_lengths(length):
    with pytest.raises(ValueError, match="length must be positive"):
        github_mirror.random_shortid(length)


def test_uuid_bytes_to_str_handles_none_and_non_uuid_lengths():
    assert github_mirror.uuid_bytes_to_str(None) == "unknown"
    assert github_mirror.uuid_bytes_to_str(b"abc") == github_mirror.to_b64url(b"abc")


def test_uuid_bytes_to_str_handles_memoryview_value():
    raw = memoryview(b"\x00" * 16)

    value = github_mirror.uuid_bytes_to_str(raw)

    assert value == github_mirror.to_b64url(raw)


def test_safe_cbor_decode_accepts_base64url_string_payload():
    payload = cbor2.dumps({"nested": [b"a", {"k": b"b"}]})

    decoded = github_mirror.safe_cbor_decode(github_mirror.to_b64url(payload))

    assert decoded == {
        "nested": [
            github_mirror.to_b64url(b"a"),
            {"k": github_mirror.to_b64url(b"b")},
        ]
    }


def test_safe_cbor_decode_rejects_invalid_base64url_string():
    assert github_mirror.safe_cbor_decode("***") == {"error": "decode_failed"}


def test_safe_cbor_decode_reports_failure_for_strings_that_are_not_base64url():
    # Standard base64 with "+"/"/" is not base64url and is refused outright,
    # rather than being decoded through a translation that changes the bytes.
    assert github_mirror.safe_cbor_decode("ab+/") == {"error": "decode_failed"}
    assert github_mirror.safe_cbor_decode("not base64url") == {"error": "decode_failed"}
    assert github_mirror.safe_cbor_decode("   ") == {"error": "decode_failed"}


def test_safe_cbor_decode_wraps_non_mapping_values_under_value_key():
    payload = cbor2.dumps(["a", "b"])

    decoded = github_mirror.safe_cbor_decode(payload)

    assert decoded == {"value": ["a", "b"]}


def test_log_path_sanitizes_folder_and_formats_timestamp(monkeypatch):
    monkeypatch.setattr(github_mirror, "random_shortid", lambda length=8: "path01")

    path = github_mirror._log_path("../unsafe", datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc))

    assert path == "logs/unknown/20260102T030405Z_path01.json"


def test_should_upload_async_env_override_has_priority(monkeypatch):
    monkeypatch.setenv("GITHUB_LOG_ASYNC", "0")
    monkeypatch.setenv("K_SERVICE", "service-name")
    assert github_mirror._should_upload_async() is False

    monkeypatch.setenv("GITHUB_LOG_ASYNC", "1")
    assert github_mirror._should_upload_async() is True


def test_should_upload_async_defaults_to_inline_on_cloud_run(monkeypatch):
    monkeypatch.delenv("GITHUB_LOG_ASYNC", raising=False)
    monkeypatch.setenv("K_SERVICE", "service-name")

    assert github_mirror._should_upload_async() is False


def test_should_upload_async_defaults_to_background_off_cloud_run(monkeypatch):
    monkeypatch.delenv("GITHUB_LOG_ASYNC", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)

    assert github_mirror._should_upload_async() is True


def test_should_upload_async_unknown_override_falls_back_to_cloud_run_policy(monkeypatch):
    monkeypatch.setenv("GITHUB_LOG_ASYNC", "maybe")
    monkeypatch.setenv("K_SERVICE", "service-name")

    assert github_mirror._should_upload_async() is False


def test_upload_worker_logs_failure_without_raising(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger=github_mirror.__name__)
    monkeypatch.setattr(
        github_mirror,
        "github_upload_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("upload failed")),
    )

    github_mirror._upload_worker(
        "logs/unknown/file.json",
        {"a": 1},
        {
            "timestamp": "2026-04-03T00:00:00+0800",
            "aaguid": "unknown",
            "device": "unknown",
            "action": "create",
        },
    )

    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "Failed to upload credential log" in output
    assert "upload failed" in output


def test_upload_worker_logs_success(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger=github_mirror.__name__)
    monkeypatch.setattr(github_mirror, "github_upload_json", lambda *_args, **_kwargs: None)

    github_mirror._upload_worker(
        "logs/unknown/file.json",
        {"a": 1},
        {
            "timestamp": "2026-04-03T00:00:00+0800",
            "aaguid": "7701a390-8b53-4ce0-bf7c-b331569b8d1a",
            "device": "Demo Device",
            "action": "create",
        },
    )

    output = "\n".join(record.getMessage() for record in caplog.records)
    assert "Uploaded credential log" in output
    assert "AAGUID=7701a390-8b53-4ce0-bf7c-b331569b8d1a" in output


def test_record_registration_event_honors_async_false_override(monkeypatch):
    uploads = []

    def fake_upload(path, payload, **kwargs):
        uploads.append((path, payload, kwargs))

    def fail_thread(*_args, **_kwargs):
        raise AssertionError("Thread should not be used when GITHUB_LOG_ASYNC=0")

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setenv("GITHUB_LOG_ASYNC", "0")
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.setattr(github_mirror, "github_upload_json", fake_upload)
    monkeypatch.setattr(github_mirror.threading, "Thread", fail_thread)

    event = github_mirror.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        rp_id="example.com",
        aaguid=None,
        device_name_mds="Demo",
        attestation_object=cbor2.dumps({}),
    )

    github_mirror.record_registration_event(event)

    assert len(uploads) == 1


def test_record_registration_event_honors_async_true_override_on_cloud_run(monkeypatch):
    uploads = []
    thread_events = []

    class _CapturingThread:
        def __init__(self, target, args=(), kwargs=None, daemon=None):
            thread_events.append(("init", daemon))
            self._target = target
            self._args = args
            self._kwargs = kwargs or {}

        def start(self):
            thread_events.append(("start", None))
            self._target(*self._args, **self._kwargs)

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setenv("K_SERVICE", "service-name")
    monkeypatch.setenv("GITHUB_LOG_ASYNC", "true")
    monkeypatch.setattr(github_mirror.threading, "Thread", _CapturingThread)
    monkeypatch.setattr(
        github_mirror,
        "github_upload_json",
        lambda path, payload, **kwargs: uploads.append((path, payload, kwargs)),
    )

    event = github_mirror.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        rp_id="example.com",
        aaguid=None,
        device_name_mds="Demo",
        attestation_object=cbor2.dumps({}),
    )

    github_mirror.record_registration_event(event)

    assert ("start", None) in thread_events
    assert len(uploads) == 1


def test_build_log_payload_handles_unknown_aaguid_and_decode_failures(monkeypatch):
    monkeypatch.setattr(github_mirror, "random_shortid", lambda length=8: "abc123")

    event = github_mirror.RegistrationEvent(
        timestamp=datetime(2026, 4, 3, 1, 2, 3, tzinfo=timezone.utc),
        rp_id="example.com",
        aaguid=None,
        device_name_mds=None,
        attestation_object=b"not-cbor",
    )

    path, payload, summary = github_mirror._build_log_payload(event)

    assert path == "logs/unknown/20260403T010203Z_abc123.json"
    assert payload["aaguid"] == "unknown"
    assert payload["decoded_attestation_object"] == {"error": "decode_failed"}
    assert summary["aaguid"] == "unknown"
    assert summary["device"] == "unknown"
