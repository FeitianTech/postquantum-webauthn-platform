"""Tests for github_mirror: the GitHub client, the registration log and the metadata copy."""

import base64
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError

import cbor2
import pytest

from server.app.storage import github_mirror
from server.app.storage.github_mirror import is_logging_enabled
from tests.app.storage import fake_github


class _FakeResponse:
    def __init__(self, status=200, body=b"{}"):
        self._status = status
        self._body = body

    def getcode(self):
        return self._status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_the_log_is_off_without_a_token(monkeypatch):
    monkeypatch.delenv("ENABLE_GITHUB_LOGGING", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert is_logging_enabled() is False


@pytest.mark.parametrize("token", ["", "   "])
def test_a_blank_token_is_no_token(monkeypatch, token):
    monkeypatch.delenv("ENABLE_GITHUB_LOGGING", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", token)
    assert is_logging_enabled() is False


def test_the_log_is_on_with_a_token(monkeypatch):
    monkeypatch.delenv("ENABLE_GITHUB_LOGGING", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
    assert is_logging_enabled() is True


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "True", "YES", "ON"])
def test_enable_github_logging_does_not_turn_the_log_on_without_a_token(monkeypatch, value):
    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", value)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert is_logging_enabled() is False

    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
    assert is_logging_enabled() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", "False", "NO", "OFF", ""])
def test_enable_github_logging_turns_the_log_off_with_a_token(monkeypatch, value):
    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", value)
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
    assert is_logging_enabled() is False


def test_api_url_uses_default_log_repository(monkeypatch):
    monkeypatch.delenv("GITHUB_LOG_REPO_OWNER", raising=False)
    monkeypatch.delenv("GITHUB_LOG_REPO_NAME", raising=False)

    assert github_mirror._api_url("contents/logs/example.json") == (
        "https://api.github.com/repos/rainzhang05/CredentialLogs/contents/logs/example.json"
    )


def test_api_url_uses_repo_env_override(monkeypatch):
    monkeypatch.setenv("GITHUB_LOG_REPO_OWNER", "example-owner")
    monkeypatch.setenv("GITHUB_LOG_REPO_NAME", "example-repo")

    assert github_mirror._api_url("contents/logs/example.json") == (
        "https://api.github.com/repos/example-owner/example-repo/contents/logs/example.json"
    )


@pytest.mark.parametrize(
    ("name", "quoted"),
    [
        ("metadata (1).json", "metadata%20%281%29.json"),
        ("a#b.json", "a%23b.json"),
        ("a?b.json", "a%3Fb.json"),
        ("métadonnées.json", "m%C3%A9tadonn%C3%A9es.json"),
        ("50%.json", "50%25.json"),
    ],
)
def test_api_url_quotes_a_file_name_but_keeps_the_folders(monkeypatch, name, quoted):
    monkeypatch.delenv("GITHUB_LOG_REPO_OWNER", raising=False)
    monkeypatch.delenv("GITHUB_LOG_REPO_NAME", raising=False)

    assert github_mirror._api_url(f"contents/metadata/{name}") == (
        f"https://api.github.com/repos/rainzhang05/CredentialLogs/contents/metadata/{quoted}"
    )


def test_a_quoted_url_is_one_urllib_sends(monkeypatch):
    # Unquoted, a space is refused by urllib (InvalidURL) and "#" cuts the path short.
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
    sent = []
    monkeypatch.setattr(
        github_mirror.urllib_request,
        "urlopen",
        lambda request_obj, timeout=None: sent.append(request_obj.selector) or _FakeResponse(status=201),
    )

    github_mirror.github_upload_file("metadata/a b#1.json", b"{}", "metadata: add a b#1.json")

    assert sent == ["/repos/rainzhang05/CredentialLogs/contents/metadata/a%20b%231.json"]


def test_credential_log_repository_falls_back_when_env_values_are_blank(monkeypatch):
    monkeypatch.setenv("GITHUB_LOG_REPO_OWNER", "   ")
    monkeypatch.setenv("GITHUB_LOG_REPO_NAME", "")

    owner, repo = github_mirror.credential_log_repository()

    assert owner == "rainzhang05"
    assert repo == "CredentialLogs"


def test_credential_log_repository_strips_env_values(monkeypatch):
    monkeypatch.setenv("GITHUB_LOG_REPO_OWNER", "  custom-owner  ")
    monkeypatch.setenv("GITHUB_LOG_REPO_NAME", "  custom-repo  ")

    owner, repo = github_mirror.credential_log_repository()

    assert owner == "custom-owner"
    assert repo == "custom-repo"


def test_token_returns_value_when_present(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")

    assert github_mirror._token() == "secret-token"


def test_token_raises_with_repository_context_when_missing(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_LOG_REPO_OWNER", "owner-a")
    monkeypatch.setenv("GITHUB_LOG_REPO_NAME", "repo-a")

    with pytest.raises(RuntimeError, match="owner-a/repo-a"):
        github_mirror._token()


def test_encode_content_returns_base64_ascii():
    data = b"hello-world"

    encoded = github_mirror._encode_content(data)

    assert encoded == base64.b64encode(data).decode("ascii")


def test_request_sets_expected_headers_and_json_body(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")

    captured = {}

    def _fake_urlopen(request_obj, timeout=None):
        captured["timeout"] = timeout
        header_items = {
            key.lower(): value for key, value in request_obj.header_items()
        }
        captured["method"] = request_obj.get_method()
        captured["url"] = request_obj.full_url
        captured["auth"] = header_items.get("authorization")
        captured["accept"] = header_items.get("accept")
        captured["user_agent"] = header_items.get("user-agent")
        captured["content_type"] = header_items.get("content-type")
        captured["body"] = request_obj.data
        return _FakeResponse(status=201, body=b'{"ok":true}')

    monkeypatch.setattr(github_mirror.urllib_request, "urlopen", _fake_urlopen)

    status, body = github_mirror._request(
        "PUT", "https://api.github.com/example", {"alpha": 1}
    )

    assert status == 201
    assert body == b'{"ok":true}'
    assert captured["method"] == "PUT"
    assert captured["url"] == "https://api.github.com/example"
    assert captured["auth"] == "Bearer token-123"
    assert captured["accept"] == "application/vnd.github+json"
    assert captured["user_agent"] == "postquantum-webauthn-logger"
    assert captured["content_type"] == "application/json"
    assert json.loads(captured["body"].decode("utf-8")) == {"alpha": 1}


def test_request_retries_once_on_5xx_http_error(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")

    calls = {"count": 0}
    sleeps = []

    def _fake_urlopen(_request_obj, timeout=None):
        calls["count"] += 1
        if calls["count"] == 1:
            raise HTTPError(
                url="https://api.github.com/example",
                code=503,
                msg="Service Unavailable",
                hdrs=None,
                fp=io.BytesIO(b"temporary"),
            )
        return _FakeResponse(status=200, body=b"ok")

    monkeypatch.setattr(github_mirror.urllib_request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(github_mirror.time, "sleep", lambda seconds: sleeps.append(seconds))

    status, body = github_mirror._request("GET", "https://api.github.com/example")

    assert calls["count"] == 2
    assert sleeps == [1]
    assert status == 200
    assert body == b"ok"


def test_request_does_not_retry_on_4xx_http_error(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")

    calls = {"count": 0}
    sleeps = []

    def _fake_urlopen(_request_obj, timeout=None):
        calls["count"] += 1
        raise HTTPError(
            url="https://api.github.com/example",
            code=400,
            msg="Bad Request",
            hdrs=None,
            fp=io.BytesIO(b"invalid"),
        )

    monkeypatch.setattr(github_mirror.urllib_request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(github_mirror.time, "sleep", lambda seconds: sleeps.append(seconds))

    with pytest.raises(HTTPError):
        github_mirror._request("GET", "https://api.github.com/example")

    assert calls["count"] == 1
    assert sleeps == []


def test_request_retries_once_on_url_error(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")

    calls = {"count": 0}
    sleeps = []

    def _fake_urlopen(_request_obj, timeout=None):
        calls["count"] += 1
        if calls["count"] == 1:
            raise URLError("network down")
        return _FakeResponse(status=200, body=b"ok")

    monkeypatch.setattr(github_mirror.urllib_request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(github_mirror.time, "sleep", lambda seconds: sleeps.append(seconds))

    status, body = github_mirror._request("GET", "https://api.github.com/example")

    assert calls["count"] == 2
    assert sleeps == [1]
    assert status == 200
    assert body == b"ok"


def test_request_raises_after_retrying_url_error(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
    sleeps = []

    monkeypatch.setattr(
        github_mirror.urllib_request,
        "urlopen",
        lambda _request_obj, timeout=None: (_ for _ in ()).throw(URLError("still down")),
    )
    monkeypatch.setattr(github_mirror.time, "sleep", lambda seconds: sleeps.append(seconds))

    with pytest.raises(URLError):
        github_mirror._request("GET", "https://api.github.com/example")

    assert sleeps == [1]


def test_request_passes_configured_timeout(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
    captured = []

    def _fake_urlopen(_request_obj, timeout=None):
        captured.append(timeout)
        return _FakeResponse(status=200, body=b"ok")

    monkeypatch.setattr(github_mirror.urllib_request, "urlopen", _fake_urlopen)

    monkeypatch.delenv("GITHUB_HTTP_TIMEOUT_SECONDS", raising=False)
    github_mirror._request("GET", "https://api.github.com/example")
    monkeypatch.setenv("GITHUB_HTTP_TIMEOUT_SECONDS", "2.5")
    github_mirror._request("GET", "https://api.github.com/example")
    monkeypatch.setenv("GITHUB_HTTP_TIMEOUT_SECONDS", "invalid")
    github_mirror._request("GET", "https://api.github.com/example")

    assert captured == [4.0, 2.5, 4.0]


def test_request_does_not_retry_timeouts(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
    calls = {"count": 0}
    sleeps = []

    def _fake_urlopen(_request_obj, timeout=None):
        calls["count"] += 1
        raise URLError(TimeoutError("timed out"))

    monkeypatch.setattr(github_mirror.urllib_request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(github_mirror.time, "sleep", lambda seconds: sleeps.append(seconds))

    with pytest.raises(URLError):
        github_mirror._request("GET", "https://api.github.com/example")

    assert calls["count"] == 1
    assert sleeps == []


def test_github_upload_json_builds_add_message_and_base64_content(monkeypatch):
    captured = {}

    def _fake_request(method, url, body=None):
        captured["method"] = method
        captured["url"] = url
        captured["body"] = body
        return 200, b"{}"

    monkeypatch.setattr(github_mirror, "_request", _fake_request)

    github_mirror.github_upload_json("logs/aaguid-1/file.json", {"k": 1})

    assert captured["method"] == "PUT"
    assert "contents/logs/aaguid-1/file.json" in captured["url"]
    assert captured["body"]["message"] == "add: file.json (AAGUID=aaguid-1)"
    decoded = base64.b64decode(captured["body"]["content"]).decode("utf-8")
    assert json.loads(decoded) == {"k": 1}
    assert "sha" not in captured["body"]


def test_github_upload_file_passes_message_content_and_optional_sha(monkeypatch):
    captured = {}

    def _fake_request(method, url, body=None):
        captured["method"] = method
        captured["url"] = url
        captured["body"] = body
        return 200, b"{}"

    monkeypatch.setattr(github_mirror, "_request", _fake_request)

    github_mirror.github_upload_file(
        "logs/test.bin",
        b"\x00\x01\x02",
        "binary upload",
        sha="sha-123",
    )

    assert captured["method"] == "PUT"
    assert "contents/logs/test.bin" in captured["url"]
    assert captured["body"]["message"] == "binary upload"
    assert captured["body"]["sha"] == "sha-123"
    assert base64.b64decode(captured["body"]["content"]) == b"\x00\x01\x02"


def test_github_upload_file_omits_sha_when_not_provided(monkeypatch):
    captured = {}

    def _fake_request(method, url, body=None):
        captured["method"] = method
        captured["url"] = url
        captured["body"] = body
        return 200, b"{}"

    monkeypatch.setattr(github_mirror, "_request", _fake_request)

    github_mirror.github_upload_file("logs/test.bin", b"\x00", "binary upload")

    assert captured["method"] == "PUT"
    assert "sha" not in captured["body"]


def test_git_blob_sha_matches_git_blob_spec():
    payload = b"hello\n"

    result = github_mirror.git_blob_sha(payload)

    assert result == "ce013625030ba8dba906f756967f9e9ca394464a"

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
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
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
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
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


def test_the_test_run_never_logs_to_github():
    # tests/conftest.py turns the log off for the whole run.
    assert is_logging_enabled() is False


def test_a_registration_without_a_token_is_not_logged_and_warns_nothing(monkeypatch, caplog):
    monkeypatch.delenv("ENABLE_GITHUB_LOGGING", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(github_mirror.threading, "Thread", ImmediateThread)
    sent = []
    monkeypatch.setattr(github_mirror, "_request", lambda *args, **kwargs: sent.append(args))

    with caplog.at_level(logging.DEBUG, logger=github_mirror.__name__):
        github_mirror.record_registration_event(
            github_mirror.RegistrationEvent(
                timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
                rp_id="example.com",
                aaguid=None,
                device_name_mds=None,
                attestation_object=cbor2.dumps({}),
            )
        )
        assert github_mirror.maybe_store_uploaded_metadata_file("demo.json", b"{}") is False

    assert sent == []
    assert [record for record in caplog.records if record.levelno >= logging.WARNING] == []


def test_record_registration_event_disabled(monkeypatch):
    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "0")

    uploads = []
    monkeypatch.setattr(github_mirror, "github_upload_json", lambda *args, **kwargs: uploads.append(args))

    event = github_mirror.RegistrationEvent(
        timestamp=datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        rp_id="example.com",
        aaguid=None,
        device_name_mds=None,
        attestation_object=cbor2.dumps({}),
    )

    github_mirror.record_registration_event(event)

    assert uploads == []


def test_record_registration_event_uploads_inline_on_cloud_run(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger=github_mirror.__name__)
    uploads = []

    def fake_upload(path, payload, **kwargs):
        uploads.append((path, payload, kwargs))

    def fail_thread(*_args, **_kwargs):
        raise AssertionError("Threaded upload should not be used on Cloud Run by default")

    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "1")
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
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
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
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
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
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


def test_safe_metadata_repo_filename_sanitizes_traversal_and_invalid_input():
    assert github_mirror._safe_metadata_repo_filename("../../../etc/passwd") == "passwd"
    assert github_mirror._safe_metadata_repo_filename(" /tmp/demo.json ") == "demo.json"
    assert github_mirror._safe_metadata_repo_filename("///") == "metadata.json"
    assert github_mirror._safe_metadata_repo_filename(None) == "metadata.json"


@pytest.mark.parametrize("name", [".", "..", " .. ", "a/.."])
def test_a_metadata_file_named_for_a_folder_is_logged_as_metadata_json(name):
    assert github_mirror._safe_metadata_repo_filename(name) == "metadata.json"


def test_no_metadata_is_copied_while_the_log_is_off(monkeypatch):
    github = fake_github.install(monkeypatch)
    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "0")

    assert github_mirror.maybe_store_uploaded_metadata_file("demo.json", b"{}") is False

    assert github.calls == []


def test_metadata_is_added_to_an_empty_repository(monkeypatch):
    github = fake_github.install(monkeypatch)

    assert github_mirror.maybe_store_uploaded_metadata_file("../../../custom.json", b'{"entry":3}') is True

    assert github.files == {"metadata/custom.json": b'{"entry":3}'}
    [(path, body)] = github.puts
    assert body["message"] == "metadata: add custom.json"
    assert "sha" not in body


def test_metadata_is_added_to_a_repository_without_a_metadata_folder(monkeypatch):
    github = fake_github.install(monkeypatch)
    github.files["logs/unknown/one.json"] = b"{}"

    assert github_mirror.maybe_store_uploaded_metadata_file("demo.json", b'{"entry":1}') is True

    assert github.files["metadata/demo.json"] == b'{"entry":1}'


def test_metadata_already_there_under_another_name_is_not_copied_again(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    github.files["metadata/existing.json"] = b'{"entry":1}'

    with caplog.at_level(logging.INFO, logger=github_mirror.__name__):
        assert github_mirror.maybe_store_uploaded_metadata_file("demo.json", b'{"entry":1}') is False

    assert github.puts == []
    assert "identical content already present as existing.json" in caplog.text


def test_metadata_already_there_is_found_past_the_contents_api_s_1000_entries(monkeypatch):
    github = fake_github.install(monkeypatch)
    for index in range(1_500):
        github.files[f"metadata/file-{index:04d}.json"] = f'{{"entry":{index}}}'.encode()

    assert github_mirror.maybe_store_uploaded_metadata_file("again.json", b'{"entry":1400}') is False

    assert github.puts == []
    assert ("GET", "git/trees/tree-metadata") in github.calls
    assert ("GET", "contents/metadata") not in github.calls


def test_metadata_in_a_folder_inside_metadata_is_not_the_folder_s_own(monkeypatch):
    github = fake_github.install(monkeypatch)
    github.files["metadata/archive/old.json"] = b'{"entry":1}'

    assert github_mirror.maybe_store_uploaded_metadata_file("demo.json", b'{"entry":1}') is True

    assert github.files["metadata/demo.json"] == b'{"entry":1}'


def test_metadata_with_a_taken_name_replaces_the_file_there(monkeypatch):
    github = fake_github.install(monkeypatch)
    github.files["metadata/demo.json"] = b'{"entry":1}'

    assert github_mirror.maybe_store_uploaded_metadata_file(" demo.json ", b'{"entry":2}') is True

    assert github.files["metadata/demo.json"] == b'{"entry":2}'
    [(_path, body)] = github.puts
    assert body["message"] == "metadata: update demo.json"
    assert body["sha"] == github_mirror.git_blob_sha(b'{"entry":1}')


def test_a_tree_github_cuts_short_is_logged_and_read(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    github.files["metadata/existing.json"] = b'{"entry":1}'
    answer = github._tree

    def _truncated(folder):
        status, body = answer(folder)
        return status, json.dumps({**json.loads(body), "truncated": True}).encode()

    monkeypatch.setattr(github, "_tree", _truncated)

    with caplog.at_level(logging.INFO, logger=github_mirror.__name__):
        assert github_mirror.maybe_store_uploaded_metadata_file("demo.json", b'{"entry":1}') is False

    assert "listed the log repository's metadata folder in part" in caplog.text


@pytest.mark.parametrize(
    "answers",
    [
        [(200, b"{}")],
        [(200, b"not json")],
        [(200, json.dumps([{"name": "metadata", "type": "dir", "sha": "t"}]).encode()), (200, b"[]")],
        [(200, json.dumps([{"name": "metadata", "type": "dir", "sha": "t"}]).encode()), (200, b'{"tree": 1}')],
    ],
    ids=["root-not-a-list", "root-not-json", "tree-not-an-object", "tree-without-entries"],
)
def test_an_answer_the_mirror_does_not_read_copies_nothing(monkeypatch, caplog, answers):
    fake_github.install(monkeypatch)
    queued = list(answers)
    puts = []

    def _request(method, url, body=None):
        if method == "PUT":
            puts.append(url)
            return 201, b"{}"
        return queued.pop(0)

    monkeypatch.setattr(github_mirror, "_request", _request)

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert github_mirror.maybe_store_uploaded_metadata_file("demo.json", b"{}") is False

    assert puts == []
    assert "Unable to read the metadata folder of the log repository" in caplog.text


def test_items_of_a_tree_that_are_not_files_are_left_out(monkeypatch):
    fake_github.install(monkeypatch)
    root = [{"name": "metadata", "type": "dir", "sha": "t"}, "metadata", {"name": "logs", "type": "dir", "sha": "u"}]
    tree = {"tree": [7, {"path": "a.json", "type": "blob", "sha": "s"}, {"path": "b", "type": "tree", "sha": "x"},
                     {"path": "c.json", "type": "blob", "sha": 3}]}
    answers = [(200, json.dumps(root).encode()), (200, json.dumps(tree).encode())]
    monkeypatch.setattr(github_mirror, "_request", lambda method, url, body=None: answers.pop(0))

    assert github_mirror.github_metadata_blobs() == {"a.json": "s"}


def test_github_failing_to_list_copies_nothing(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    github.fail.append(fake_github.http_error(503))

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert github_mirror.maybe_store_uploaded_metadata_file("demo.json", b"{}") is False

    assert github.puts == []
    assert "Unable to read the metadata folder" in caplog.text


def test_a_root_listing_github_refuses_is_not_an_empty_repository(monkeypatch):
    github = fake_github.install(monkeypatch)
    github.fail.append(fake_github.http_error(403))

    with pytest.raises(HTTPError):
        github_mirror.github_metadata_blobs()


def test_github_failing_to_take_the_file_is_logged(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    real = github.request

    def _refuse_puts(method, url, body=None):
        if method == "PUT":
            raise fake_github.http_error(500)
        return real(method, url, body)

    monkeypatch.setattr(github_mirror, "_request", _refuse_puts)

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert github_mirror.maybe_store_uploaded_metadata_file("demo.json", b"{}") is False

    assert "Failed to upload metadata file demo.json" in caplog.text
