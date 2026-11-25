"""Tests for github_mirror: the GitHub client, the registration log and the metadata copy."""

import base64
import http.client
import io
import json
import logging
import os
import threading
import types
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote

import cbor2
import pytest
from fido2 import cbor

from server.app.storage import github_mirror, github_outbox
from server.app.storage.github_mirror import is_logging_enabled
from server.app.storage.github_outbox import Delivery, OutboxEntry
from tests.app.log_lines import FORGED, one_line_naming
from tests.app.metadata.upload_entries import minimal_entry
from tests.app.security.ceremony_helpers import shared_where_fido2_reads_plain_items
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


def test_github_upload_file_creates_the_file_and_never_names_a_sha(monkeypatch):
    captured = {}

    def _fake_request(method, url, body=None):
        captured["method"] = method
        captured["url"] = url
        captured["body"] = body
        return 201, b"{}"

    monkeypatch.setattr(github_mirror, "_request", _fake_request)

    github_mirror.github_upload_file("logs/test.bin", b"\x00\x01\x02", "binary upload")

    assert captured["method"] == "PUT"
    assert "contents/logs/test.bin" in captured["url"]
    assert captured["body"] == {"message": "binary upload", "content": base64.b64encode(b"\x00\x01\x02").decode()}


def test_git_blob_sha_matches_git_blob_spec():
    payload = b"hello\n"

    result = github_mirror.git_blob_sha(payload)

    assert result == "ce013625030ba8dba906f756967f9e9ca394464a"

@pytest.fixture
def log_outbox(monkeypatch, tmp_path):
    """The outbox in this test's directory."""

    root = tmp_path / "outbox"
    monkeypatch.setenv("FIDO_SERVER_GITHUB_OUTBOX_DIR", str(root))
    return root


def _queued_paths(root) -> list[str]:
    if not root.exists():
        return []
    names = sorted(name for name in os.listdir(root) if name.endswith(".entry"))
    return [github_outbox.decode_entry((root / name).read_bytes()).path for name in names]


def _registration(**overrides) -> github_mirror.RegistrationEvent:
    fields = {
        "timestamp": datetime(2025, 10, 23, 9, 41, 10, tzinfo=timezone.utc),
        "rp_id": "example.com",
        "aaguid": uuid.UUID("7701a390-8b53-4ce0-bf7c-b331569b8d1a").bytes,
        "device_name_mds": "Example Authenticator",
        "attestation_object": cbor2.dumps({"test": b"value"}),
        **overrides,
    }
    return github_mirror.RegistrationEvent(**fields)


_LOGGED_PATH = "logs/7701a390-8b53-4ce0-bf7c-b331569b8d1a/20251023T094110Z_abcdef12.json"


def test_a_registration_is_queued_then_delivered_to_its_path(monkeypatch, log_outbox):
    github = fake_github.install(monkeypatch)
    monkeypatch.setattr(github_mirror, "random_shortid", lambda length=8: "abcdef12")
    attestation_object = cbor2.dumps({"test": b"value"})

    github_mirror.record_registration_event(
        _registration(signature_valid=True, root_valid=True, rp_id_hash_valid=True, aaguid_match=True)
    )

    assert list(github.files) == [_LOGGED_PATH]
    [(_path, body)] = github.puts
    assert body["message"] == "add: 20251023T094110Z_abcdef12.json (AAGUID=7701a390-8b53-4ce0-bf7c-b331569b8d1a)"
    payload = json.loads(github.files[_LOGGED_PATH])
    # The file is written as it always was: indented, non-ASCII kept.
    assert github.files[_LOGGED_PATH] == json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    assert payload == {
        "timestamp": "2025-10-23T17:41:10+08:00",
        "rp_id": "example.com",
        "aaguid": "7701a390-8b53-4ce0-bf7c-b331569b8d1a",
        "device_name_mds": "Example Authenticator",
        "raw_attestation_object": github_mirror.to_b64url(attestation_object),
        "decoded_attestation_object": {"test": github_mirror.to_b64url(b"value")},
        "signature_valid": True,
        "root_valid": True,
        "rp_id_hash_valid": True,
        "aaguid_match": True,
    }
    assert _queued_paths(log_outbox) == []


def test_each_registration_is_a_file_of_its_own(monkeypatch, log_outbox):
    github = fake_github.install(monkeypatch)
    short_ids = iter(["firstid", "secondid"])
    monkeypatch.setattr(github_mirror, "random_shortid", lambda length=8: next(short_ids))

    github_mirror.record_registration_event(_registration())
    github_mirror.record_registration_event(_registration(timestamp=datetime(2025, 10, 23, 9, 45, 10, tzinfo=timezone.utc)))

    assert sorted(github.files) == [
        "logs/7701a390-8b53-4ce0-bf7c-b331569b8d1a/20251023T094110Z_firstid.json",
        "logs/7701a390-8b53-4ce0-bf7c-b331569b8d1a/20251023T094510Z_secondid.json",
    ]


def test_a_registration_waits_in_the_outbox_while_github_is_down(monkeypatch, log_outbox, caplog):
    github = fake_github.install(monkeypatch)
    monkeypatch.setattr(github_mirror, "random_shortid", lambda length=8: "abcdef12")
    github.fail.append(fake_github.http_error(503))

    with caplog.at_level(logging.WARNING):
        github_mirror.record_registration_event(_registration())

    assert github.files == {}
    assert _queued_paths(log_outbox) == [_LOGGED_PATH]
    assert f"GitHub could not take {_LOGGED_PATH} now (HTTP 503); it stays queued" in caplog.text

    # Once the outbox may be tried again, the next run delivers it.
    monkeypatch.setattr(github_outbox, "FLUSH", github_outbox.FlushState())
    (log_outbox / ".lease").write_bytes(b"{}")
    github_outbox.schedule_flush(github_mirror.deliver)

    assert list(github.files) == [_LOGGED_PATH]
    assert _queued_paths(log_outbox) == []


def _named_log_entry(name: str) -> OutboxEntry:
    return OutboxEntry("registration", f"logs/unknown/{name}.json", f"add: {name}.json (AAGUID=unknown)", b"{}")


def _queued_attempts(root) -> dict[str, int]:
    names = sorted(name for name in os.listdir(root) if name.endswith(".entry"))
    return {entry.path: entry.attempts for entry in (github_outbox.decode_entry((root / n).read_bytes()) for n in names)}


def test_an_entry_github_never_takes_does_not_hold_back_the_ones_behind_it(monkeypatch, log_outbox, caplog):
    github = fake_github.install(monkeypatch)
    request = github.request

    def _never_takes_stuck(method, url, body=None):
        if method == "PUT" and url.endswith("/stuck.json"):
            raise fake_github.http_error(409, "is at another commit")
        return request(method, url, body)

    monkeypatch.setattr(github_mirror, "_request", _never_takes_stuck)
    github_outbox.enqueue([_named_log_entry("stuck")])

    with caplog.at_level(logging.WARNING):
        for run in range(1, github_outbox.MAX_ATTEMPTS + 1):
            github_outbox.enqueue([_named_log_entry(f"later{run}")])
            github_outbox.flush(github_mirror.deliver)
            # Each run delivers the entry behind the stuck one.
            assert f"logs/unknown/later{run}.json" in github.files
            if run < github_outbox.MAX_ATTEMPTS:
                assert _queued_attempts(log_outbox) == {"logs/unknown/stuck.json": run}

    assert sorted(github.files) == [f"logs/unknown/later{run}.json" for run in range(1, github_outbox.MAX_ATTEMPTS + 1)]
    assert _queued_paths(log_outbox) == []
    assert "Dropped logs/unknown/stuck.json from the credential log" in caplog.text


@pytest.mark.parametrize("status", [503, 401, 429])
def test_an_outage_a_bad_token_or_a_rate_limit_drops_nothing(monkeypatch, log_outbox, status):
    github = fake_github.install(monkeypatch)
    names = [f"e{index}" for index in range(github_outbox.MAX_UNAVAILABLE_IN_A_ROW + 2)]
    github_outbox.enqueue([_named_log_entry(name) for name in names])
    github.fail.extend(fake_github.http_error(status) for _ in range(1_000))
    runs = github_outbox.MAX_ATTEMPTS + 1

    for _run in range(runs):
        (log_outbox / ".lease").write_bytes(b"{}")  # The backoff is over.
        assert github_outbox.flush(github_mirror.deliver).handled == 0

    # Each run stops after a few calls; nothing is counted.
    assert len(github.calls) == runs * github_outbox.MAX_UNAVAILABLE_IN_A_ROW
    assert _queued_attempts(log_outbox) == {f"logs/unknown/{name}.json": 0 for name in names}
    assert json.loads((log_outbox / ".lease").read_bytes())["notBefore"] > 0


def test_the_registration_never_waits_for_github(monkeypatch, log_outbox):
    github = fake_github.install(monkeypatch)
    monkeypatch.setattr(github_outbox, "FLUSH_ASYNC", True)
    at_github, release = threading.Event(), threading.Event()
    request = github.request

    def _slow(method, url, body=None):
        at_github.set()
        assert release.wait(10)
        return request(method, url, body)

    monkeypatch.setattr(github_mirror, "_request", _slow)

    github_mirror.record_registration_event(_registration())

    # It returned while the worker waits on GitHub.
    assert at_github.wait(10)
    assert github.files == {}
    worker = github_outbox.FLUSH.worker
    release.set()
    worker.join(10)
    assert len(github.files) == 1


def test_a_registration_without_a_token_is_not_logged_and_warns_nothing(monkeypatch, log_outbox, caplog):
    monkeypatch.delenv("ENABLE_GITHUB_LOGGING", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    sent = []
    monkeypatch.setattr(github_mirror, "_request", lambda *args, **kwargs: sent.append(args))

    with caplog.at_level(logging.DEBUG):
        github_mirror.record_registration_event(_registration())
        github_mirror.queue_uploaded_metadata_files([("demo.json", b"{}")])

    assert sent == []
    assert not log_outbox.exists()
    assert [record for record in caplog.records if record.levelno >= logging.WARNING] == []


def test_a_registration_s_attestation_object_is_logged_as_fido2_read_it(monkeypatch, log_outbox):
    github = fake_github.install(monkeypatch)
    monkeypatch.setattr(github_mirror, "random_shortid", lambda length=8: "abcdef12")
    auth_data = b"\x01" * 37
    attestation_object = shared_where_fido2_reads_plain_items(auth_data, levels=12)

    github_mirror.record_registration_event(_registration(attestation_object=attestation_object))

    logged = github.files[_LOGGED_PATH]
    # Its shared value is not written out: cbor2's reading took 323 KB of JSON.
    assert len(logged) < 2048
    assert json.loads(logged)["decoded_attestation_object"] == {
        "fmt": "none",
        "attStmt": {},
        "authData": github_mirror.to_b64url(auth_data),
        "x": False,
        "1": github_mirror.to_b64url(cbor.decode(attestation_object)[1]),
    }


def test_a_registration_is_not_logged_while_the_log_is_turned_off(monkeypatch, log_outbox):
    github = fake_github.install(monkeypatch)
    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "0")

    github_mirror.record_registration_event(_registration())

    assert github.calls == []
    assert not log_outbox.exists()


def test_a_registration_whose_entry_cannot_be_built_stands_with_a_warning(monkeypatch, log_outbox, caplog):
    github = fake_github.install(monkeypatch)

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        github_mirror.record_registration_event(_registration(attestation_object=None))

    assert github.calls == []
    assert _queued_paths(log_outbox) == []
    assert "Could not build the credential log entry of a registration for example.com" in caplog.text


def test_a_registration_past_the_outbox_s_bound_starts_no_flush(monkeypatch, log_outbox, caplog):
    github = fake_github.install(monkeypatch)
    monkeypatch.setattr(github_outbox, "MAX_ENTRIES", 0)

    with caplog.at_level(logging.WARNING):
        github_mirror.record_registration_event(_registration())

    assert github.calls == []
    assert "The credential log outbox is full" in caplog.text


def test_the_test_run_never_logs_to_github():
    # tests/conftest.py turns the log off for the whole run.
    assert is_logging_enabled() is False


# A map cut short before its value. (fido2's decoder does not hold a string's length to the
# bytes there: b"not-cbor" reads as the text "ot-cbor".)
CUT_SHORT = b"\xa1\x01"


@pytest.mark.parametrize(
    "payload",
    [CUT_SHORT, "", None],
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


def test_build_log_payload_handles_unknown_aaguid_and_decode_failures(monkeypatch):
    monkeypatch.setattr(github_mirror, "random_shortid", lambda length=8: "abc123")

    event = github_mirror.RegistrationEvent(
        timestamp=datetime(2026, 4, 3, 1, 2, 3, tzinfo=timezone.utc),
        rp_id="example.com",
        aaguid=None,
        device_name_mds=None,
        attestation_object=CUT_SHORT,
    )

    path, payload = github_mirror._build_log_payload(event)

    assert path == "logs/unknown/20260403T010203Z_abc123.json"
    assert payload["aaguid"] == "unknown"
    assert payload["device_name_mds"] == "unknown"
    assert payload["decoded_attestation_object"] == {"error": "decode_failed"}


def test_safe_metadata_repo_filename_sanitizes_traversal_and_invalid_input():
    assert github_mirror._safe_metadata_repo_filename("../../../etc/passwd") == "passwd"
    assert github_mirror._safe_metadata_repo_filename(" /tmp/demo.json ") == "demo.json"
    assert github_mirror._safe_metadata_repo_filename("///") == "metadata.json"
    assert github_mirror._safe_metadata_repo_filename(None) == "metadata.json"


@pytest.mark.parametrize("name", [".", "..", " .. ", "a/.."])
def test_a_metadata_file_named_for_a_folder_is_logged_as_metadata_json(name):
    assert github_mirror._safe_metadata_repo_filename(name) == "metadata.json"


def _deliver_metadata(filename, content):
    return github_mirror.deliver(github_mirror._metadata_entry(filename, content))


def test_uploaded_metadata_files_are_queued_then_delivered_whole(monkeypatch, log_outbox):
    github = fake_github.install(monkeypatch)

    github_mirror.queue_uploaded_metadata_files([("../one.json", b'{"entry":1}'), ("two.json", b'{"entry":2}')])

    assert github.files == {"metadata/one.json": b'{"entry":1}', "metadata/two.json": b'{"entry":2}'}
    assert [body["message"] for _path, body in github.puts] == ["metadata: add one.json", "metadata: add two.json"]
    assert _queued_paths(log_outbox) == []


def test_uploaded_metadata_waits_in_the_outbox_while_github_is_down(monkeypatch, log_outbox):
    github = fake_github.install(monkeypatch)
    github.fail.append(fake_github.http_error(502))

    github_mirror.queue_uploaded_metadata_files([("one.json", b'{"entry":1}')])

    assert github.files == {}
    assert _queued_paths(log_outbox) == ["metadata/one.json"]


def test_no_metadata_is_queued_while_the_log_is_off(monkeypatch, log_outbox):
    github = fake_github.install(monkeypatch)
    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "0")

    github_mirror.queue_uploaded_metadata_files([("demo.json", b"{}")])

    assert github.calls == []
    assert not log_outbox.exists()


def test_an_empty_metadata_file_or_none_queues_nothing(monkeypatch, log_outbox):
    github = fake_github.install(monkeypatch)

    github_mirror.queue_uploaded_metadata_files([("demo.json", b"")])
    github_mirror.queue_uploaded_metadata_files([])

    assert github.calls == []
    assert not log_outbox.exists()


def test_a_metadata_file_over_the_cap_is_not_queued_and_is_said_so(monkeypatch, log_outbox, caplog):
    github = fake_github.install(monkeypatch)
    cap = github_mirror.MAX_LOGGED_METADATA_BYTES

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        github_mirror.queue_uploaded_metadata_files([("at-cap.json", b"a" * cap), ("../over.json", b"o" * (cap + 1))])

    assert sorted(github.files) == ["metadata/at-cap.json"]
    assert (
        f"Not copying metadata file over.json to the credential log: it holds {cap + 1:,} bytes, over the 1 MiB copied"
    ) in caplog.text
    assert "at-cap.json" not in caplog.text


def test_an_uploaded_file_over_the_cap_is_named_on_one_line_however_it_was_named(mds_fixture_snapshot, client, monkeypatch, tmp_path, caplog):
    github = fake_github.install(monkeypatch)
    monkeypatch.setenv("FIDO_SERVER_GITHUB_OUTBOX_DIR", str(tmp_path / "outbox"))
    statement = json.dumps(minimal_entry("Big")).encode()
    content = statement[:-1] + b" " * github_mirror.MAX_LOGGED_METADATA_BYTES + b"}"
    # RFC 7578's filename*: a name a browser's form would not send, but any client can.
    body = (
        f"--b\r\nContent-Disposition: form-data; name=\"files\"; filename*=UTF-8''{quote(FORGED)}\r\n\r\n".encode()
        + content
        + b"\r\n--b--\r\n"
    )

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        response = client.post("/api/mds/metadata/upload", data=body, content_type="multipart/form-data; boundary=b")

    assert response.status_code == 200, response.get_json()
    assert github.files == {}
    message = one_line_naming(caplog, github_mirror.__name__, FORGED)
    assert message.startswith("Not copying metadata file 'x\\nERROR forged line\\r\\x1b[31myyy")
    assert message.endswith(
        f"... ({len(FORGED):,} characters) to the credential log: it holds {len(content):,} bytes, over the 1 MiB copied"
    )


def test_a_registration_for_an_rp_id_of_any_text_is_named_on_one_line(monkeypatch, log_outbox, caplog):
    fake_github.install(monkeypatch)

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        github_mirror.record_registration_event(_registration(rp_id=FORGED, attestation_object=None))

    one_line_naming(caplog, github_mirror.__name__, FORGED)


@pytest.mark.parametrize(
    ("error", "delivery"),
    [
        (fake_github.http_error(503), Delivery.UNAVAILABLE),
        (fake_github.http_error(400), Delivery.DROPPED),
        (URLError("unreachable"), Delivery.UNAVAILABLE),
        (RuntimeError("the mirror broke"), Delivery.DROPPED),
    ],
    ids=["unavailable", "refused", "network", "unexpected"],
)
def test_a_file_github_does_not_take_is_named_on_one_line(monkeypatch, caplog, error, delivery):
    github = fake_github.install(monkeypatch)
    github.fail.append(error)

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert _deliver_metadata(FORGED, b'{"entry":1}') is delivery

    one_line_naming(caplog, github_mirror.__name__, f"metadata/{FORGED}")


def test_a_file_whose_both_paths_are_taken_is_named_on_one_line(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    github.files[f"metadata/{FORGED}"] = b'{"entry":1}'
    hashed = github_mirror._hashed_metadata_path(FORGED, github_mirror.git_blob_sha(b'{"entry":2}'))
    _after_the_tree_read(monkeypatch, github, {hashed: b"something else"})

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert _deliver_metadata(FORGED, b'{"entry":2}') is Delivery.DROPPED

    one_line_naming(caplog, github_mirror.__name__, FORGED, hashed)


def test_a_file_github_does_not_show_yet_is_named_on_one_line(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    github.files["metadata/other.json"] = b"{}"
    _after_the_tree_read(monkeypatch, github, {f"metadata/{FORGED}": b'{"entry":1}'})
    github.unseen.add(f"metadata/{FORGED}")

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert _deliver_metadata(FORGED, b'{"entry":2}') is Delivery.UNAVAILABLE

    message = one_line_naming(caplog, github_mirror.__name__, f"metadata/{FORGED}")
    assert message.endswith("characters) that it does not show yet")


def test_a_file_whose_answer_is_not_json_is_named_on_one_line(monkeypatch, caplog):
    fake_github.install(monkeypatch)
    answers = [fake_github.http_error(404), fake_github.http_error(422, fake_github.SHA_NOT_SUPPLIED), (200, b"not json")]

    def _request(method, url, body=None):
        answer = answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr(github_mirror, "_request", _request)

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert _deliver_metadata(FORGED, b'{"entry":1}') is Delivery.UNAVAILABLE

    message = one_line_naming(caplog, github_mirror.__name__, f"metadata/{FORGED}", f"contents/metadata/{FORGED}")
    assert message.endswith("characters) is not JSON")


def test_metadata_is_added_to_an_empty_repository(monkeypatch):
    github = fake_github.install(monkeypatch)

    assert _deliver_metadata("../../../custom.json", b'{"entry":3}') is Delivery.DELIVERED

    assert github.files == {"metadata/custom.json": b'{"entry":3}'}
    [(path, body)] = github.puts
    assert body["message"] == "metadata: add custom.json"
    assert "sha" not in body


def test_metadata_is_added_to_a_repository_without_a_metadata_folder(monkeypatch):
    github = fake_github.install(monkeypatch)
    github.files["logs/unknown/one.json"] = b"{}"

    assert _deliver_metadata("demo.json", b'{"entry":1}') is Delivery.DELIVERED

    assert github.files["metadata/demo.json"] == b'{"entry":1}'


def test_metadata_already_there_under_another_name_is_not_copied_again(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    github.files["metadata/existing.json"] = b'{"entry":1}'

    with caplog.at_level(logging.INFO, logger=github_mirror.__name__):
        assert _deliver_metadata("demo.json", b'{"entry":1}') is Delivery.DELIVERED

    assert github.puts == []
    assert "identical content already present as existing.json" in caplog.text


def test_metadata_already_there_is_found_past_the_contents_api_s_1000_entries(monkeypatch):
    github = fake_github.install(monkeypatch)
    for index in range(1_500):
        github.files[f"metadata/file-{index:04d}.json"] = f'{{"entry":{index}}}'.encode()

    assert _deliver_metadata("again.json", b'{"entry":1400}') is Delivery.DELIVERED

    assert github.puts == []
    assert ("GET", "git/trees/tree-metadata") in github.calls
    assert ("GET", "contents/metadata") not in github.calls


def test_metadata_in_a_folder_inside_metadata_is_not_the_folder_s_own(monkeypatch):
    github = fake_github.install(monkeypatch)
    github.files["metadata/archive/old.json"] = b'{"entry":1}'

    assert _deliver_metadata("demo.json", b'{"entry":1}') is Delivery.DELIVERED

    assert github.files["metadata/demo.json"] == b'{"entry":1}'


def test_metadata_with_a_taken_name_is_added_beside_it_under_its_hash(monkeypatch):
    github = fake_github.install(monkeypatch)
    github.files["metadata/demo.json"] = b'{"entry":1}'
    content_sha = github_mirror.git_blob_sha(b'{"entry":2}')
    hashed = f"metadata/demo-{content_sha[:12]}.json"

    assert _deliver_metadata(" demo.json ", b'{"entry":2}') is Delivery.DELIVERED

    assert github.files == {"metadata/demo.json": b'{"entry":1}', hashed: b'{"entry":2}'}
    [(_path, body)] = github.puts
    assert body["message"] == f"metadata: add {hashed.removeprefix('metadata/')}"
    assert "sha" not in body


def test_a_hashed_name_keeps_a_name_without_an_extension():
    assert github_mirror._hashed_metadata_path("statement", "0123456789abcdef") == "metadata/statement-0123456789ab"


def _after_the_tree_read(monkeypatch, github, files):
    """Have ``files`` appear once the metadata folder's tree has been read, as another copy landing then would."""

    answer = github._tree

    def _tree(folder):
        result = answer(folder)
        github.files.update(files)
        return result

    monkeypatch.setattr(github, "_tree", _tree)


def test_a_name_taken_after_the_tree_was_read_sends_the_file_to_its_hashed_name(monkeypatch):
    github = fake_github.install(monkeypatch)
    github.files["metadata/other.json"] = b"{}"
    _after_the_tree_read(monkeypatch, github, {"metadata/demo.json": b'{"entry":1}'})
    hashed = github_mirror._hashed_metadata_path("demo.json", github_mirror.git_blob_sha(b'{"entry":2}'))

    assert _deliver_metadata("demo.json", b'{"entry":2}') is Delivery.DELIVERED

    assert github.files["metadata/demo.json"] == b'{"entry":1}'
    assert github.files[hashed] == b'{"entry":2}'


def test_a_copy_that_landed_after_the_tree_was_read_is_not_made_twice(monkeypatch):
    github = fake_github.install(monkeypatch)
    github.files["metadata/other.json"] = b"{}"
    _after_the_tree_read(monkeypatch, github, {"metadata/demo.json": b'{"entry":1}'})

    assert _deliver_metadata("demo.json", b'{"entry":1}') is Delivery.DELIVERED

    assert sorted(github.files) == ["metadata/demo.json", "metadata/other.json"]


def test_a_taken_name_github_does_not_show_yet_adds_nothing(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    github.files["metadata/other.json"] = b"{}"
    _after_the_tree_read(monkeypatch, github, {"metadata/demo.json": b'{"entry":1}'})
    github.unseen.add("metadata/demo.json")

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert _deliver_metadata("demo.json", b'{"entry":2}') is Delivery.UNAVAILABLE

    assert sorted(github.files) == ["metadata/demo.json", "metadata/other.json"]
    assert "does not show yet" in caplog.text
    assert "it stays queued" in caplog.text


def test_a_hashed_name_holding_the_same_content_adds_nothing(monkeypatch):
    github = fake_github.install(monkeypatch)
    github.files["metadata/demo.json"] = b'{"entry":1}'
    hashed = github_mirror._hashed_metadata_path("demo.json", github_mirror.git_blob_sha(b'{"entry":2}'))
    _after_the_tree_read(monkeypatch, github, {hashed: b'{"entry":2}'})

    assert _deliver_metadata("demo.json", b'{"entry":2}') is Delivery.DELIVERED

    assert github.puts == []


def test_a_hashed_name_holding_other_content_is_left_alone(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    github.files["metadata/demo.json"] = b'{"entry":1}'
    hashed = github_mirror._hashed_metadata_path("demo.json", github_mirror.git_blob_sha(b'{"entry":2}'))
    _after_the_tree_read(monkeypatch, github, {hashed: b"something else"})

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert _deliver_metadata("demo.json", b'{"entry":2}') is Delivery.DROPPED

    assert github.files[hashed] == b"something else"
    assert f"another file is at {hashed}" in caplog.text


def test_a_422_that_is_not_about_a_file_there_is_a_refusal(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    real = github.request

    def _refuse_puts(method, url, body=None):
        if method == "PUT":
            raise fake_github.http_error(422, "Invalid request. path is not valid")
        return real(method, url, body)

    monkeypatch.setattr(github_mirror, "_request", _refuse_puts)

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert _deliver_metadata("demo.json", b"{}") is Delivery.DROPPED

    assert "GitHub refused metadata/demo.json (HTTP 422): dropped" in caplog.text
    assert ("GET", "contents/metadata/demo.json") not in github.calls


@pytest.mark.parametrize("body", [None, b"not json", b"[]", b'{"message": 3}', b'{"message": "no file"}'])
def test_a_422_says_a_file_is_there_only_when_its_message_names_the_sha(body):
    error = HTTPError("https://api.github.com/", 422, "Unprocessable", None, io.BytesIO(body) if body else None)

    assert github_mirror._says_sha_was_not_supplied(error) is False


def test_a_422_naming_the_sha_says_a_file_is_there():
    assert github_mirror._says_sha_was_not_supplied(fake_github.http_error(422, fake_github.SHA_NOT_SUPPLIED)) is True


def test_a_tree_github_cuts_short_is_logged_and_read(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    github.files["metadata/existing.json"] = b'{"entry":1}'
    answer = github._tree

    def _truncated(folder):
        status, body = answer(folder)
        return status, json.dumps({**json.loads(body), "truncated": True}).encode()

    monkeypatch.setattr(github, "_tree", _truncated)

    with caplog.at_level(logging.INFO, logger=github_mirror.__name__):
        assert _deliver_metadata("demo.json", b'{"entry":1}') is Delivery.DELIVERED

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
        assert _deliver_metadata("demo.json", b"{}") is Delivery.UNAVAILABLE

    assert puts == []
    assert "GitHub could not take metadata/demo.json now; it stays queued" in caplog.text


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
        assert _deliver_metadata("demo.json", b"{}") is Delivery.UNAVAILABLE

    assert github.puts == []
    assert "GitHub could not take metadata/demo.json now (HTTP 503); it stays queued" in caplog.text


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
        assert _deliver_metadata("demo.json", b"{}") is Delivery.UNAVAILABLE

    assert "GitHub could not take metadata/demo.json now (HTTP 500); it stays queued" in caplog.text


def test_the_same_content_delivered_lately_under_another_name_is_not_copied_twice(monkeypatch):
    github = fake_github.install(monkeypatch)
    clock = types.SimpleNamespace(now=1_000.0)
    monkeypatch.setattr(github_mirror, "time", types.SimpleNamespace(time=lambda: clock.now, sleep=lambda _s: None))

    assert _deliver_metadata("first.json", b'{"entry":1}') is Delivery.DELIVERED
    del github.files["metadata/first.json"]  # A tree read just after a delivery may not show it yet.

    assert _deliver_metadata("second.json", b'{"entry":1}') is Delivery.DELIVERED
    assert sorted(github.files) == []

    clock.now += 601
    assert _deliver_metadata("second.json", b'{"entry":1}') is Delivery.DELIVERED
    assert sorted(github.files) == ["metadata/second.json"]


def _log_entry(content: bytes = b'{"rp_id": "example.com"}') -> OutboxEntry:
    return OutboxEntry(
        "registration", "logs/unknown/20260403T010203Z_abc123.json", "add: 20260403T010203Z_abc123.json (AAGUID=unknown)", content
    )


def test_a_log_entry_is_delivered_to_its_path(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)

    with caplog.at_level(logging.INFO, logger=github_mirror.__name__):
        assert github_mirror.deliver(_log_entry()) is Delivery.DELIVERED

    assert github.files == {"logs/unknown/20260403T010203Z_abc123.json": b'{"rp_id": "example.com"}'}
    [(_path, body)] = github.puts
    assert body["message"] == "add: 20260403T010203Z_abc123.json (AAGUID=unknown)"
    assert "Delivered logs/unknown/20260403T010203Z_abc123.json to the credential log" in caplog.text


def test_a_log_entry_delivered_again_finds_its_file_and_makes_no_second(monkeypatch):
    github = fake_github.install(monkeypatch)
    assert github_mirror.deliver(_log_entry()) is Delivery.DELIVERED

    assert github_mirror.deliver(_log_entry()) is Delivery.DELIVERED

    assert list(github.files) == ["logs/unknown/20260403T010203Z_abc123.json"]
    assert len(github.puts) == 1


def test_a_log_entry_whose_file_github_does_not_show_yet_counts_as_there(monkeypatch):
    github = fake_github.install(monkeypatch)
    assert github_mirror.deliver(_log_entry()) is Delivery.DELIVERED
    github.unseen.add("logs/unknown/20260403T010203Z_abc123.json")

    assert github_mirror.deliver(_log_entry()) is Delivery.DELIVERED

    assert len(github.puts) == 1


def test_a_log_entry_whose_path_holds_another_file_is_dropped(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    github.files["logs/unknown/20260403T010203Z_abc123.json"] = b"another registration"

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert github_mirror.deliver(_log_entry()) is Delivery.DROPPED

    assert github.files["logs/unknown/20260403T010203Z_abc123.json"] == b"another registration"
    assert "the log repository holds another file at its path" in caplog.text


@pytest.mark.parametrize(
    ("error", "delivery"),
    [
        (fake_github.http_error(401), Delivery.UNAVAILABLE),
        (fake_github.http_error(403, "API rate limit exceeded"), Delivery.UNAVAILABLE),
        (fake_github.http_error(404), Delivery.UNAVAILABLE),
        (fake_github.http_error(408), Delivery.UNAVAILABLE),
        (fake_github.http_error(409, "is at abc but expected def"), Delivery.UNAVAILABLE),
        (fake_github.http_error(429), Delivery.UNAVAILABLE),
        (fake_github.http_error(500), Delivery.UNAVAILABLE),
        (fake_github.http_error(502), Delivery.UNAVAILABLE),
        (fake_github.http_error(503), Delivery.UNAVAILABLE),
        (fake_github.http_error(400), Delivery.DROPPED),
        (fake_github.http_error(410), Delivery.DROPPED),
        (fake_github.http_error(413), Delivery.DROPPED),
        (fake_github.http_error(422, "Invalid request. content is not valid Base64"), Delivery.DROPPED),
        (URLError("network down"), Delivery.UNAVAILABLE),
        (URLError(TimeoutError("timed out")), Delivery.UNAVAILABLE),
        (TimeoutError("timed out"), Delivery.UNAVAILABLE),
        (ConnectionResetError("reset"), Delivery.UNAVAILABLE),
        (http.client.IncompleteRead(b""), Delivery.UNAVAILABLE),
        (github_mirror.GitHubUnavailable("not JSON"), Delivery.UNAVAILABLE),
        (ValueError("a bug"), Delivery.DROPPED),
    ],
)
def test_what_github_answers_decides_whether_an_entry_waits_or_is_dropped(monkeypatch, caplog, error, delivery):
    github = fake_github.install(monkeypatch)
    github.fail.append(error)

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert github_mirror.deliver(_log_entry()) is delivery

    assert github.files == {}
    assert ("stays queued" in caplog.text) is (delivery is Delivery.UNAVAILABLE)


def test_an_entry_waits_while_there_is_no_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        github_mirror.urllib_request, "urlopen", lambda *_args, **_kwargs: pytest.fail("a request without a token was sent")
    )

    assert github_mirror.deliver(_log_entry()) is Delivery.UNAVAILABLE


def test_a_request_flushes_the_outbox_while_the_log_is_on(make_app, monkeypatch, tmp_path):
    github = fake_github.install(monkeypatch)
    monkeypatch.setenv("FIDO_SERVER_GITHUB_OUTBOX_DIR", str(tmp_path / "outbox"))
    assert github_outbox.enqueue([_log_entry()]) == 1

    assert make_app().test_client().get("/health").status_code == 200

    assert list(github.files) == [_log_entry().path]
    assert [name for name in os.listdir(tmp_path / "outbox") if name.endswith(".entry")] == []


def test_no_request_flushes_while_the_log_is_off(make_app, monkeypatch, tmp_path):
    github = fake_github.install(monkeypatch)
    monkeypatch.setenv("FIDO_SERVER_GITHUB_OUTBOX_DIR", str(tmp_path / "outbox"))
    github_outbox.enqueue([_log_entry()])
    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "0")

    assert make_app().test_client().get("/health").status_code == 200

    assert github.calls == []
    assert len([name for name in os.listdir(tmp_path / "outbox") if name.endswith(".entry")]) == 1


def test_a_flush_that_cannot_start_never_fails_the_request(make_app, monkeypatch, caplog):
    fake_github.install(monkeypatch)

    def _cannot_start(_deliver, **_kwargs):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(github_outbox, "schedule_flush", _cannot_start)

    with caplog.at_level(logging.WARNING, logger=github_mirror.__name__):
        assert make_app().test_client().get("/health").status_code == 200

    assert "Could not start flushing the credential log outbox" in caplog.text


def test_a_delivered_file_is_named_on_one_line(monkeypatch, caplog):
    fake_github.install(monkeypatch)

    with caplog.at_level(logging.INFO, logger=github_mirror.__name__):
        assert _deliver_metadata(FORGED, b'{"entry":1}') is Delivery.DELIVERED

    message = one_line_naming(caplog, github_mirror.__name__, f"metadata/{FORGED}")
    assert message.startswith("Delivered ")


def test_a_file_already_in_the_log_is_named_on_one_line_with_its_copy(monkeypatch, caplog):
    github = fake_github.install(monkeypatch)
    there = "copy\nERROR forged line.json"
    github.files[f"metadata/{there}"] = b'{"entry":1}'

    with caplog.at_level(logging.INFO, logger=github_mirror.__name__):
        assert _deliver_metadata(FORGED, b'{"entry":1}') is Delivery.DELIVERED

    message = one_line_naming(caplog, github_mirror.__name__, FORGED, there)
    assert message.startswith("Skipping upload of metadata file ")


def test_an_entry_passed_over_is_named_on_one_line(monkeypatch, log_outbox, caplog):
    github = fake_github.install(monkeypatch)
    request = github.request

    def _never_takes_the_forged_file(method, url, body=None):
        if method == "PUT" and "ERROR" in url:
            raise fake_github.http_error(409, "is at another commit")
        return request(method, url, body)

    monkeypatch.setattr(github_mirror, "_request", _never_takes_the_forged_file)
    github_outbox.enqueue([github_mirror._metadata_entry(FORGED, b'{"entry":1}'), _named_log_entry("later")])

    with caplog.at_level(logging.INFO, logger=github_outbox.__name__):
        github_outbox.flush(github_mirror.deliver)

    assert "logs/unknown/later.json" in github.files
    message = one_line_naming(caplog, github_outbox.__name__, f"metadata/{FORGED}")
    assert message.startswith("GitHub took a later entry but not ")
