"""Tests for the GitHub client module."""
import base64
import io
import json
import sys
import types
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

_ROOT = Path(__file__).resolve().parents[2]

server_pkg = types.ModuleType("server")
server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", server_pkg)

server_server_pkg = types.ModuleType("server.app")
server_server_pkg.__path__ = [str(_ROOT / "server" / "app")]
sys.modules.setdefault("server.app", server_server_pkg)

from server.app import github_client
from server.app.github_client import is_logging_enabled


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


def test_is_logging_enabled_default(monkeypatch):
    """Test that logging is enabled by default when no env vars are set."""
    monkeypatch.delenv("ENABLE_GITHUB_LOGGING", raising=False)
    assert is_logging_enabled() is True


def test_is_logging_enabled_explicit_true(monkeypatch):
    """Test that logging is enabled when ENABLE_GITHUB_LOGGING is truthy."""
    for value in ("1", "true", "yes", "on", "True", "YES", "ON"):
        monkeypatch.setenv("ENABLE_GITHUB_LOGGING", value)
        assert is_logging_enabled() is True, f"Expected True for value '{value}'"


def test_is_logging_enabled_explicit_false(monkeypatch):
    """Test that logging is disabled when ENABLE_GITHUB_LOGGING is falsy."""
    for value in ("0", "false", "no", "off", "False", "NO", "OFF"):
        monkeypatch.setenv("ENABLE_GITHUB_LOGGING", value)
        assert is_logging_enabled() is False, f"Expected False for value '{value}'"


def test_is_logging_enabled_empty_string(monkeypatch):
    """Test that logging is disabled when ENABLE_GITHUB_LOGGING is an empty string."""
    monkeypatch.setenv("ENABLE_GITHUB_LOGGING", "")
    assert is_logging_enabled() is False


def test_api_url_uses_default_log_repository(monkeypatch):
    monkeypatch.delenv("GITHUB_LOG_REPO_OWNER", raising=False)
    monkeypatch.delenv("GITHUB_LOG_REPO_NAME", raising=False)

    assert github_client._api_url("contents/logs/example.json") == (
        "https://api.github.com/repos/rainzhang05/CredentialLogs/contents/logs/example.json"
    )


def test_api_url_uses_repo_env_override(monkeypatch):
    monkeypatch.setenv("GITHUB_LOG_REPO_OWNER", "example-owner")
    monkeypatch.setenv("GITHUB_LOG_REPO_NAME", "example-repo")

    assert github_client._api_url("contents/logs/example.json") == (
        "https://api.github.com/repos/example-owner/example-repo/contents/logs/example.json"
    )


def test_credential_log_repository_falls_back_when_env_values_are_blank(monkeypatch):
    monkeypatch.setenv("GITHUB_LOG_REPO_OWNER", "   ")
    monkeypatch.setenv("GITHUB_LOG_REPO_NAME", "")

    owner, repo = github_client.credential_log_repository()

    assert owner == "rainzhang05"
    assert repo == "CredentialLogs"


def test_credential_log_repository_strips_env_values(monkeypatch):
    monkeypatch.setenv("GITHUB_LOG_REPO_OWNER", "  custom-owner  ")
    monkeypatch.setenv("GITHUB_LOG_REPO_NAME", "  custom-repo  ")

    owner, repo = github_client.credential_log_repository()

    assert owner == "custom-owner"
    assert repo == "custom-repo"


def test_token_returns_value_when_present(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")

    assert github_client._token() == "secret-token"


def test_token_raises_with_repository_context_when_missing(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_LOG_REPO_OWNER", "owner-a")
    monkeypatch.setenv("GITHUB_LOG_REPO_NAME", "repo-a")

    with pytest.raises(RuntimeError, match="owner-a/repo-a"):
        github_client._token()


def test_encode_content_returns_base64_ascii():
    data = b"hello-world"

    encoded = github_client._encode_content(data)

    assert encoded == base64.b64encode(data).decode("ascii")


def test_request_sets_expected_headers_and_json_body(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")

    captured = {}

    def _fake_urlopen(request_obj):
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

    monkeypatch.setattr(github_client.urllib_request, "urlopen", _fake_urlopen)

    status, body = github_client._request(
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

    def _fake_urlopen(_request_obj):
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

    monkeypatch.setattr(github_client.urllib_request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(github_client.time, "sleep", lambda seconds: sleeps.append(seconds))

    status, body = github_client._request("GET", "https://api.github.com/example")

    assert calls["count"] == 2
    assert sleeps == [1]
    assert status == 200
    assert body == b"ok"


def test_request_does_not_retry_on_4xx_http_error(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")

    calls = {"count": 0}
    sleeps = []

    def _fake_urlopen(_request_obj):
        calls["count"] += 1
        raise HTTPError(
            url="https://api.github.com/example",
            code=400,
            msg="Bad Request",
            hdrs=None,
            fp=io.BytesIO(b"invalid"),
        )

    monkeypatch.setattr(github_client.urllib_request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(github_client.time, "sleep", lambda seconds: sleeps.append(seconds))

    with pytest.raises(HTTPError):
        github_client._request("GET", "https://api.github.com/example")

    assert calls["count"] == 1
    assert sleeps == []


def test_request_retries_once_on_url_error(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")

    calls = {"count": 0}
    sleeps = []

    def _fake_urlopen(_request_obj):
        calls["count"] += 1
        if calls["count"] == 1:
            raise URLError("network down")
        return _FakeResponse(status=200, body=b"ok")

    monkeypatch.setattr(github_client.urllib_request, "urlopen", _fake_urlopen)
    monkeypatch.setattr(github_client.time, "sleep", lambda seconds: sleeps.append(seconds))

    status, body = github_client._request("GET", "https://api.github.com/example")

    assert calls["count"] == 2
    assert sleeps == [1]
    assert status == 200
    assert body == b"ok"


def test_request_raises_after_retrying_url_error(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "token-123")
    sleeps = []

    monkeypatch.setattr(
        github_client.urllib_request,
        "urlopen",
        lambda _request_obj: (_ for _ in ()).throw(URLError("still down")),
    )
    monkeypatch.setattr(github_client.time, "sleep", lambda seconds: sleeps.append(seconds))

    with pytest.raises(URLError):
        github_client._request("GET", "https://api.github.com/example")

    assert sleeps == [1]


def test_github_get_json_decodes_base64_payload_and_returns_sha(monkeypatch):
    payload = {"hello": "world"}
    encoded_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    response_body = {
        "encoding": "base64",
        "content": encoded_payload,
        "sha": "abc123",
    }

    monkeypatch.setattr(
        github_client,
        "_request",
        lambda _method, _url: (200, json.dumps(response_body).encode("utf-8")),
    )

    parsed, sha = github_client.github_get_json("logs/example.json")

    assert parsed == payload
    assert sha == "abc123"


def test_github_get_json_translates_404_to_file_not_found(monkeypatch):
    monkeypatch.setattr(
        github_client,
        "_request",
        lambda _method, _url: (_ for _ in ()).throw(
            HTTPError(
                url="https://api.github.com/example",
                code=404,
                msg="Not Found",
                hdrs=None,
                fp=io.BytesIO(b""),
            )
        ),
    )

    with pytest.raises(FileNotFoundError, match="logs/missing.json"):
        github_client.github_get_json("logs/missing.json")


def test_github_get_json_raises_on_unexpected_encoding(monkeypatch):
    response_body = {"encoding": "utf-8", "content": "{}", "sha": "abc123"}

    monkeypatch.setattr(
        github_client,
        "_request",
        lambda _method, _url: (200, json.dumps(response_body).encode("utf-8")),
    )

    with pytest.raises(RuntimeError, match="Unexpected response"):
        github_client.github_get_json("logs/example.json")


def test_github_get_json_raises_when_sha_missing(monkeypatch):
    payload = {"encoding": "base64", "content": base64.b64encode(b"{}").decode("ascii")}

    monkeypatch.setattr(
        github_client,
        "_request",
        lambda _method, _url: (200, json.dumps(payload).encode("utf-8")),
    )

    with pytest.raises(RuntimeError, match="Missing SHA"):
        github_client.github_get_json("logs/example.json")


def test_github_upload_json_builds_add_message_and_base64_content(monkeypatch):
    captured = {}

    def _fake_request(method, url, body=None):
        captured["method"] = method
        captured["url"] = url
        captured["body"] = body
        return 200, b"{}"

    monkeypatch.setattr(github_client, "_request", _fake_request)

    github_client.github_upload_json("logs/aaguid-1/file.json", {"k": 1})

    assert captured["method"] == "PUT"
    assert "contents/logs/aaguid-1/file.json" in captured["url"]
    assert captured["body"]["message"] == "add: file.json (AAGUID=aaguid-1)"
    decoded = base64.b64decode(captured["body"]["content"]).decode("utf-8")
    assert json.loads(decoded) == {"k": 1}
    assert "sha" not in captured["body"]


def test_github_upload_json_builds_update_message_when_sha_provided(monkeypatch):
    captured = {}

    def _fake_request(method, url, body=None):
        captured["method"] = method
        captured["url"] = url
        captured["body"] = body
        return 200, b"{}"

    monkeypatch.setattr(github_client, "_request", _fake_request)

    github_client.github_upload_json("logs/aaguid-2/file.json", {"k": 2}, sha="old-sha")

    assert captured["body"]["message"] == "update: file.json (AAGUID=aaguid-2)"
    assert captured["body"]["sha"] == "old-sha"


def test_github_upload_file_passes_message_content_and_optional_sha(monkeypatch):
    captured = {}

    def _fake_request(method, url, body=None):
        captured["method"] = method
        captured["url"] = url
        captured["body"] = body
        return 200, b"{}"

    monkeypatch.setattr(github_client, "_request", _fake_request)

    github_client.github_upload_file(
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


def test_github_list_directory_returns_list_payload(monkeypatch):
    directory_payload = [{"name": "a.json"}, {"name": "b.json"}]

    monkeypatch.setattr(
        github_client,
        "_request",
        lambda _method, _url: (200, json.dumps(directory_payload).encode("utf-8")),
    )

    result = github_client.github_list_directory("logs")

    assert result == directory_payload


def test_github_list_directory_returns_empty_list_on_404(monkeypatch):
    monkeypatch.setattr(
        github_client,
        "_request",
        lambda _method, _url: (_ for _ in ()).throw(
            HTTPError(
                url="https://api.github.com/example",
                code=404,
                msg="Not Found",
                hdrs=None,
                fp=io.BytesIO(b""),
            )
        ),
    )

    assert github_client.github_list_directory("missing") == []


def test_github_list_directory_raises_on_non_list_response(monkeypatch):
    monkeypatch.setattr(
        github_client,
        "_request",
        lambda _method, _url: (200, json.dumps({"unexpected": True}).encode("utf-8")),
    )

    with pytest.raises(RuntimeError, match="Unexpected response listing directory"):
        github_client.github_list_directory("logs")


def test_git_blob_sha_matches_git_blob_spec():
    payload = b"hello\n"

    result = github_client.git_blob_sha(payload)

    assert result == "ce013625030ba8dba906f756967f9e9ca394464a"
