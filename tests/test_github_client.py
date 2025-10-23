import base64
import json

from urllib import error as urllib_error

from server.server import github_client


def test_github_upload_json_uses_pretty_format(monkeypatch):
    captured = {}

    def fake_request(method, url, body=None):
        captured["method"] = method
        captured["url"] = url
        captured["body"] = body
        return 200, b"{}"

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(github_client, "_request", fake_request)

    github_client.github_upload_json("logs/example_unknown.json", {"key": "value"})

    encoded = captured["body"]["content"]
    decoded = base64.b64decode(encoded).decode("utf-8")
    assert decoded.startswith("{\n")
    assert "\n  \"key\": \"value\"\n" in decoded
    assert decoded.endswith("\n")
    assert captured["body"]["message"].startswith("add:")


def test_github_get_json_returns_payload(monkeypatch):
    payload = {
        "content": base64.b64encode(json.dumps({"a": 1}).encode("utf-8")).decode("ascii"),
        "encoding": "base64",
        "sha": "sha123",
    }

    def fake_request(method, url, body=None):
        assert method == "GET"
        return 200, json.dumps(payload).encode("utf-8")

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(github_client, "_request", fake_request)

    data, sha = github_client.github_get_json("logs/example.json")
    assert data == {"a": 1}
    assert sha == "sha123"


def test_github_get_json_404(monkeypatch):
    def fake_request(method, url, body=None):
        raise urllib_error.HTTPError(url, 404, "Not Found", hdrs=None, fp=None)

    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(github_client, "_request", fake_request)

    assert github_client.github_get_json("logs/missing.json") is None
