from __future__ import annotations

import builtins
import gzip
from pathlib import Path
import types
from unittest import mock

from flask import Flask
import pytest

import server.app.config as config_module


def test_discover_project_root_fallback_when_frontend_not_found(monkeypatch):
    monkeypatch.setattr(Path, "is_dir", lambda self: False, raising=False)

    package_root = Path("/tmp/postquantum/server/app")
    assert config_module._discover_project_root(package_root) == package_root.parents[1]


def test_resolve_secret_key_handles_read_oserror_and_makedirs_failure(monkeypatch):
    fake_app = types.SimpleNamespace(instance_path="/virtual-instance", logger=mock.Mock())
    monkeypatch.setattr(config_module, "app", fake_app, raising=False)

    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY", raising=False)
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY_FILE", raising=False)

    def _open_read_error(path, mode="r", *args, **kwargs):
        if "rb" in mode:
            raise OSError("read failure")
        raise AssertionError("unexpected write open")

    def _raise_makedirs(*_args, **_kwargs):
        raise OSError("mkdir failure")

    monkeypatch.setattr(builtins, "open", _open_read_error)
    monkeypatch.setattr(config_module.os, "urandom", lambda size: b"S" * size)
    monkeypatch.setattr(config_module.os, "makedirs", _raise_makedirs)

    assert config_module._resolve_secret_key() == b"S" * 32


def test_resolve_secret_key_replace_failure_cleanup_paths(monkeypatch):
    fake_app = types.SimpleNamespace(instance_path="/virtual-instance", logger=mock.Mock())
    monkeypatch.setattr(config_module, "app", fake_app, raising=False)

    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY", raising=False)
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY_FILE", raising=False)

    class _DummyTarget:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def write(self, _data):
            return None

        def flush(self):
            return None

        def fileno(self):
            return 7

    def _open_missing(path, mode="r", *args, **kwargs):
        if "rb" in mode:
            raise FileNotFoundError(path)
        raise AssertionError("unexpected builtin open write")

    def _replace_failure(*_args, **_kwargs):
        raise OSError("replace failed")

    unlink_calls = []

    def _unlink_failure(path):
        unlink_calls.append(path)
        raise OSError("unlink failed")

    monkeypatch.setattr(builtins, "open", _open_missing)
    monkeypatch.setattr(config_module.os, "urandom", lambda size: b"T" * size)
    monkeypatch.setattr(config_module.os, "makedirs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(config_module.tempfile, "mkstemp", lambda **_kwargs: (42, "/tmp/session-secret.tmp"))
    monkeypatch.setattr(config_module.os, "fdopen", lambda _fd, _mode: _DummyTarget())
    monkeypatch.setattr(config_module.os, "fsync", lambda _fd: None)
    monkeypatch.setattr(config_module.os, "replace", _replace_failure)
    monkeypatch.setattr(config_module.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(config_module.os, "unlink", _unlink_failure)

    assert config_module._resolve_secret_key() == b"T" * 32
    assert unlink_calls


def test_response_compression_paths_and_accepts_gzip_guard(monkeypatch):
    app = config_module.app

    assert config_module._accepts_gzip() is False

    with app.test_request_context("/", headers={"Accept-Encoding": "gzip"}):
        app.config["RESPONSE_COMPRESSION_MIN_SIZE"] = 1

        payload = b"A" * 1024
        response = app.response_class(payload, status=200, mimetype="text/plain")
        response.direct_passthrough = True
        response.headers["ETag"] = "etag"
        response.headers["Content-MD5"] = "digest"

        compressed = config_module.maybe_compress_response(response)
        assert compressed.headers["Content-Encoding"] == "gzip"
        assert "Accept-Encoding" in compressed.headers["Vary"]
        assert compressed.direct_passthrough is False
        assert "ETag" not in compressed.headers
        assert "Content-MD5" not in compressed.headers
        assert gzip.decompress(compressed.get_data()) == payload

        monkeypatch.setattr(
            config_module.gzip,
            "compress",
            lambda data, compresslevel=6: data + b"not-smaller",
        )
        unchanged = app.response_class(payload, status=200, mimetype="text/plain")
        assert config_module.maybe_compress_response(unchanged).headers.get("Content-Encoding") is None

        already_encoded = app.response_class(payload, status=200, mimetype="text/plain")
        already_encoded.headers["Content-Encoding"] = "br"
        assert config_module.maybe_compress_response(already_encoded) is already_encoded

        non_2xx = app.response_class(payload, status=304, mimetype="text/plain")
        assert config_module.maybe_compress_response(non_2xx) is non_2xx

        non_text = app.response_class(payload, status=200, mimetype="application/octet-stream")
        assert config_module.maybe_compress_response(non_text) is non_text


def test_register_after_request_once_guard_paths(monkeypatch):
    flask_app = Flask("config-branch-guards")
    marker = config_module._RESPONSE_COMPRESSION_MARKER

    calls = []
    monkeypatch.setattr(flask_app, "after_request", lambda handler: calls.append(handler), raising=False)

    existing = lambda response: response
    setattr(existing, marker, True)
    flask_app.after_request_funcs.setdefault(None, []).append(existing)

    config_module._register_after_request_once(flask_app, lambda response: response)
    assert calls == []

    flask_app.after_request_funcs[None] = []
    monkeypatch.setattr(flask_app, "_got_first_request", True, raising=False)
    config_module._register_after_request_once(flask_app, lambda response: response)
    assert calls == []

    monkeypatch.setattr(flask_app, "_got_first_request", False, raising=False)
    handler = lambda response: response
    config_module._register_after_request_once(flask_app, handler)
    assert calls == [handler]


def test_parse_fingerprints_and_host_normalization_branches(monkeypatch):
    assert config_module._parse_trusted_ca_fingerprints(None) is None
    assert config_module._parse_trusted_ca_fingerprints("ab:cd") is None

    long_fp = ":".join(["aa"] * 20)
    parsed = config_module._parse_trusted_ca_fingerprints(f"{long_fp}, short")
    assert parsed == {"AA" * 20}

    monkeypatch.setitem(config_module.app.config, "FIDO_SERVER_RP_ID", "  configured.example  ")
    assert config_module.determine_rp_id() == "configured.example"

    assert config_module._normalise_request_host(None) is None
    assert config_module._normalise_request_host("   ") is None
    assert config_module._normalise_request_host("[2001:db8::1]:8443") == "2001:db8::1"
    assert config_module._normalise_request_host("2001:db8::1") == "2001:db8::1"
    assert config_module._normalise_request_host("Example.COM:8443") == "example.com"
    assert config_module._normalise_request_host("bad host") == "bad host"

    assert config_module._resolve_request_host() is None

    with config_module.app.test_request_context(
        "/",
        headers={"Host": ""},
        environ_overrides={"HTTP_HOST": "api.example", "SERVER_NAME": "fallback.example"},
    ):
        assert config_module._resolve_request_host() == "api.example"

    with config_module.app.test_request_context(
        "/",
        headers={"Host": ""},
        environ_overrides={"HTTP_HOST": "", "SERVER_NAME": ""},
    ):
        assert config_module._resolve_request_host() is None
