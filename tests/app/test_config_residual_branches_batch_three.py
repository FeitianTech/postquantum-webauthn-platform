from __future__ import annotations

import importlib
import io
from types import SimpleNamespace

import pytest

import server.app.config as config_module


def test_resolve_secret_key_reads_empty_stored_key_and_generates(monkeypatch):
    fake_app = SimpleNamespace(instance_path="/virtual-instance", logger=SimpleNamespace(warning=lambda *a, **k: None))
    monkeypatch.setattr(config_module, "app", fake_app, raising=False)

    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY", raising=False)
    monkeypatch.delenv("FIDO_SERVER_SECRET_KEY_FILE", raising=False)
    monkeypatch.setattr(config_module.os, "urandom", lambda size: b"Z" * size)
    monkeypatch.setattr(config_module.os, "makedirs", lambda *_a, **_k: None)
    monkeypatch.setattr(
        config_module.tempfile,
        "mkstemp",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("skip write")),
    )

    def _open_empty_read(path, mode="r", *args, **kwargs):
        if "rb" in mode:
            return io.BytesIO(b"")
        raise AssertionError(f"unexpected open mode: {mode} for {path}")

    monkeypatch.setattr(config_module, "open", _open_empty_read, raising=False)

    assert config_module._resolve_secret_key() == b"Z" * 32


def test_maybe_compress_response_returns_early_for_small_payload():
    app = config_module.app

    with app.test_request_context("/", headers={"Accept-Encoding": "gzip"}):
        app.config["RESPONSE_COMPRESSION_MIN_SIZE"] = 64
        response = app.response_class(b"tiny", status=200, mimetype="text/plain")
        compressed = config_module.maybe_compress_response(response)

    assert compressed.headers.get("Content-Encoding") is None
    assert compressed.get_data() == b"tiny"


def test_config_reload_applies_session_metadata_recover_env(monkeypatch):
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_RECOVER", "1")
    reloaded = importlib.reload(config_module)

    assert reloaded.app.config["SESSION_METADATA_RECOVER_ON_START"] is True


def test_determine_rp_id_handles_missing_host_and_loopback_fallback(monkeypatch):
    with config_module.app.test_request_context(
        "/",
        headers={"Host": ""},
        environ_overrides={"HTTP_HOST": "", "SERVER_NAME": ""},
    ):
        assert config_module.determine_rp_id() == "localhost"

    monkeypatch.setattr(config_module.ipaddress, "ip_address", lambda _value: (_ for _ in ()).throw(ValueError("bad")))
    with config_module.app.test_request_context("/", headers={"Host": "::1"}):
        assert config_module.determine_rp_id() == "localhost"


def test_normalise_request_host_returns_raw_value_when_urlsplit_has_no_hostname(monkeypatch):
    monkeypatch.setattr(config_module, "urlsplit", lambda _value: SimpleNamespace(hostname=None), raising=False)

    assert config_module._normalise_request_host("host-without-parse") == "host-without-parse"
