"""``create_app()``: its init steps, their order, and what the order guarantees."""
from __future__ import annotations

import gzip
import re
from pathlib import Path

from werkzeug.middleware.proxy_fix import ProxyFix

from server.app import factory, static_assets
from server.app.config import (
    attestation_trust,
    compression,
    logs,
    origins,
    proxy,
    relying_party,
    security_headers,
    session_cookie,
    session_secret,
)

_SERVER_APP = Path(__file__).resolve().parents[3] / "server" / "app"


def test_init_steps_are_pinned_in_order():
    """Reordering these is a behaviour change; update this test deliberately."""

    assert factory.INIT_STEPS == (
        logs.init_app,
        session_secret.init_app,
        proxy.init_app,
        compression.init_app,
        security_headers.init_app,
        static_assets.init_app,
        factory._register_blueprints,
        relying_party.init_app,
    )
    assert factory.CONFIG_SOURCES == (
        attestation_trust,
        origins,
        relying_party,
        security_headers,
        session_cookie,
    )


def test_create_app_runs_each_step_once_in_that_order(monkeypatch):
    original = factory.INIT_STEPS
    calls = []

    def _recording(step):
        def _run(app):
            calls.append(step)
            step(app)

        return _run

    monkeypatch.setattr(factory, "INIT_STEPS", tuple(_recording(step) for step in original))

    factory.create_app({"SECRET_KEY": "order-test"})

    assert calls == list(original)


def test_hooks_and_blueprints_are_registered_in_order(app):
    # Flask runs after_request handlers in reverse: headers first, then gzip.
    assert app.after_request_funcs[None] == [
        compression.maybe_compress_response,
        security_headers.set_security_headers,
    ]
    assert app.before_request_funcs[None] == [static_assets._hide_private_static_files]
    assert list(app.blueprints) == ["static_assets", "advanced", "general", "simple"]
    assert app.jinja_env.globals["asset_url"] is static_assets.asset_url


def test_proxy_fix_wraps_the_app_only_behind_a_trusted_proxy(monkeypatch, make_app):
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("FIDO_SERVER_TRUST_PROXY", raising=False)
    assert not isinstance(make_app().wsgi_app, ProxyFix)

    monkeypatch.setenv("K_SERVICE", "pqcwebauthn")
    wrapped = make_app().wsgi_app
    assert isinstance(wrapped, ProxyFix)
    assert (wrapped.x_for, wrapped.x_proto) == (1, 1)
    # Never the forwarded host: the RP ID is derived from Host when unconfigured.
    assert (wrapped.x_host, wrapped.x_port, wrapped.x_prefix) == (0, 0, 0)


def test_gzipped_response_still_carries_the_security_headers(client):
    response = client.get("/", base_url="https://localhost", headers={"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.headers["Content-Encoding"] == "gzip"
    body = response.get_data()
    assert int(response.headers["Content-Length"]) == len(body)
    assert b"<html" in gzip.decompress(body).lower()
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")
    assert "Accept-Encoding" in response.headers["Vary"]


def test_explicit_config_overrides_the_environment(monkeypatch, make_app):
    monkeypatch.setenv("FIDO_SERVER_RP_ID", "env.example")

    assert make_app().config["FIDO_SERVER_RP_ID"] == "env.example"
    assert make_app({"FIDO_SERVER_RP_ID": "override.example"}).config["FIDO_SERVER_RP_ID"] == (
        "override.example"
    )


def test_a_configured_secret_key_is_used_as_is(make_app):
    app = make_app({"SECRET_KEY": "configured-secret"})

    assert app.secret_key == "configured-secret"


def test_no_server_module_reads_the_config_app_alias():
    """``config.app`` exists for old callers; the app itself must not depend on it."""

    alias = _SERVER_APP / "config" / "__init__.py"
    pattern = re.compile(r"\bconfig\.app\b|from \.+config(\.application)? import [^\n]*\bapp\b")
    offenders = []
    for path in _SERVER_APP.rglob("*.py"):
        if path == alias:
            continue
        text = path.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(str(path.relative_to(_SERVER_APP)))

    assert offenders == []
