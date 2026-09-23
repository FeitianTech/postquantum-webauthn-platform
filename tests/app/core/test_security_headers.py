"""Transport hardening: response security headers, session cookie, ProxyFix."""
from __future__ import annotations

import importlib
import os
import re
from datetime import timedelta

import pytest

config_module = pytest.importorskip("server.app.config")
config_paths = pytest.importorskip("server.app.config.paths")
config_proxy = pytest.importorskip("server.app.config.proxy")
config_session_cookie = pytest.importorskip("server.app.config.session_cookie")
config_security_headers = pytest.importorskip("server.app.config.security_headers")
app_module = pytest.importorskip("server.app.app")

app = config_module.app


@pytest.fixture
def client():
    return app.test_client()


EXPECTED_HEADERS = (
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def _parse_csp(policy: str) -> dict:
    directives = {}
    for chunk in policy.split(";"):
        parts = chunk.strip().split()
        if parts:
            directives[parts[0]] = parts[1:]
    return directives


# --------------------------------------------------------------------------
# Headers present on ordinary responses
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/health"])
@pytest.mark.parametrize("header", EXPECTED_HEADERS)
def test_every_expected_header_is_present(client, path, header):
    response = client.get(path)
    assert response.status_code == 200
    assert response.headers.get(header), f"{header} missing from {path}"


def test_index_still_renders_under_the_shipped_csp(client):
    """A policy that breaks the page is worse than no policy."""

    response = client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "<title>" in body
    assert "scripts/main.js" in body
    # The inline bootstrap block and the inline handlers are still there, which
    # is exactly why script-src still needs 'unsafe-inline'.
    assert "__INITIAL_MDS_INFO__" in body


def test_clickjacking_is_refused_two_ways(client):
    response = client.get("/")
    assert response.headers["X-Frame-Options"] == "DENY"
    csp = _parse_csp(response.headers["Content-Security-Policy"])
    assert csp["frame-ancestors"] == ["'none'"]


def test_content_type_and_referrer_policies(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_permissions_policy_scopes_webauthn_to_self(client):
    policy = client.get("/").headers["Permissions-Policy"]
    assert "publickey-credentials-get=(self)" in policy
    assert "publickey-credentials-create=(self)" in policy
    # Nothing else this app does not use should be left open.
    assert "camera=()" in policy
    assert "microphone=()" in policy
    assert "geolocation=()" in policy


def test_csp_locks_down_the_non_script_directives(client):
    csp = _parse_csp(client.get("/").headers["Content-Security-Policy"])
    assert csp["default-src"] == ["'self'"]
    assert csp["base-uri"] == ["'self'"]
    assert csp["object-src"] == ["'none'"]
    assert csp["form-action"] == ["'self'"]
    assert csp["connect-src"] == ["'self'"]
    assert csp["frame-src"] == ["'none'"]
    # Google Fonts is the only third-party origin the templates reference.
    assert csp["font-src"] == ["'self'", "https://fonts.gstatic.com"]
    assert "https://fonts.googleapis.com" in csp["style-src"]
    assert "'unsafe-inline'" not in csp["default-src"]


def test_csp_script_src_is_documented_as_not_strict(client):
    """The 125 inline on*= handlers still force 'unsafe-inline' for scripts.

    This test exists to fail loudly if the templates are cleaned up (or if the
    policy is tightened) so the TODO in config/security_headers.py gets retired
    deliberately.
    """

    csp = _parse_csp(client.get("/").headers["Content-Security-Policy"])
    assert csp["script-src"] == ["'self'", "'unsafe-inline'"]

    template_root = config_paths._FRONTEND_TEMPLATE_ROOT
    handler_pattern = re.compile(r"\son[a-zA-Z]+\s*=\s*\"")
    inline_handlers = 0
    for dirpath, _dirnames, filenames in os.walk(template_root):
        for filename in filenames:
            if not filename.endswith(".html"):
                continue
            with open(os.path.join(dirpath, filename), encoding="utf-8") as handle:
                inline_handlers += len(handler_pattern.findall(handle.read()))

    assert inline_handlers > 0, (
        "No inline on*= handlers remain -- drop 'unsafe-inline' from script-src "
        "and retire the TODO(csp-strict) note in server/app/config/security_headers.py."
    )


def test_security_headers_do_not_clobber_an_explicit_value():
    response = app.response_class("ok")
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    with app.test_request_context("/"):
        config_module.set_security_headers(response)
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"


def test_headers_handler_is_registered_exactly_once():
    handlers = app.after_request_funcs.get(None, [])
    marked = [
        handler
        for handler in handlers
        if getattr(handler, config_security_headers._SECURITY_HEADERS_MARKER, False)
    ]
    assert len(marked) == 1

    config_security_headers._register_security_headers_once(
        app, config_module.set_security_headers
    )
    assert len(app.after_request_funcs.get(None, [])) == len(handlers)


# --------------------------------------------------------------------------
# HSTS is TLS-only
# --------------------------------------------------------------------------


def test_hsts_absent_on_plain_http(client):
    response = client.get("/health")
    assert "Strict-Transport-Security" not in response.headers


def test_hsts_present_on_https(client):
    response = client.get("/health", base_url="https://localhost")
    hsts = response.headers["Strict-Transport-Security"]
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts
    # Never opt a deployment into the preload list on its behalf.
    assert "preload" not in hsts


def test_hsts_follows_the_forwarded_scheme_behind_a_proxy():
    """Cloud Run terminates TLS, so is_secure only works via X-Forwarded-Proto."""

    from werkzeug.middleware.proxy_fix import ProxyFix

    proxied = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)
    original = app.wsgi_app
    app.wsgi_app = proxied
    try:
        response = app.test_client().get(
            "/health", headers={"X-Forwarded-Proto": "https"}
        )
    finally:
        app.wsgi_app = original

    assert "Strict-Transport-Security" in response.headers


# --------------------------------------------------------------------------
# Session cookie
# --------------------------------------------------------------------------


def test_session_cookie_flags_are_configured():
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    # False here, because the test client and localhost dev both speak http and
    # a Secure cookie would never be sent back.
    assert app.config["SESSION_COOKIE_SECURE"] is False


def test_session_lifetime_is_short_enough_for_ceremony_state():
    lifetime = app.config["PERMANENT_SESSION_LIFETIME"]
    assert isinstance(lifetime, timedelta)
    assert lifetime <= timedelta(hours=1)
    assert lifetime >= timedelta(minutes=5)


def test_issued_session_cookie_carries_the_flags(client):
    with client.session_transaction() as flask_session:
        flask_session["probe"] = "value"
    response = client.get("/health")
    cookies = response.headers.getlist("Set-Cookie")
    session_cookies = [value for value in cookies if value.startswith("session=")]
    if session_cookies:
        cookie = session_cookies[0]
        assert "HttpOnly" in cookie
        assert "SameSite=Lax" in cookie
        assert "Secure" not in cookie


@pytest.mark.parametrize(
    "env_value,expected",
    [("1", True), ("true", True), ("0", False), ("off", False)],
)
def test_session_cookie_secure_follows_the_env_override(monkeypatch, env_value, expected):
    monkeypatch.setenv("FIDO_SERVER_SESSION_COOKIE_SECURE", env_value)
    assert config_session_cookie._resolve_session_cookie_secure() is expected


def test_session_cookie_secure_defaults_on_for_cloud_run(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_SESSION_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    assert config_session_cookie._resolve_session_cookie_secure() is False

    monkeypatch.setenv("K_SERVICE", "pqc-webauthn")
    assert config_session_cookie._resolve_session_cookie_secure() is True


@pytest.mark.parametrize(
    "raw,expected",
    [("900", 900), ("not-a-number", 30 * 60), ("0", 30 * 60), ("-5", 30 * 60)],
)
def test_session_lifetime_env_parsing(monkeypatch, raw, expected):
    monkeypatch.setenv("FIDO_SERVER_SESSION_LIFETIME_SECONDS", raw)
    assert config_session_cookie._resolve_session_lifetime_seconds() == expected


# --------------------------------------------------------------------------
# ProxyFix vs. Host-header RP ID derivation
# --------------------------------------------------------------------------


def test_trust_proxy_defaults_to_the_cloud_run_signal(monkeypatch):
    monkeypatch.delenv("FIDO_SERVER_TRUST_PROXY", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    assert config_proxy._should_trust_proxy_headers() is False

    monkeypatch.setenv("K_SERVICE", "pqc-webauthn")
    assert config_proxy._should_trust_proxy_headers() is True

    monkeypatch.setenv("FIDO_SERVER_TRUST_PROXY", "0")
    assert config_proxy._should_trust_proxy_headers() is False


def test_apply_proxy_fix_is_idempotent():
    from flask import Flask

    probe = Flask(__name__)
    assert config_proxy._apply_proxy_fix(probe) is True
    wrapped = probe.wsgi_app
    assert config_proxy._apply_proxy_fix(probe) is False
    assert probe.wsgi_app is wrapped


def test_proxy_fix_does_not_let_x_forwarded_host_steer_the_rp_id():
    """The RP ID is derived from Host when nothing is configured.

    ``request.headers['Host']`` is a view over ``environ['HTTP_HOST']``, which is
    exactly what ``ProxyFix(x_host=1)`` would overwrite from the client-supplied
    ``X-Forwarded-Host``.  x_host must stay 0 or an attacker picks the RP ID.
    """

    from flask import Flask, jsonify, request

    probe = Flask(__name__)

    @probe.route("/whoami")
    def whoami():
        return jsonify(
            host=request.host,
            header_host=request.headers.get("Host"),
            scheme=request.scheme,
            secure=request.is_secure,
        )

    config_proxy._apply_proxy_fix(probe)

    response = probe.test_client().get(
        "/whoami",
        base_url="http://real.example",
        headers={
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "attacker.example",
            "X-Forwarded-Port": "8443",
        },
    )
    payload = response.get_json()

    assert payload["host"] == "real.example"
    assert payload["header_host"] == "real.example"
    assert "attacker.example" not in payload["host"]
    # ...while the forwarded scheme *is* honoured, which is the whole point.
    assert payload["scheme"] == "https"
    assert payload["secure"] is True


def test_rp_id_derivation_ignores_forwarded_host_header():
    with app.test_request_context(
        "/",
        base_url="http://real.example",
        headers={"X-Forwarded-Host": "attacker.example"},
    ):
        assert config_module.determine_rp_id() == "real.example"
        assert config_module._resolve_request_host() == "real.example"


def test_app_module_exposes_the_hardened_app():
    assert app_module.app is app
    assert "set_security_headers" in config_module.__all__
    assert importlib.import_module("server.app.config").app is app
