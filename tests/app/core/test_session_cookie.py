"""The session cookie: only an answer that changed the session sets it, so an answer
that lands after a ceremony's begin cannot put back the session from before it."""
from __future__ import annotations

from http.cookies import SimpleCookie

import pytest

from server.app import visitor_session
from server.app.config.web_export import WEB_EXPORT_ROOT_KEY
from tests.app import cookies, visitor_namespace
from tests.app.security.ceremony_helpers import (
    ORIGIN,
    Authenticator,
    registration_payload,
    unb64u,
)

EMAIL = "user@example.com"

# The routes that keep a ceremony's state in the session, and so set its cookie.
_CEREMONIES = {
    "simple_registration.register_begin",
    "simple_registration.register_complete",
    "simple_authentication.authenticate_begin",
    "simple_authentication.authenticate_complete",
    "advanced_registration.advanced_register_begin",
    "advanced_registration.advanced_register_complete",
    "advanced_authentication.advanced_authenticate_begin",
    "advanced_authentication.advanced_authenticate_complete",
}


@pytest.fixture
def app(make_app, export_root, mds_fixture_snapshot, credential_store, monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR", str(tmp_path / "credential-artifacts"))
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_DIR", str(tmp_path / "session-metadata"))
    return make_app({WEB_EXPORT_ROOT_KEY: str(export_root)})


def _returning_visitor(app):
    """A browser with a namespace, whose session an earlier release made permanent."""

    client = app.test_client()
    visitor_namespace.give(client, "returning-visitor")
    with client.session_transaction() as session:
        session.permanent = True
        session["state"] = {"challenge": "AQID"}
    return client


def _sample_url(rule) -> str:
    return rule.build({name: "sample.json" for name in rule.arguments}, append_unknown=False)[1]


def test_no_answer_but_a_ceremonys_sets_the_session_cookie(app):
    client = _returning_visitor(app)
    setting = []

    for rule in app.url_map.iter_rules():
        if rule.endpoint in _CEREMONIES:
            continue
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            response = client.open(_sample_url(rule), method=method, json={})
            if cookies.session_cookies(response):
                setting.append(f"{method} {rule.rule}")

    assert setting == []


def _apply(client, response) -> None:
    """Keep the answer's cookies, as the browser does when the answer arrives."""

    for header in response.headers.getlist("Set-Cookie"):
        for name, morsel in SimpleCookie(header).items():
            client.set_cookie(name, morsel.value)


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/api/mds/metadata/info", None),
        ("PUT", "/api/advanced/credential-artifacts/cred-1", {"artifact": {"kept": True}}),
        ("POST", "/api/codec", {"mode": "decode", "payload": "a0"}),
    ],
)
def test_an_answer_sent_before_a_begin_and_arriving_after_it_leaves_the_ceremony_whole(app, method, path, body):
    browser = _returning_visitor(app)
    # The same browser's request, sent with the cookies it held before the begin.
    late = app.test_client()
    for name in ("session", visitor_session.COOKIE_NAME):
        late.set_cookie(name, browser.get_cookie(name).value)
    authenticator = Authenticator()

    begin = browser.post(f"/api/register/begin?email={EMAIL}", json={})
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    _apply(browser, late.open(path, method=method, json=body))
    complete = browser.post(
        f"/api/register/complete?email={EMAIL}",
        json=registration_payload(authenticator, challenge=challenge),
        headers={"Origin": ORIGIN},
    )

    assert complete.status_code == 200, complete.get_json()
