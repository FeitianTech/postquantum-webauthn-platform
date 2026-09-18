"""The metadata session namespace must not be selectable by the client.

``_get_metadata_session_id`` used to take ``request.cookies["fido.mds.session"]``
verbatim.  ``_normalise_session_identifier`` blocked path traversal, but nothing
blocked *naming another visitor's namespace*: anyone who could set a cookie could
read and overwrite the stored metadata and credential artifacts of any session id
they knew.  The recovery cookie is now signed with the application secret.
"""
from __future__ import annotations

import itsdangerous
import pytest
from flask import session as flask_session

COOKIE_SALT = "fido.mds.session-cookie.v1"


@pytest.fixture
def session_env(monkeypatch, tmp_path):
    config = pytest.importorskip("server.app.config")
    metadata = pytest.importorskip("server.app.metadata")
    session_store = pytest.importorskip("server.app.session_metadata_store")
    runtime_state = pytest.importorskip("server.app.metadata.runtime_state")
    pytest.importorskip("server.app.app")

    session_dir = tmp_path / "sessions"
    session_dir.mkdir()

    for module in (config, metadata, session_store):
        monkeypatch.setattr(
            module, "SESSION_METADATA_DIR", str(session_dir), raising=False
        )

    monkeypatch.setattr(session_store, "gcs_enabled", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_using_gcs", lambda: False, raising=False)
    monkeypatch.setattr(session_store, "_local_last_cleanup", 0.0, raising=False)
    monkeypatch.setattr(runtime_state, "_session_metadata_entry_ids", set())
    monkeypatch.setattr(runtime_state, "_session_metadata_last_cleanup", 0.0)

    return config.app, metadata


def _entry(description: str) -> dict:
    return {
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "metadataStatement": {"description": description},
    }


def _seal(app, identifier: str) -> str:
    return itsdangerous.URLSafeTimedSerializer(
        app.secret_key, salt=COOKIE_SALT
    ).dumps(identifier)


def _seed_victim(app, metadata, namespace: str) -> None:
    with app.test_request_context("/"):
        flask_session[metadata._SESSION_METADATA_SESSION_KEY] = namespace
        metadata.save_session_metadata_item(_entry("victim secret entry"))


def _custom_items(app, cookie_value=None):
    """GET the per-session metadata list as a client holding ``cookie_value``.

    NOTE: the cookie must go through ``client.set_cookie``.  Werkzeug's test
    client rebuilds ``HTTP_COOKIE`` from its own jar on every request, so a
    ``Cookie`` header passed in ``headers=`` is silently dropped -- which would
    make every negative assertion below pass for the wrong reason.  The positive
    case (``test_returning_visitor_keeps_their_namespace_via_the_signed_cookie``)
    uses this same helper and therefore proves the cookie really is delivered.
    """

    client = app.test_client()
    if cookie_value is not None:
        client.set_cookie("fido.mds.session", cookie_value)
    response = client.get("/api/mds/metadata/custom")
    assert response.status_code == 200
    return response.get_json()["items"]


# --------------------------------------------------------------------------
# Forged cookies
# --------------------------------------------------------------------------


def test_forged_plaintext_cookie_cannot_reach_another_namespace(session_env):
    app, metadata = session_env
    _seed_victim(app, metadata, "victim-namespace")

    with app.test_request_context("/"):
        flask_session[metadata._SESSION_METADATA_SESSION_KEY] = "victim-namespace"
        assert len(metadata.list_session_metadata_items()) == 1

    # The attacker names the victim's namespace directly.
    assert _custom_items(app, "victim-namespace") == []


def test_forged_cookie_cannot_write_into_another_namespace(session_env):
    app, metadata = session_env
    _seed_victim(app, metadata, "victim-namespace")

    with app.test_request_context(
        "/", headers={"Cookie": "fido.mds.session=victim-namespace"}
    ):
        attacker_namespace = metadata.ensure_metadata_session_id()
        assert attacker_namespace != "victim-namespace"
        metadata.save_session_metadata_item(_entry("attacker entry"))

    with app.test_request_context("/"):
        flask_session[metadata._SESSION_METADATA_SESSION_KEY] = "victim-namespace"
        items = metadata.list_session_metadata_items()
    assert len(items) == 1
    assert items[0].payload["metadataStatement"]["description"] == "victim secret entry"


def test_cookie_signed_with_a_different_secret_is_rejected(session_env):
    app, metadata = session_env
    _seed_victim(app, metadata, "victim-namespace")

    forged = itsdangerous.URLSafeTimedSerializer(
        b"not-the-application-secret", salt=COOKIE_SALT
    ).dumps("victim-namespace")

    assert _custom_items(app, forged) == []


def test_cookie_signed_with_the_wrong_salt_is_rejected(session_env):
    app, metadata = session_env
    _seed_victim(app, metadata, "victim-namespace")

    forged = itsdangerous.URLSafeTimedSerializer(
        app.secret_key, salt="some.other.purpose"
    ).dumps("victim-namespace")

    assert _custom_items(app, forged) == []


def test_tampered_signature_is_rejected(session_env):
    app, metadata = session_env
    _seed_victim(app, metadata, "victim-namespace")

    sealed = _seal(app, "victim-namespace")
    tampered = sealed[:-4] + ("zzzz" if not sealed.endswith("zzzz") else "yyyy")

    assert _custom_items(app, tampered) == []


@pytest.mark.parametrize(
    "value", ["", "   ", ".hidden", "../escape", "not-base64-at-all", "a.b.c"]
)
def test_malformed_cookies_never_raise_and_never_bind(session_env, value):
    app, _metadata = session_env
    assert _custom_items(app, value) == []


# --------------------------------------------------------------------------
# Legitimate use keeps working
# --------------------------------------------------------------------------


def test_returning_visitor_keeps_their_namespace_via_the_signed_cookie(session_env):
    app, metadata = session_env
    _seed_victim(app, metadata, "victim-namespace")

    # A brand-new client (no Flask session cookie at all) carrying only the
    # signed recovery cookie must land back in its own namespace.
    items = _custom_items(app, _seal(app, "victim-namespace"))
    assert len(items) == 1
    assert items[0]["entry"]["metadataStatement"]["description"] == (
        "victim secret entry"
    )


def test_signed_flask_session_takes_precedence_over_the_cookie(session_env):
    app, metadata = session_env

    with app.test_request_context(
        "/", headers={"Cookie": f"fido.mds.session={_seal(app, 'from-cookie')}"}
    ):
        flask_session[metadata._SESSION_METADATA_SESSION_KEY] = "from-session"
        assert metadata._get_metadata_session_id(create=False) == "from-session"


def test_issued_cookie_is_signed_httponly_and_round_trips(session_env):
    app, metadata = session_env

    client = app.test_client()
    response = client.get("/api/mds/metadata/custom")
    assert response.status_code == 200

    set_cookies = [
        value
        for value in response.headers.getlist("Set-Cookie")
        if value.startswith("fido.mds.session=")
    ]
    assert set_cookies, "no metadata session cookie was issued"
    cookie = set_cookies[0]
    assert "HttpOnly" in cookie

    value = cookie.split(";", 1)[0].split("=", 1)[1]
    identifier = itsdangerous.URLSafeTimedSerializer(
        app.secret_key, salt=COOKIE_SALT
    ).loads(value)
    # The wire value is not the namespace name itself.
    assert value != identifier
    assert metadata._normalise_session_identifier(identifier) == identifier


def test_fresh_visitor_gets_an_unguessable_namespace(session_env):
    app, metadata = session_env

    with app.test_request_context("/"):
        first = metadata.ensure_metadata_session_id()
    with app.test_request_context("/"):
        second = metadata.ensure_metadata_session_id()

    assert first != second
    assert len(first) >= 32
