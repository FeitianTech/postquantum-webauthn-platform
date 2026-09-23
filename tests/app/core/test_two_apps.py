"""Two apps built in one process keep to their own settings -- the point of a factory."""
from __future__ import annotations

import pytest
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import BadSignature

from server.app.config import origins


def _app_settings(name: str) -> dict:
    return {
        "SECRET_KEY": f"secret-for-{name}-0123456789abcdef",
        "FIDO_SERVER_RP_ID": f"{name}.example",
        "FIDO_SERVER_RP_NAME": f"App {name.upper()}",
        "FIDO_SERVER_ALLOWED_ORIGINS": (f"https://{name}.example",),
    }


def _register_begin(client, host: str):
    response = client.post(
        "/api/register/begin",
        json={},
        base_url=f"https://{host}",
        headers={"Host": host},
    )
    assert response.status_code == 200, response.get_json()
    return response


def _session_cookie(response) -> str:
    for header in response.headers.getlist("Set-Cookie"):
        name, _, rest = header.partition("=")
        if name == "session":
            return rest.split(";", 1)[0]
    raise AssertionError("no session cookie set")


def test_two_apps_with_different_rp_settings_do_not_interfere(make_app):
    app_a = make_app(_app_settings("a"))
    app_b = make_app(_app_settings("b"))
    client_a = app_a.test_client()
    client_b = app_b.test_client()

    # Interleaved requests: each resolves its own app's RP.
    for _ in range(2):
        rp_a = _register_begin(client_a, "a.example").get_json()["publicKey"]["rp"]
        rp_b = _register_begin(client_b, "b.example").get_json()["publicKey"]["rp"]
        assert rp_a == {"id": "a.example", "name": "App A"}
        assert rp_b == {"id": "b.example", "name": "App B"}

    with app_a.app_context():
        assert origins.get_allowed_origins() == ("https://a.example",)
    with app_b.app_context():
        assert origins.get_allowed_origins() == ("https://b.example",)

    # Nothing is shared between them.
    assert app_a.config is not app_b.config
    assert app_a.after_request_funcs[None] is not app_b.after_request_funcs[None]
    assert app_a.url_map is not app_b.url_map
    assert app_a.secret_key != app_b.secret_key

    # A's session cookie verifies under A's key and not under B's.
    cookie = _session_cookie(_register_begin(client_a, "a.example"))
    interface = SecureCookieSessionInterface()
    assert interface.get_signing_serializer(app_a).loads(cookie)["register_rp_id"] == "a.example"
    with pytest.raises(BadSignature):
        interface.get_signing_serializer(app_b).loads(cookie)

    # Changing A after it was built leaves B alone.
    app_a.config["FIDO_SERVER_RP_ID"] = "changed.example"
    assert _register_begin(client_a, "a.example").get_json()["publicKey"]["rp"]["id"] == "changed.example"
    assert _register_begin(client_b, "b.example").get_json()["publicKey"]["rp"]["id"] == "b.example"
