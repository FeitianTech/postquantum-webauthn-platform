from __future__ import annotations

from types import SimpleNamespace

from server.app.config import relying_party
from tests.app.entry_app import entry_app


def test_the_unread_session_metadata_recover_setting_is_gone(monkeypatch, make_app):
    # Nothing ever read app.config["SESSION_METADATA_RECOVER_ON_START"].
    monkeypatch.setenv("FIDO_SERVER_SESSION_METADATA_RECOVER", "1")

    assert "SESSION_METADATA_RECOVER_ON_START" not in make_app().config


def test_determine_rp_id_handles_missing_host_and_loopback_fallback(monkeypatch):
    with entry_app().test_request_context(
        "/",
        headers={"Host": ""},
        environ_overrides={"HTTP_HOST": "", "SERVER_NAME": ""},
    ):
        assert relying_party.determine_rp_id() == "localhost"

    monkeypatch.setattr(relying_party.ipaddress, "ip_address", lambda _value: (_ for _ in ()).throw(ValueError("bad")))
    with entry_app().test_request_context("/", headers={"Host": "::1"}):
        assert relying_party.determine_rp_id() == "localhost"


def test_normalise_request_host_returns_raw_value_when_urlsplit_has_no_hostname(monkeypatch):
    monkeypatch.setattr(relying_party, "urlsplit", lambda _value: SimpleNamespace(hostname=None))

    assert relying_party._normalise_request_host("host-without-parse") == "host-without-parse"
