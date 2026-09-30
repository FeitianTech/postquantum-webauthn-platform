"""``config.relying_party``: the RP ID a ceremony uses when none is given.

A configured ``FIDO_SERVER_RP_ID`` wins. Without one, the RP ID comes from the
request's host (a development-only fallback): its hostname or IP literal, with a
loopback address read as ``localhost``, and ``localhost`` when there is no host.

Without both an RP ID and an origin allowlist it warns, once, that it is running
on that fallback.
"""
from __future__ import annotations

import logging

import pytest

from server.app.config import relying_party


@pytest.fixture
def unconfigured_app(make_app):
    return make_app({"FIDO_SERVER_RP_ID": None})


def _rp_id_for(app, **request) -> str:
    with app.test_request_context("/", **request):
        return relying_party.determine_rp_id()


def test_a_configured_rp_id_wins_and_is_trimmed(make_app):
    app = make_app({"FIDO_SERVER_RP_ID": "  configured.example  "})

    assert _rp_id_for(app, headers={"Host": "other.example"}) == "configured.example"


@pytest.mark.parametrize(
    ("host", "rp_id"),
    [
        ("Example.COM:8443", "example.com"),
        ("[2001:DB8::1]:8443", "2001:db8::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("127.0.0.1:5000", "localhost"),
        ("[::1]:8000", "localhost"),
        ("192.0.2.10:443", "192.0.2.10"),
        # Not a hostname a URL can hold: used as sent.
        ("bad host", "bad host"),
        (":8080", ":8080"),
        ("[2001:db8::1", "[2001:db8::1"),
    ],
)
def test_without_one_the_rp_id_is_the_request_host(unconfigured_app, host, rp_id):
    assert _rp_id_for(unconfigured_app, headers={"Host": host}) == rp_id


def test_a_blank_host_header_falls_back_to_the_server_name(unconfigured_app):
    rp_id = _rp_id_for(unconfigured_app, headers={"Host": "   "}, environ_overrides={"SERVER_NAME": "fallback.example"})

    assert rp_id == "fallback.example"


def test_a_request_without_any_host_uses_localhost(unconfigured_app):
    rp_id = _rp_id_for(unconfigured_app, environ_overrides={"HTTP_HOST": None, "SERVER_NAME": ""})

    assert rp_id == "localhost"


def test_the_request_host_is_none_outside_a_request():
    # determine_rp_id asks for it only inside a request.
    assert relying_party._resolve_request_host() is None


@pytest.mark.parametrize(
    ("rp_id", "allowlist", "named"),
    [
        (None, None, "FIDO_SERVER_RP_ID and FIDO_SERVER_ALLOWED_ORIGINS"),
        ("app.example", None, "FIDO_SERVER_ALLOWED_ORIGINS not configured"),
        (None, "https://app.example", "FIDO_SERVER_RP_ID not configured"),
    ],
)
def test_the_fallback_warning_names_what_is_missing(monkeypatch, caplog, make_app, rp_id, allowlist, named):
    app = make_app({"FIDO_SERVER_RP_ID": rp_id, "FIDO_SERVER_ALLOWED_ORIGINS": allowlist})
    # Building the app made this process's one check; each case asks afresh.
    monkeypatch.setattr(relying_party, "_RP_CONFIGURATION_WARNING_EMITTED", False)

    with caplog.at_level(logging.WARNING, logger=relying_party.__name__):
        assert relying_party.warn_if_development_rp_configuration(app) is True

    assert [record.getMessage().startswith(named) for record in caplog.records] == [True]


def test_a_configured_rp_id_and_allowlist_warn_of_nothing(monkeypatch, caplog, make_app):
    app = make_app({"FIDO_SERVER_RP_ID": "app.example", "FIDO_SERVER_ALLOWED_ORIGINS": "https://app.example"})
    unconfigured = make_app({"FIDO_SERVER_RP_ID": None})
    monkeypatch.setattr(relying_party, "_RP_CONFIGURATION_WARNING_EMITTED", False)

    with caplog.at_level(logging.WARNING, logger=relying_party.__name__):
        assert relying_party.warn_if_development_rp_configuration(app) is False
        # Nor later, with nothing configured: the check is made once.
        assert relying_party.warn_if_development_rp_configuration(unconfigured) is False

    assert caplog.records == []
