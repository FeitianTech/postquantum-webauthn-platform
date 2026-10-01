"""Tests for the exact-origin allowlist and the origin a ceremony claims."""
from __future__ import annotations

import base64
import json

import pytest

from server.app.config import origins

ALLOWLIST = "FIDO_SERVER_ALLOWED_ORIGINS"


def _client_data(payload) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def test_an_allowlist_is_read_once_per_origin_from_commas_and_newlines(monkeypatch):
    monkeypatch.setenv(ALLOWLIST, "https://A.example, https://a.example:443\n\nhttp://b.example:8080 ,https://")

    assert origins.config_from_env() == {ALLOWLIST: ("https://a.example", "http://b.example:8080")}


def test_an_allowlist_without_an_origin_is_no_allowlist(monkeypatch):
    monkeypatch.setenv(ALLOWLIST, " , \n ")

    assert origins.config_from_env() == {ALLOWLIST: None}


@pytest.mark.parametrize(
    ("raw", "origin"),
    [
        ("Example.COM", "https://example.com"),
        ("https://example.com:443", "https://example.com"),
        ("https://example.com:8443", "https://example.com:8443"),
        ("http://[::1]:80", "http://[::1]"),
        ("https://", None),
        ("   ", None),
        (None, None),
    ],
)
def test_an_origin_is_reduced_to_its_scheme_host_and_port(raw, origin):
    assert origins.normalise_origin(raw) == origin


@pytest.mark.parametrize(
    ("configured", "allowlist"),
    [
        ("https://a.example, https://b.example", ("https://a.example", "https://b.example")),
        (["https://a.example", "https://A.example", "https://"], ("https://a.example",)),
        ([], None),
        (443, None),
    ],
)
def test_a_configured_allowlist_is_text_or_a_collection_of_origins(configured, allowlist):
    assert origins.allowed_origins_from_config({ALLOWLIST: configured}) == allowlist


def test_only_an_allowlisted_origin_is_allowed(make_app):
    with make_app({ALLOWLIST: ("https://a.example",)}).app_context():
        assert origins.is_origin_allowed("https://A.example:443") is True
        assert origins.is_origin_allowed("https://b.example") is False
        assert origins.is_origin_allowed("") is False


def test_without_an_allowlist_every_origin_is_allowed(make_app):
    with make_app({ALLOWLIST: None}).app_context():
        assert origins.is_origin_allowed("https://anything.example") is True


@pytest.mark.parametrize(
    ("credential_response", "origin"),
    [
        ({"clientDataJSON": _client_data({"origin": "https://a.example"})}, "https://a.example"),
        ({"clientDataJSON": base64.b64encode(b'{"origin": "https://a.example", "x": ">?"}').decode()}, "https://a.example"),
        ({"clientDataJSON": _client_data({"origin": 443})}, None),
        ({"clientDataJSON": _client_data(["https://a.example"])}, None),
        ({"clientDataJSON": base64.urlsafe_b64encode(b"not json").decode()}, None),
        ({"clientDataJSON": "not base64!"}, None),
        ({"clientDataJSON": 443}, None),
        ({}, None),
        ("not a response", None),
    ],
)
def test_the_claimed_origin_is_read_from_client_data_json(credential_response, origin):
    assert origins.extract_client_data_origin(credential_response) == origin


def test_the_expected_origin_is_a_candidate_only_when_it_is_allowlisted(make_app):
    app = make_app({ALLOWLIST: ("https://a.example", "https://b.example")})

    with app.app_context():
        assert origins.determine_expected_origin("https://b.example") == "https://b.example"
        assert origins.determine_expected_origin("https://evil.example") == "https://a.example"


def test_without_an_allowlist_the_expected_origin_is_the_requests_or_none(make_app):
    app = make_app({ALLOWLIST: None})

    with app.test_request_context("/", base_url="http://localhost:5000"):
        assert origins.determine_expected_origin("https://evil.example") == "http://localhost:5000"
    with app.app_context():
        assert origins.determine_expected_origin() is None
