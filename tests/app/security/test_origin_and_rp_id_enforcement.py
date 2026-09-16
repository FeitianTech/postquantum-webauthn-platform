"""Fix 3 -- RP ID and origin must not come from attacker-controlled input.

The RP ID used to be derived from the ``Host`` header with no origin
allowlist, and the expected origin used to be read straight from the request's
own ``Origin`` header -- which the same attacker sets alongside
``clientDataJSON.origin``, making the check self-referential.
"""
from __future__ import annotations

import pytest

from .ceremony_helpers import (
    ORIGIN,
    RP_ID,
    Authenticator,
    registration_payload,
    unb64u,
)


def _register(client, *, host=RP_ID, origin=ORIGIN, client_data_origin=None):
    """Run a full registration ceremony and return the /complete response."""

    begin = client.post(
        "/api/register/begin?email=user@example.com",
        json={"credentials": []},
        headers={"Host": host},
    )
    assert begin.status_code == 200
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])

    authenticator = Authenticator()
    payload = registration_payload(
        authenticator,
        challenge=challenge,
        origin=client_data_origin or origin,
        rp_id=host,
    )
    return client.post(
        "/api/register/complete?email=user@example.com",
        json=payload,
        headers={"Host": host, "Origin": origin},
    )


# --------------------------------------------------------------------------
# NEGATIVE -- the allowlist actually blocks.
# --------------------------------------------------------------------------


def test_allowlist_rejects_host_header_derived_rp_id_attack(
    config_module, simple_module, simple_storage, allowed_origins
):
    """The core Fix 3 case.

    With no allowlist the attacker controls the RP ID (via ``Host``) *and* the
    origin (via ``Origin`` + ``clientDataJSON``), so the whole ceremony
    validates against values of their choosing. The allowlist must stop that.
    """

    allowed_origins("https://app.example")

    client = config_module.app.test_client()
    response = _register(
        client, host="evil.example", origin="https://evil.example"
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body.get("status") != "OK"
    assert "not permitted" in body["error"]
    assert simple_storage == {}


def test_allowlist_rejects_an_unlisted_ceremony_origin(
    config_module, simple_module, simple_storage, allowed_origins
):
    """The allowlist gates clientDataJSON.origin, the ceremony's real origin.

    The Host header keeps the RP ID consistent so that the library-level origin
    check passes -- proving it is our allowlist that does the rejecting.
    """

    allowed_origins("https://app.example, https://other.example")

    client = config_module.app.test_client()
    response = _register(
        client, host="not-listed.example", origin="https://not-listed.example"
    )

    assert response.status_code == 400
    assert "not permitted" in response.get_json()["error"]
    assert simple_storage == {}


def test_expected_origin_is_not_taken_from_the_request_origin_header(
    config_module, simple_module, simple_storage
):
    """The self-referential check is gone.

    The attacker sets BOTH ``Origin`` and ``clientDataJSON.origin`` to the same
    value. That used to satisfy the origin check trivially; the expected origin
    must now come from the server's own configuration instead.
    """

    client = config_module.app.test_client()
    response = _register(
        client, host="evil.example", origin="https://evil.example"
    )

    assert response.status_code == 400
    body = response.get_json()
    assert body.get("status") != "OK"
    assert "origin_mismatch" in body.get("attestationErrors", [])
    assert simple_storage == {}


def test_simple_flow_never_takes_rp_id_from_the_request_body(
    config_module, simple_module, simple_storage
):
    """A body-supplied ``rp.id``/``rpId`` must have no effect in the simple flow."""

    client = config_module.app.test_client()
    begin = client.post(
        "/api/register/begin?email=user@example.com",
        json={
            "credentials": [],
            "publicKey": {"rp": {"id": "evil.example"}, "rpId": "evil.example"},
        },
    )

    assert begin.status_code == 200
    # The RP ID stays the server-resolved one, not the body's.
    assert begin.get_json()["publicKey"]["rp"]["id"] == RP_ID

    with client.session_transaction() as session:
        assert session["register_rp_id"] == RP_ID


# --------------------------------------------------------------------------
# POSITIVE -- a listed origin still completes.
# --------------------------------------------------------------------------


def test_allowlist_permits_a_listed_origin(
    config_module, simple_module, simple_storage, allowed_origins
):
    allowed_origins("http://localhost, https://app.example")

    client = config_module.app.test_client()
    response = _register(client)

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "OK"
    assert simple_storage["email"] == "user@example.com"


def test_unconfigured_server_still_works_for_local_development(
    config_module, simple_module, simple_storage
):
    """With nothing configured the dev fallback keeps the demo usable."""

    assert config_module.get_allowed_origins() is None

    client = config_module.app.test_client()
    response = _register(client)

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "OK"


# --------------------------------------------------------------------------
# Config-level unit coverage.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "candidate, expected",
    [
        ("https://app.example", True),
        ("https://app.example:443", True),  # default port is equivalent
        ("https://app.example/some/path", True),  # path is not part of an origin
        ("http://app.example", False),  # scheme must match exactly
        ("https://sub.app.example", False),  # no subdomain wildcarding
        ("https://app.example:8443", False),  # explicit non-default port differs
        ("https://evil.example", False),
        (None, False),
        ("", False),
    ],
)
def test_is_origin_allowed_is_an_exact_match(config_module, allowed_origins, candidate, expected):
    allowed_origins("https://app.example")
    assert config_module.is_origin_allowed(candidate) is expected


def test_is_origin_allowed_permits_everything_when_unconfigured(config_module, allowed_origins):
    allowed_origins(None)
    assert config_module.is_origin_allowed("https://anything.example") is True


def test_determine_expected_origin_never_echoes_an_unlisted_candidate(
    config_module, allowed_origins
):
    allowed_origins("https://app.example, https://second.example")

    # A listed candidate is honoured...
    assert config_module.determine_expected_origin("https://second.example") == (
        "https://second.example"
    )
    # ...but an unlisted one falls back to the allowlist, never to itself.
    assert config_module.determine_expected_origin("https://evil.example") == (
        "https://app.example"
    )


def test_development_fallback_warning_is_emitted_once(config_module, monkeypatch):
    warnings = []
    monkeypatch.setattr(
        config_module.app.logger,
        "warning",
        lambda msg, *args: warnings.append(msg % args if args else msg),
    )
    monkeypatch.setattr(config_module, "_RP_CONFIGURATION_WARNING_EMITTED", False, raising=False)
    monkeypatch.setitem(config_module.app.config, "FIDO_SERVER_RP_ID", None)
    monkeypatch.setitem(config_module.app.config, "FIDO_SERVER_ALLOWED_ORIGINS", None)

    assert config_module.warn_if_development_rp_configuration() is True
    assert len(warnings) == 1
    assert "DEVELOPMENT-ONLY" in warnings[0]
    assert "FIDO_SERVER_ALLOWED_ORIGINS" in warnings[0]

    # Emitted once, not on every call.
    assert config_module.warn_if_development_rp_configuration() is False
    assert len(warnings) == 1
