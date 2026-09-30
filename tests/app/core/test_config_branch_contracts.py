from __future__ import annotations

from server.app.config import (
    attestation_trust,
    paths,
    relying_party,
)
from tests.app.entry_app import entry_app


def test_the_project_root_is_two_levels_above_the_package():
    assert paths._PACKAGE_ROOT.parts[-2:] == ("server", "app")
    assert paths._PROJECT_ROOT == paths._PACKAGE_ROOT.parents[1]
    assert (paths._PROJECT_ROOT / "server" / "app" / "config" / "paths.py").is_file()


def test_parse_fingerprints_and_host_normalization_branches(monkeypatch):
    assert attestation_trust._parse_trusted_ca_fingerprints(None) is None
    assert attestation_trust._parse_trusted_ca_fingerprints("ab:cd") is None

    long_fp = ":".join(["aa"] * 20)
    parsed = attestation_trust._parse_trusted_ca_fingerprints(f"{long_fp}, short")
    assert parsed == {"AA" * 20}

    monkeypatch.setitem(entry_app().config, "FIDO_SERVER_RP_ID", "  configured.example  ")
    with entry_app().app_context():
        assert relying_party.determine_rp_id() == "configured.example"

    assert relying_party._normalise_request_host(None) is None
    assert relying_party._normalise_request_host("   ") is None
    assert relying_party._normalise_request_host("[2001:db8::1]:8443") == "2001:db8::1"
    assert relying_party._normalise_request_host("2001:db8::1") == "2001:db8::1"
    assert relying_party._normalise_request_host("Example.COM:8443") == "example.com"
    assert relying_party._normalise_request_host("bad host") == "bad host"

    assert relying_party._resolve_request_host() is None

    with entry_app().test_request_context(
        "/",
        headers={"Host": ""},
        environ_overrides={"HTTP_HOST": "api.example", "SERVER_NAME": "fallback.example"},
    ):
        assert relying_party._resolve_request_host() == "api.example"

    with entry_app().test_request_context(
        "/",
        headers={"Host": ""},
        environ_overrides={"HTTP_HOST": "", "SERVER_NAME": ""},
    ):
        assert relying_party._resolve_request_host() is None
