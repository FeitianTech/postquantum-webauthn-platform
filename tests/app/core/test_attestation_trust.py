"""``config.attestation_trust``: the operator's trusted attestation CAs, from the environment."""
from __future__ import annotations

import pytest

from server.app.config import attestation_trust

FINGERPRINTS = "FIDO_SERVER_TRUSTED_ATTESTATION_CA_FINGERPRINTS"
SHA1 = ":".join(["ab"] * 20)


def _fingerprints(monkeypatch, value):
    if value is None:
        monkeypatch.delenv(FINGERPRINTS, raising=False)
    else:
        monkeypatch.setenv(FINGERPRINTS, value)
    return attestation_trust.config_from_env()["TRUSTED_ATTESTATION_CA_FINGERPRINTS"]


def test_no_fingerprint_setting_trusts_no_fingerprint(monkeypatch):
    assert _fingerprints(monkeypatch, None) is None


def test_fingerprints_are_read_as_upper_case_hex_whatever_their_separators(monkeypatch):
    sha256 = "0f" * 32

    assert _fingerprints(monkeypatch, f"{SHA1};\n{sha256}, {SHA1}") == {"AB" * 20, "0F" * 32}


@pytest.mark.parametrize("value", ["", "ab:cd", "  ,;  ", "not hex at all"])
def test_a_fingerprint_shorter_than_twenty_bytes_is_ignored(monkeypatch, value):
    assert _fingerprints(monkeypatch, value) is None


def test_short_entries_are_dropped_and_the_rest_kept(monkeypatch):
    assert _fingerprints(monkeypatch, f"{SHA1}, abcd") == {"AB" * 20}
