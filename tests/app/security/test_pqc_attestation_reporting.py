"""Fix 5 -- the PQC fallback must not launder attestation errors away.

When normal attestation verification failed, a PQC fallback re-ran a bare
signature check and, on success, set ``signature_valid = True`` *and cleared*
``attestation_errors``. The fallback only checks the signature -- it skips the
packed-attestation certificate policy checks (Subject OU, AAGUID extension
match, Basic Constraints) -- so a narrow pass was being promoted into a clean
overall verdict.

The PQC result must now be reported as its own field and must never replace
the verdict or erase the errors.
"""
from __future__ import annotations

import pytest

from .ceremony_helpers import (
    ORIGIN,
    RP_ID,
    Authenticator,
    attestation_object,
    b64u,
    client_data,
)

MLDSA44_ALG = -48


@pytest.fixture
def attestation_module():
    return pytest.importorskip("server.app.attestation")


def _packed_registration_response(authenticator, *, challenge, attestation_alg):
    """A packed attestation whose signature cannot verify.

    The attestation statement claims a PQC algorithm while the credential key
    is a classical one, so the PQC fallback is genuinely attempted and
    genuinely fails -- no stubbing involved.
    """

    data = client_data(challenge=challenge, ceremony_type="webauthn.create")
    auth_data = authenticator.authenticator_data(rp_id=RP_ID)
    att_obj = attestation_object(
        auth_data,
        fmt="packed",
        att_stmt={"alg": attestation_alg, "sig": b"\x00" * 64},
    )
    return {
        "id": b64u(authenticator.credential_id),
        "rawId": b64u(authenticator.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(data),
            "attestationObject": b64u(att_obj),
        },
        "clientExtensionResults": {},
    }


def test_pqc_fallback_failure_never_clears_attestation_errors(attestation_module):
    """A failing PQC fallback must append, never erase."""

    authenticator = Authenticator()
    challenge = b"\x61" * 32

    response = _packed_registration_response(
        authenticator, challenge=challenge, attestation_alg=MLDSA44_ALG
    )

    result = attestation_module.perform_attestation_checks(
        response,
        {"challenge": challenge},
        None,
        None,
        ORIGIN,
        RP_ID,
    )

    # The overall verdict stays negative...
    assert result["signature_valid"] is False
    # ...the PQC result is reported separately...
    assert result["pqc_signature_valid"] is False
    # ...and the original failure is still visible.
    assert result["errors"], "attestation errors must not be cleared"
    joined = "\n".join(result["errors"])
    assert "attestation" in joined


def test_pqc_signature_result_is_a_separate_field_from_the_verdict(attestation_module):
    """``pqc_signature_valid`` exists and is distinct from ``signature_valid``."""

    authenticator = Authenticator()
    challenge = b"\x62" * 32

    response = _packed_registration_response(
        authenticator, challenge=challenge, attestation_alg=MLDSA44_ALG
    )
    result = attestation_module.perform_attestation_checks(
        response,
        {"challenge": challenge},
        None,
        None,
        ORIGIN,
        RP_ID,
    )

    assert "pqc_signature_valid" in result
    assert result["signature_valid"] is not result["pqc_signature_valid"] or (
        result["signature_valid"] is False
    )


def test_non_pqc_attestation_leaves_pqc_field_unset(attestation_module):
    """A classical failure must not invent a PQC result."""

    authenticator = Authenticator()
    challenge = b"\x63" * 32

    response = _packed_registration_response(
        authenticator, challenge=challenge, attestation_alg=-7
    )
    result = attestation_module.perform_attestation_checks(
        response,
        {"challenge": challenge},
        None,
        None,
        ORIGIN,
        RP_ID,
    )

    assert result["signature_valid"] is False
    assert result["pqc_signature_valid"] is None
    assert result["errors"]


def test_pqc_fallback_success_does_not_become_the_verdict(attestation_module, monkeypatch):
    """The laundering case itself.

    liboqs is not available in this environment, so a genuine ML-DSA signature
    cannot be produced here. This test therefore drives the fallback's *output
    contract* directly: even when the bare signature check succeeds, it must
    not promote ``signature_valid`` or clear the errors the full verification
    produced. (No verification function is weakened -- the stub makes the
    fallback report success, which is the case that used to launder.)
    """

    from types import SimpleNamespace

    authenticator = Authenticator()
    challenge = b"\x64" * 32
    response = _packed_registration_response(
        authenticator, challenge=challenge, attestation_alg=MLDSA44_ALG
    )

    monkeypatch.setattr(
        attestation_module,
        "_attempt_pqc_attestation_signature_validation",
        lambda *_a, **_k: {
            "attempted": True,
            "success": True,
            "attestation_result": SimpleNamespace(trust_path=[]),
            "error": None,
        },
        raising=False,
    )

    result = attestation_module.perform_attestation_checks(
        response,
        {"challenge": challenge},
        None,
        None,
        ORIGIN,
        RP_ID,
    )

    # The bare signature check passed...
    assert result["pqc_signature_valid"] is True
    # ...but it is NOT the verdict, and the errors survive.
    assert result["signature_valid"] is False
    assert result["errors"], "the PQC fallback must not clear attestation errors"
