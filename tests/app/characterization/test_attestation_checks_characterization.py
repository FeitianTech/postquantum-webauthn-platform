"""``perform_attestation_checks`` and its metadata step report what they reported before.

A table of registration responses -- valid, tampered, wrongly typed, bound to the
wrong origin, challenge or RP, missing UV, using a disallowed algorithm or a broken
COSE key, ML-DSA, and the captured attestation formats -- goes through the checks
with no MDS verifier, and ``_finalize_metadata_results`` gets fake metadata entries
and verifiers. Every result must equal ``golden/attestation-checks.json``.
"""
from __future__ import annotations

import types
import uuid

import pytest

from fido2.webauthn import AuthenticatorData

from ..security.ceremony_helpers import ORIGIN, RP_ID, b64u, client_data
from . import harness, material

CHALLENGE = b"\x5a" * 32
ES256_ONLY = {"pubKeyCredParams": [{"type": "public-key", "alg": -7}]}


def _cases():
    es256 = material.Authenticator("checks-es256", aaguid=bytes(range(16)))
    mldsa = material.Authenticator("checks-mldsa44", key_type="ML-DSA-44")
    state = {"challenge": b64u(CHALLENGE), "user_verification": "preferred"}
    build = lambda authenticator=es256, **kwargs: material.registration_payload(  # noqa: E731
        authenticator, challenge=CHALLENGE, **kwargs
    )
    cases = {
        "none-valid": (build(), state, ES256_ONLY),
        "self-valid": (build(attestation="self"), state, ES256_ONLY),
        "self-tampered": (build(attestation="self", tamper=True), state, ES256_ONLY),
        "x5c-valid": (build(attestation="x5c"), state, ES256_ONLY),
        "x5c-aaguid-mismatch": (build(attestation="x5c", x5c_aaguid=b"\x77" * 16), state, ES256_ONLY),
        "x5c-tampered": (build(attestation="x5c", tamper=True), state, ES256_ONLY),
        "mldsa-self-valid": (build(mldsa, attestation="self"), state, {"pubKeyCredParams": [{"type": "public-key", "alg": -48}]}),
        "mldsa-self-tampered": (build(mldsa, attestation="self", tamper=True), state, None),
        "wrong-type": (build(ceremony_type="webauthn.get"), state, ES256_ONLY),
        "cross-origin": (build(cross_origin=True), state, ES256_ONLY),
        "wrong-origin": (build(origin="https://elsewhere.example"), state, ES256_ONLY),
        "wrong-challenge": (build(), {"challenge": b64u(b"\x01" * 32)}, ES256_ONLY),
        "wrong-rp": (build(rp_id="example.com"), state, ES256_ONLY),
        "uv-required-missing": (build(user_verified=False), {**state, "user_verification": "required"}, ES256_ONLY),
        "uv-required-in-options": (
            build(user_verified=False), None,
            {"challenge": b64u(CHALLENGE), "authenticatorSelection": {"userVerification": "required"}},
        ),
        "uv-required-top-level": (build(user_verified=False), None, {"challenge": CHALLENGE.hex(), "userVerification": "required"}),
        "algorithm-not-allowed": (build(), state, {"pubKeyCredParams": [{"type": "public-key", "alg": -257}, {"alg": "x"}, "y"]}),
        "cose-key-broken": (build(cose_key_bytes=b"\xa1\x01\x02"), state, ES256_ONLY),
        "cose-key-unknown-algorithm": (build(cose_key_bytes=es256.cose_key_with_declared_algorithm(-12345)), state, ES256_ONLY),
        "options-challenge-base64url": (build(), None, {"challenge": {"$base64url": b64u(CHALLENGE)}}),
        "options-challenge-base64": (build(), None, {"challenge": {"$base64": __import__("base64").b64encode(CHALLENGE).decode()}}),
        "options-challenge-hex": (build(), None, {"challenge": {"$hex": CHALLENGE.hex()}}),
        "options-challenge-bytes": (build(), None, {"challenge": CHALLENGE}),
        "options-challenge-odd": (build(), None, {"challenge": {"other": 1}}),
        "options-challenge-text": (build(), None, {"challenge": "not a challenge at all"}),
        "no-challenge": (build(), None, None),
        "state-uv-enum": (build(user_verified=False), {"challenge": b64u(CHALLENGE), "user_verification": __import__("fido2.webauthn", fromlist=["x"]).UserVerificationRequirement.REQUIRED}, None),
        "not-a-mapping": (["not", "a", "mapping"], state, None),
        "unparsable": ({"id": "x", "type": "public-key", "response": {}}, state, None),
    }
    for name, attestation_object in material.captured_attestation_objects().items():
        response = {
            "id": b64u(b"\x42" * 16),
            "rawId": b64u(b"\x42" * 16),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(client_data(challenge=CHALLENGE, ceremony_type="webauthn.create")),
                "attestationObject": b64u(attestation_object),
            },
            "clientExtensionResults": {},
        }
        cases[f"captured-{name}"] = (response, state, None)
    return cases


@pytest.fixture
def no_mds(monkeypatch):
    from server.app.webauthn import metadata

    monkeypatch.setattr(metadata, "get_mds_verifier", lambda: None)


def test_attestation_checks_match_their_golden_record(no_mds):
    from server.app.webauthn import attestation

    record = {}
    for name, (response, state, options) in _cases().items():
        record[name] = harness.json_safe(attestation.perform_attestation_checks(response, state, options, None, ORIGIN, RP_ID))
    auth_data = AuthenticatorData(material.Authenticator("checks-auth-data").authenticator_data())
    response, state, options = _cases()["none-valid"]
    record["explicit-auth-data"] = harness.json_safe(
        attestation.perform_attestation_checks(response, state, options, auth_data, ORIGIN, RP_ID)
    )
    harness.check_golden("attestation-checks.json", record)


class _Verifier:
    def __init__(self, entry=None, error=None):
        self.entry, self.error, self.asked = entry, error, []

    def find_entry_by_aaguid(self, aaguid):
        self.asked.append(str(aaguid))
        if self.error:
            raise self.error
        return self.entry


def test_metadata_finalisation_matches_its_golden_record(monkeypatch):
    from server.app.webauthn import metadata
    from server.app.webauthn.attestation import checks

    aaguid = uuid.UUID("f8a011f3-8c0a-4d15-8006-17111f9edc7d")
    statement = types.SimpleNamespace(
        description="Model", authenticator_get_info={"algorithms": [-7, -8]}, attestation_root_certificates=[b"root"]
    )
    entries = {
        "object": types.SimpleNamespace(aaguid=aaguid, metadata_statement=statement),
        "object-other-algorithms": types.SimpleNamespace(
            aaguid=aaguid,
            metadata_statement=types.SimpleNamespace(description="", authenticator_get_info={"algorithms": [-257, "x"]}, attestation_root_certificates=[]),
        ),
        "dict-statement": types.SimpleNamespace(aaguid=None, metadata_statement={"attestationRootCertificates": ["root"]}),
        "dict-statement-snake": types.SimpleNamespace(aaguid=None, metadata_statement={"attestation_root_certificates": "root"}),
        "no-statement": types.SimpleNamespace(),
    }
    record = {}
    variants = [
        (name, dict(metadata_entry=entry, verifier=None)) for name, entry in entries.items()
    ] + [
        ("fallback-found", dict(metadata_entry=None, verifier=_Verifier(entries["object"]))),
        ("fallback-missing", dict(metadata_entry=None, verifier=_Verifier(None))),
        ("fallback-raises", dict(metadata_entry=None, verifier=_Verifier(error=RuntimeError("down")))),
        ("fallback-global-verifier", dict(metadata_entry=None, verifier=None)),
    ]
    global_verifier = _Verifier(entries["object"])
    monkeypatch.setattr(metadata, "get_mds_verifier", lambda: global_verifier)
    for name, kwargs in variants:
        for credential, certificate in ((aaguid.bytes, aaguid.bytes), (aaguid.bytes, b"\x01" * 16), (b"", b""), (b"\x05", b"")):
            results = {"authenticator_data": {"algorithm": -7}, "errors": [], "warnings": []}
            checks._finalize_metadata_results(
                results,
                metadata_lookup_source="chain" if kwargs["metadata_entry"] is not None else None,
                credential_aaguid_bytes=credential,
                certificate_aaguid_bytes=certificate,
                root_check_details={"chain": True} if credential else None,
                root_valid=True if certificate else None,
                **kwargs,
            )
            record[f"{name}/{credential.hex() or '-'}/{certificate.hex() or '-'}"] = harness.json_safe(results)
    harness.check_golden("metadata-finalisation.json", record)
