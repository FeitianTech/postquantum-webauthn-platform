from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest


class _CredentialData:
    def __init__(self, public_key=None):
        self.credential_id = b"credential-id"
        self.public_key = public_key if public_key is not None else {3: -7}
        self.aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")


class _AuthData:
    def __init__(self, *, rp_id: str, flags: int, credential_data: _CredentialData | None = None):
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = flags
        self.counter = 1
        self.credential_data = credential_data or _CredentialData()

    def __bytes__(self):
        return b"auth-data"


class _ClientData:
    def __init__(self, *, challenge: bytes, origin: str):
        self.type = "webauthn.create"
        self.challenge = challenge
        self.origin = origin
        self.cross_origin = False
        self.hash = hashlib.sha256(b"client-data").digest()


def _registration(attestation_object, client_data):
    return SimpleNamespace(
        response=SimpleNamespace(
            attestation_object=attestation_object,
            client_data=client_data,
        ),
        client_extension_results={},
    )


def test_coerce_certificate_bytes_falls_back_to_hex_parsing_when_base64_decode_fails(
    monkeypatch,
):
    attestation_module = pytest.importorskip("server.app.attestation")

    monkeypatch.setattr(
        attestation_module.base64,
        "b64decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad-base64")),
        raising=False,
    )

    assert attestation_module._coerce_certificate_bytes("0a0b") == b"\x0a\x0b"
    assert attestation_module._coerce_certificate_bytes("zz") is None


def test_extract_certificate_aaguid_handles_non_hex_string_extension_values(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    class _ExtensionValue:
        value = "Z" * 16

    class _Extension:
        value = _ExtensionValue()

    class _Extensions:
        def get_extension_for_oid(self, _oid):
            return _Extension()

    class _Certificate:
        extensions = _Extensions()

    monkeypatch.setattr(
        attestation_module.x509,
        "load_der_x509_certificate",
        lambda _data: _Certificate(),
        raising=False,
    )

    extracted = attestation_module._extract_certificate_aaguid(b"cert")
    assert extracted == b"Z" * 16


def test_attempt_pqc_attestation_signature_validation_reports_public_key_construction_errors(
    monkeypatch,
):
    attestation_module = pytest.importorskip("server.app.attestation")

    monkeypatch.setattr(
        attestation_module,
        "extract_certificate_public_key_info",
        lambda _cert: {"subject_public_key": b"pub"},
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module.CoseKey,
        "for_alg",
        lambda _alg: (
            lambda _mapping: (_ for _ in ()).throw(ValueError("invalid-public-key"))
        ),
        raising=False,
    )

    outcome = attestation_module._attempt_pqc_attestation_signature_validation(
        SimpleNamespace(
            att_stmt={"alg": -49, "sig": b"sig", "x5c": [b"cert"]},
            auth_data=SimpleNamespace(credential_data=SimpleNamespace(public_key={}), __bytes__=lambda self=None: b"auth"),
        ),
        b"client-hash",
    )

    assert outcome["attempted"] is True
    assert outcome["error"].startswith("pqc_attestation_public_key_invalid:")


def test_coerce_attestation_certificate_bytes_string_path_uses_websafe_decode_fallback(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    monkeypatch.setattr(
        attestation_module.base64,
        "b64decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad-base64")),
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "websafe_decode",
        lambda _value: b"\x01\x02",
        raising=False,
    )
    assert attestation_module._coerce_attestation_certificate_bytes("AQI") == b"\x01\x02"

    monkeypatch.setattr(
        attestation_module,
        "websafe_decode",
        lambda _value: (_ for _ in ()).throw(ValueError("bad-websafe")),
        raising=False,
    )
    assert attestation_module._coerce_attestation_certificate_bytes("AQI") is None


def test_evaluate_mldsa_attestation_root_clears_chain_errors_after_later_success(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    metadata_entry = SimpleNamespace(metadata_statement=SimpleNamespace())
    monkeypatch.setattr(
        attestation_module,
        "_find_metadata_entry_for_aaguid",
        lambda _verifier, _aaguid: metadata_entry,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_collect_metadata_root_certificates",
        lambda _entry: [b"root-a", b"root-b"],
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_is_trusted_ca_certificate",
        lambda _root, allow_subject_parsing=False: True,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "metadata_entry_trust_anchor_status",
        lambda _entry: None,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_collect_trust_path_entries",
        lambda _x5c: [b"leaf"],
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_verify_pqc_attestation_chain",
        lambda _trust_path, root, now: (False, ["dup", "dup"])
        if root == b"root-a"
        else (True, []),
        raising=False,
    )

    outcome = attestation_module._evaluate_mldsa_attestation_root(
        SimpleNamespace(att_stmt={"x5c": [b"leaf"]}),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        verifier=object(),
        now=datetime.now(timezone.utc),
    )

    assert outcome["checks"]["chain"] is True
    assert "dup" not in outcome["errors"]


def test_evaluate_mldsa_attestation_root_deduplicates_chain_errors_when_all_roots_fail(
    monkeypatch,
):
    attestation_module = pytest.importorskip("server.app.attestation")

    metadata_entry = SimpleNamespace(metadata_statement=SimpleNamespace())
    monkeypatch.setattr(
        attestation_module,
        "_find_metadata_entry_for_aaguid",
        lambda _verifier, _aaguid: metadata_entry,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_collect_metadata_root_certificates",
        lambda _entry: [b"root-a", b"root-b"],
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_is_trusted_ca_certificate",
        lambda _root, allow_subject_parsing=False: True,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "metadata_entry_trust_anchor_status",
        lambda _entry: None,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_collect_trust_path_entries",
        lambda _x5c: [b"leaf"],
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_verify_pqc_attestation_chain",
        lambda _trust_path, _root, now: (False, ["dup", "dup"]),
        raising=False,
    )

    outcome = attestation_module._evaluate_mldsa_attestation_root(
        SimpleNamespace(att_stmt={"x5c": [b"leaf"]}),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        verifier=object(),
        now=datetime.now(timezone.utc),
    )

    assert outcome["checks"]["chain"] is False
    assert outcome["errors"].count("dup") == 1


def test_normalise_signature_algorithm_name_covers_ed448_and_dsa_paths():
    attestation_module = pytest.importorskip("server.app.attestation")

    assert attestation_module._normalise_signature_algorithm_name("ed448 with shake") == "ED448"
    assert attestation_module._normalise_signature_algorithm_name("dsa-with-sha1") == "DSA"


def test_perform_attestation_checks_coerces_string_challenge_via_utf8_fallback_and_records_attestation_error(
    monkeypatch,
):
    attestation_module = pytest.importorskip("server.app.attestation")

    flags = int(attestation_module.AuthenticatorData.FLAG.UP | attestation_module.AuthenticatorData.FLAG.AT)
    auth_data = _AuthData(rp_id="example.com", flags=flags)
    challenge = b"raw:text:challenge"
    client_data = _ClientData(challenge=challenge, origin="https://example.com")
    attestation_object = SimpleNamespace(fmt="packed", att_stmt={}, auth_data=auth_data)

    monkeypatch.setattr(
        attestation_module.RegistrationResponse,
        "from_dict",
        lambda _response: _registration(attestation_object, client_data),
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "websafe_decode",
        lambda _value: (_ for _ in ()).throw(ValueError("bad-websafe")),
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module.base64,
        "b64decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad-base64")),
        raising=False,
    )

    class _AttestationVerifier:
        def verify(self, _att_stmt, _auth_data, _client_hash):
            raise RuntimeError("boom")

    monkeypatch.setattr(
        attestation_module.Attestation,
        "for_type",
        lambda _fmt: _AttestationVerifier,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_attempt_pqc_attestation_signature_validation",
        lambda _att_obj, _client_hash: {"attempted": False, "success": False, "error": None},
        raising=False,
    )
    monkeypatch.setattr(attestation_module, "get_mds_verifier", lambda: None, raising=False)

    result = attestation_module.perform_attestation_checks(
        response={"dummy": True},
        state={"challenge": challenge.decode("utf-8")},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["client_data"]["challenge_matches"] is True
    assert result["signature_valid"] is False
    assert any(err.startswith("attestation_error:") for err in result["errors"])


def test_perform_attestation_checks_falls_back_to_public_key_options_when_state_hex_wrapper_is_invalid(
    monkeypatch,
):
    attestation_module = pytest.importorskip("server.app.attestation")

    flags = int(attestation_module.AuthenticatorData.FLAG.UP | attestation_module.AuthenticatorData.FLAG.AT)
    auth_data = _AuthData(rp_id="example.com", flags=flags)
    challenge = b"fallback-challenge"
    client_data = _ClientData(challenge=challenge, origin="https://example.com")
    attestation_object = SimpleNamespace(fmt="none", att_stmt={}, auth_data=auth_data)

    monkeypatch.setattr(
        attestation_module.RegistrationResponse,
        "from_dict",
        lambda _response: _registration(attestation_object, client_data),
        raising=False,
    )
    monkeypatch.setattr(attestation_module, "get_mds_verifier", lambda: None, raising=False)

    result = attestation_module.perform_attestation_checks(
        response={"dummy": True},
        state={"challenge": {"$hex": "zz"}},
        public_key_options={
            "challenge": challenge,
            "pubKeyCredParams": [{"alg": -7}],
        },
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["client_data"]["challenge_matches"] is True
    assert "challenge_mismatch" not in result["errors"]
