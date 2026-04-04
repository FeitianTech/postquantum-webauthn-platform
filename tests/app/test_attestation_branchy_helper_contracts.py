from __future__ import annotations

import base64
import hashlib
import math
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class _CredentialData:
    def __init__(
        self,
        *,
        credential_id: object = b"credential-id",
        public_key: object | None = None,
        aaguid: object = bytes.fromhex("00112233445566778899aabbccddeeff"),
    ):
        self.credential_id = credential_id
        self.public_key = public_key or {
            1: 2,
            3: -7,
            -1: 1,
            -2: b"\x01" * 32,
            -3: b"\x02" * 32,
        }
        self.aaguid = aaguid


class _AuthData:
    def __init__(
        self,
        *,
        rp_id: str,
        flags: int,
        counter: int = 1,
        credential_data: _CredentialData | None = None,
    ):
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = flags
        self.counter = counter
        self.credential_data = credential_data or _CredentialData()

    def __bytes__(self):
        return b"auth-data"


class _ClientData:
    def __init__(
        self,
        *,
        challenge: bytes,
        origin: str,
        type_value: str = "webauthn.create",
        cross_origin: bool = False,
    ):
        self.type = type_value
        self.challenge = challenge
        self.origin = origin
        self.cross_origin = cross_origin
        self.hash = hashlib.sha256(b"client-data").digest()


def _registration(attestation_object, client_data):
    return SimpleNamespace(
        response=SimpleNamespace(
            attestation_object=attestation_object,
            client_data=client_data,
        ),
        client_extension_results={},
    )


def test_perform_attestation_checks_rejects_non_mapping_response():
    attestation_module = pytest.importorskip("server.app.attestation")

    result = attestation_module.perform_attestation_checks(
        response=["not-a-mapping"],
        state=None,
        public_key_options=None,
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["errors"] == ["registration_response_invalid"]


def test_perform_attestation_checks_coerces_challenge_from_base64_and_hex_wrappers(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    flags = int(attestation_module.AuthenticatorData.FLAG.UP | attestation_module.AuthenticatorData.FLAG.AT)
    auth_data = _AuthData(rp_id="example.com", flags=flags)
    challenge = b"challenge-from-hex"
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
        state={"challenge": {"$base64": "%%%"}},
        public_key_options={
            "challenge": {"$hex": challenge.hex()},
            "pubKeyCredParams": [{"alg": -7}],
        },
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["client_data"]["challenge_matches"] is True
    assert result["client_data"]["expected_challenge"] == _b64url(challenge)
    assert "challenge_mismatch" not in result["errors"]


def test_perform_attestation_checks_accepts_base64url_wrapped_challenge_and_enum_uv(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    flags = int(
        attestation_module.AuthenticatorData.FLAG.UP
        | attestation_module.AuthenticatorData.FLAG.UV
        | attestation_module.AuthenticatorData.FLAG.AT
    )
    auth_data = _AuthData(rp_id="example.com", flags=flags)
    challenge = b"challenge-base64url"
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
        state={
            "challenge": {"$base64url": _b64url(challenge)},
            "user_verification": SimpleNamespace(value="required"),
        },
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        auth_data=None,
        expected_origin="https://example.com/",
        rp_id="example.com",
    )

    assert result["client_data"]["challenge_matches"] is True
    assert result["client_data"]["origin_valid"] is True
    assert result["authenticator_data"]["user_verification_required"] is True
    assert result["authenticator_data"]["user_verification_satisfied"] is True


def test_perform_attestation_checks_handles_broken_credential_shapes(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    class _BrokenPublicKey:
        def __iter__(self):
            raise TypeError("cannot iterate")

        def get(self, _name):
            raise RuntimeError("cannot read alg")

    broken_credential_data = _CredentialData(
        credential_id=123,
        public_key=_BrokenPublicKey(),
        aaguid=object(),
    )
    flags = int(attestation_module.AuthenticatorData.FLAG.UP | attestation_module.AuthenticatorData.FLAG.AT)
    auth_data = _AuthData(
        rp_id="example.com",
        flags=flags,
        credential_data=broken_credential_data,
    )
    client_data = _ClientData(challenge=b"x", origin="https://example.com")
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
        state={"challenge": b"x"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["authenticator_data"]["credential_id_length"] is None
    assert result["authenticator_data"]["credential_aaguid"] is None
    assert result["authenticator_data"]["algorithm"] is None
    assert result["authenticator_data"]["cose_key_valid"] is False
    assert "algorithm_not_allowed" in result["errors"]
    assert any(err.startswith("cose_key_error:") for err in result["errors"])


def test_perform_attestation_checks_uses_fallback_metadata_lookup_and_mapping_roots(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    class _MetadataAaguid:
        def __str__(self):
            return "00112233-4455-6677-8899-aabbccddeeff"

        def __bytes__(self):
            return bytes.fromhex("00112233445566778899aabbccddeeff")

    metadata_entry = SimpleNamespace(
        metadata_statement={"attestationRootCertificates": "present-root"},
        aaguid=_MetadataAaguid(),
    )
    verifier = SimpleNamespace(find_entry_by_aaguid=lambda _aaguid: metadata_entry)

    flags = int(attestation_module.AuthenticatorData.FLAG.UP | attestation_module.AuthenticatorData.FLAG.AT)
    auth_data = _AuthData(rp_id="example.com", flags=flags)
    client_data = _ClientData(challenge=b"meta", origin="https://example.com")
    attestation_object = SimpleNamespace(fmt="none", att_stmt={}, auth_data=auth_data)

    monkeypatch.setattr(
        attestation_module.RegistrationResponse,
        "from_dict",
        lambda _response: _registration(attestation_object, client_data),
        raising=False,
    )
    monkeypatch.setattr(attestation_module, "get_mds_verifier", lambda: verifier, raising=False)

    result = attestation_module.perform_attestation_checks(
        response={"dummy": True},
        state={"challenge": b"meta"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["metadata"]["available"] is True
    assert result["metadata"]["source"] == "aaguid"
    assert result["metadata"]["root_certificates_present"] is True
    assert result["metadata"]["aaguid"] == "00112233-4455-6677-8899-aabbccddeeff"


def test_perform_attestation_checks_ignores_metadata_fallback_lookup_exceptions(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    class _FailingVerifier:
        def find_entry_by_aaguid(self, _aaguid):
            raise RuntimeError("lookup failure")

    flags = int(attestation_module.AuthenticatorData.FLAG.UP | attestation_module.AuthenticatorData.FLAG.AT)
    auth_data = _AuthData(rp_id="example.com", flags=flags)
    client_data = _ClientData(challenge=b"meta2", origin="https://example.com")
    attestation_object = SimpleNamespace(fmt="none", att_stmt={}, auth_data=auth_data)

    monkeypatch.setattr(
        attestation_module.RegistrationResponse,
        "from_dict",
        lambda _response: _registration(attestation_object, client_data),
        raising=False,
    )
    monkeypatch.setattr(attestation_module, "get_mds_verifier", lambda: _FailingVerifier(), raising=False)

    result = attestation_module.perform_attestation_checks(
        response={"dummy": True},
        state={"challenge": b"meta2"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["metadata"]["available"] is False


def test_evaluate_classical_attestation_root_handles_missing_trust_path_and_metadata():
    attestation_module = pytest.importorskip("server.app.attestation")

    outcome = attestation_module._evaluate_classical_attestation_root(
        SimpleNamespace(att_stmt={}),
        SimpleNamespace(trust_path=[]),
        b"client-hash",
        verifier=None,
        now=datetime.now(timezone.utc),
    )

    assert "trust_path_missing" in outcome["errors"]
    assert "metadata_not_available" in outcome["warnings"]
    assert outcome["checks"]["trusted_ca"] is False
    assert outcome["root_valid"] is None


def test_evaluate_classical_attestation_root_records_parse_and_verifier_failures(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    class _FailingVerifier:
        def evaluate_attestation(self, _att_obj, _client_hash):
            raise RuntimeError("verifier exploded")

    monkeypatch.setattr(
        attestation_module,
        "verify_x509_chain",
        lambda _chain: (_ for _ in ()).throw(attestation_module.InvalidSignature("bad chain")),
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module.x509,
        "load_der_x509_certificate",
        lambda _der: (_ for _ in ()).throw(ValueError("bad cert")),
        raising=False,
    )

    outcome = attestation_module._evaluate_classical_attestation_root(
        SimpleNamespace(att_stmt={}),
        SimpleNamespace(trust_path=[b"broken-cert"]),
        b"client-hash",
        verifier=_FailingVerifier(),
        now=datetime.now(timezone.utc),
    )

    assert any(err.startswith("certificate_parse_error:") for err in outcome["errors"])
    assert any(err.startswith("untrusted_attestation:") for err in outcome["errors"])
    assert "metadata_entry_missing" in outcome["errors"]
    assert outcome["checks"]["trusted_ca"] is False


def test_evaluate_classical_attestation_root_reports_untrusted_root_and_mds_errors(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    now = datetime.now(timezone.utc)
    valid_cert = SimpleNamespace(
        subject=SimpleNamespace(rfc4514_string=lambda: "CN=Leaf"),
        not_valid_before_utc=now - timedelta(days=1),
        not_valid_after_utc=now + timedelta(days=1),
    )
    trust_details = attestation_module.TrustPathEvaluation(
        attestation_result=None,
        ca_certificate=b"root-ca",
        chain_valid=True,
        errors=["mds_chain_warning"],
    )
    evaluation = SimpleNamespace(
        trust_path=trust_details,
        metadata_entry=SimpleNamespace(metadata_statement=SimpleNamespace()),
        metadata_lookup_source="aaguid",
    )

    monkeypatch.setattr(attestation_module, "verify_x509_chain", lambda _chain: None, raising=False)
    monkeypatch.setattr(attestation_module.x509, "load_der_x509_certificate", lambda _der: valid_cert, raising=False)
    monkeypatch.setattr(attestation_module, "_collect_metadata_root_certificates", lambda _entry: [b"meta-root"], raising=False)
    monkeypatch.setattr(attestation_module, "_is_trusted_ca_certificate", lambda _root: False, raising=False)

    verifier = SimpleNamespace(evaluate_attestation=lambda _obj, _hash: evaluation)
    outcome = attestation_module._evaluate_classical_attestation_root(
        SimpleNamespace(att_stmt={}),
        SimpleNamespace(trust_path=[b"leaf"]),
        b"client-hash",
        verifier=verifier,
        now=now,
    )

    assert "mds_chain_warning" in outcome["errors"]
    assert "attestation_root_not_trusted" in outcome["errors"]
    assert outcome["checks"]["trusted_ca"] is False
    assert outcome["metadata_lookup_source"] == "aaguid"


def test_evaluate_classical_attestation_root_forces_chain_false_on_expired_leaf(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    now = datetime.now(timezone.utc)
    expired_cert = SimpleNamespace(
        subject=SimpleNamespace(rfc4514_string=lambda: "CN=Expired"),
        not_valid_before_utc=now - timedelta(days=10),
        not_valid_after_utc=now - timedelta(seconds=1),
    )
    trust_details = attestation_module.TrustPathEvaluation(
        attestation_result=None,
        ca_certificate=b"trusted-root",
        chain_valid=True,
        errors=[],
    )
    metadata_entry = SimpleNamespace(metadata_statement=SimpleNamespace())
    evaluation = SimpleNamespace(
        trust_path=trust_details,
        metadata_entry=metadata_entry,
        metadata_lookup_source="aaguid",
    )

    monkeypatch.setattr(attestation_module, "verify_x509_chain", lambda _chain: None, raising=False)
    monkeypatch.setattr(attestation_module.x509, "load_der_x509_certificate", lambda _der: expired_cert, raising=False)
    monkeypatch.setattr(attestation_module, "_collect_metadata_root_certificates", lambda _entry: [], raising=False)
    monkeypatch.setattr(attestation_module, "_is_trusted_ca_certificate", lambda _root: True, raising=False)
    monkeypatch.setattr(attestation_module, "metadata_entry_trust_anchor_status", lambda _entry: False, raising=False)

    verifier = SimpleNamespace(evaluate_attestation=lambda _obj, _hash: evaluation)
    outcome = attestation_module._evaluate_classical_attestation_root(
        SimpleNamespace(att_stmt={}),
        SimpleNamespace(trust_path=[b"expired-leaf"]),
        b"client-hash",
        verifier=verifier,
        now=now,
    )

    assert any(err.startswith("certificate_out_of_validity:") for err in outcome["errors"])
    assert "metadata_not_fido_trusted" in outcome["errors"]
    assert outcome["checks"]["trusted_ca"] is True
    assert outcome["checks"]["fido_mds"] is False
    assert outcome["checks"]["chain"] is False
    assert outcome["root_valid"] is False


def test_attempt_pqc_attestation_signature_validation_covers_trust_path_error_paths(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    auth_data = SimpleNamespace(credential_data=SimpleNamespace(public_key={}), __bytes__=lambda self=None: b"auth")

    monkeypatch.setattr(
        attestation_module.CoseKey,
        "for_alg",
        lambda _alg: (_ for _ in ()).throw(RuntimeError("unsupported")),
        raising=False,
    )
    unsupported = attestation_module._attempt_pqc_attestation_signature_validation(
        SimpleNamespace(att_stmt={"alg": -49, "sig": b"sig"}, auth_data=auth_data),
        b"client-hash",
    )
    assert unsupported["attempted"] is True
    assert unsupported["error"].startswith("pqc_attestation_unsupported_algorithm:")

    monkeypatch.setattr(attestation_module.CoseKey, "for_alg", lambda _alg: (lambda _map: object()), raising=False)
    monkeypatch.setattr(
        attestation_module,
        "extract_certificate_public_key_info",
        lambda _cert: (_ for _ in ()).throw(ValueError("bad cert key")),
        raising=False,
    )
    key_error = attestation_module._attempt_pqc_attestation_signature_validation(
        SimpleNamespace(att_stmt={"alg": -49, "sig": b"sig", "x5c": [b"cert"]}, auth_data=auth_data),
        b"client-hash",
    )
    assert key_error["error"].startswith("pqc_attestation_public_key_error:")

    monkeypatch.setattr(
        attestation_module,
        "extract_certificate_public_key_info",
        lambda _cert: {"subject_public_key": None},
        raising=False,
    )
    missing_key = attestation_module._attempt_pqc_attestation_signature_validation(
        SimpleNamespace(att_stmt={"alg": -49, "sig": b"sig", "x5c": [b"cert"]}, auth_data=auth_data),
        b"client-hash",
    )
    assert missing_key["error"] == "pqc_attestation_public_key_missing"


def test_attempt_pqc_attestation_signature_validation_verification_failure_and_success(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    class _VerifyFails:
        def verify(self, _message, _signature):
            raise RuntimeError("invalid signature")

    class _VerifyPasses:
        def verify(self, _message, _signature):
            return None

    class _AuthData:
        credential_data = SimpleNamespace(public_key={})

        def __bytes__(self):
            return b"auth-data"

    monkeypatch.setattr(
        attestation_module,
        "extract_certificate_public_key_info",
        lambda _cert: {"subject_public_key": b"public-key"},
        raising=False,
    )

    monkeypatch.setattr(attestation_module.CoseKey, "for_alg", lambda _alg: (lambda _map: _VerifyFails()), raising=False)
    verify_failed = attestation_module._attempt_pqc_attestation_signature_validation(
        SimpleNamespace(att_stmt={"alg": -49, "sig": b"sig", "x5c": [b"cert"]}, auth_data=_AuthData()),
        b"client-hash",
    )
    assert verify_failed["attempted"] is True
    assert verify_failed["success"] is False
    assert verify_failed["error"].startswith("pqc_attestation_verification_failed:")

    monkeypatch.setattr(attestation_module.CoseKey, "for_alg", lambda _alg: (lambda _map: _VerifyPasses()), raising=False)
    verified = attestation_module._attempt_pqc_attestation_signature_validation(
        SimpleNamespace(att_stmt={"alg": -49, "sig": b"sig", "x5c": [b"cert"]}, auth_data=_AuthData()),
        b"client-hash",
    )
    assert verified["attempted"] is True
    assert verified["success"] is True
    assert list(verified["attestation_result"].trust_path) == [b"cert"]


def test_attempt_pqc_attestation_signature_validation_covers_no_chain_branches(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    monkeypatch.setattr(attestation_module.CoseKey, "for_alg", lambda _alg: object(), raising=False)

    missing_credential = attestation_module._attempt_pqc_attestation_signature_validation(
        SimpleNamespace(att_stmt={"alg": -49, "sig": b"sig"}, auth_data=SimpleNamespace(credential_data=None, __bytes__=lambda self=None: b"auth")),
        b"client-hash",
    )
    assert missing_credential["error"] == "pqc_attestation_credential_data_missing"

    monkeypatch.setattr(
        attestation_module.CoseKey,
        "parse",
        lambda _pk: (_ for _ in ()).throw(ValueError("cannot parse")),
        raising=False,
    )
    parse_error = attestation_module._attempt_pqc_attestation_signature_validation(
        SimpleNamespace(
            att_stmt={"alg": -49, "sig": b"sig"},
            auth_data=SimpleNamespace(
                credential_data=SimpleNamespace(public_key={}),
                __bytes__=lambda self=None: b"auth",
            ),
        ),
        b"client-hash",
    )
    assert parse_error["error"].startswith("pqc_attestation_public_key_parse_error:")


def test_numeric_aaguid_and_extension_helpers_cover_fallback_paths():
    attestation_module = pytest.importorskip("server.app.attestation")

    assert attestation_module.coerce_non_negative_int(True) is None
    assert attestation_module.coerce_non_negative_int(-1) is None
    assert attestation_module.coerce_non_negative_int(3.9) == 3
    assert attestation_module.coerce_non_negative_int(math.inf) is None
    assert attestation_module.coerce_non_negative_int(" 42 ") == 42
    assert attestation_module.coerce_non_negative_int("not-int") is None

    assert attestation_module.normalize_aaguid_string("00112233-4455-6677-8899-aabbccddeeff") == "00112233445566778899aabbccddeeff"
    assert attestation_module.normalize_aaguid_string(123) is None

    class _AaguidBytes:
        def __bytes__(self):
            return bytes.fromhex("00112233445566778899aabbccddeeff")

    class _BadBytes:
        def __bytes__(self):
            raise TypeError("boom")

    assert (
        attestation_module.coerce_aaguid_hex({"value": "00112233-4455-6677-8899-aabbccddeeff"})
        == "00112233445566778899aabbccddeeff"
    )
    assert attestation_module.coerce_aaguid_hex(_AaguidBytes()) == "00112233445566778899aabbccddeeff"
    assert attestation_module.coerce_aaguid_hex(_BadBytes()) is None

    enriched = {"aaguid": {"raw": "00112233-4455-6677-8899-aabbccddeeff"}}
    attestation_module.augment_aaguid_fields(enriched)
    assert enriched["aaguidHex"] == "00112233445566778899aabbccddeeff"
    assert enriched["aaguidRaw"] == "00112233445566778899aabbccddeeff"
    assert "aaguidGuid" in enriched

    stripped = {
        "aaguid": "invalid",
        "aaguidHex": "stale",
        "aaguidGuid": "stale",
        "aaguidRaw": "stale",
    }
    attestation_module.augment_aaguid_fields(stripped)
    assert "aaguidHex" not in stripped
    assert "aaguidGuid" not in stripped
    assert "aaguidRaw" not in stripped

    assert attestation_module.extract_min_pin_length({"minPinLength": 6}) == 6
    assert (
        attestation_module.extract_min_pin_length({"minPinLength": {"minimumPinLength": "9"}})
        == 9
    )
    assert attestation_module.extract_min_pin_length({"minPinLength": {"value": ""}}) is None
    assert attestation_module.extract_min_pin_length(None) is None

    summary = attestation_module.summarize_authenticator_extensions(
        {"credProtect": 2, "hmac-secret": True}
    )
    assert summary["credProtectLabel"] == "userVerificationOptionalWithCredentialIDList"
    assert summary["hmac-secret"] is True

    safe = attestation_module.make_json_safe(
        {
            "bytes": b"abc",
            "list": [bytearray(b"d")],
            "set": {memoryview(b"e")},
        }
    )
    assert safe["bytes"] == _b64url(b"abc")
    assert safe["list"][0] == _b64url(b"d")
    assert safe["set"] == [_b64url(b"e")]


def test_serialize_extension_value_covers_authority_constraints_and_fallback_repr():
    attestation_module = pytest.importorskip("server.app.attestation")

    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo Issuer")])
    aki = x509.AuthorityKeyIdentifier(
        key_identifier=b"\x01\x02",
        authority_cert_issuer=[x509.DirectoryName(issuer_name)],
        authority_cert_serial_number=17,
    )
    aki_value = attestation_module._serialize_extension_value(
        SimpleNamespace(oid=ObjectIdentifier("2.5.29.35"), value=aki)
    )
    assert "Authority Cert Serial Number" in aki_value
    assert aki_value["Authority Cert Issuer"]
    assert "Demo Issuer" in aki_value["Authority Cert Issuer"][0]

    constraints = attestation_module._serialize_extension_value(
        SimpleNamespace(
            oid=ObjectIdentifier("2.5.29.19"),
            value=x509.BasicConstraints(ca=True, path_length=0),
        )
    )
    assert constraints["Path Length"] == 0

    firmware_value = attestation_module._serialize_extension_value(
        SimpleNamespace(
            oid=ObjectIdentifier("1.3.6.1.4.1.41482.13.1"),
            value=x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.41482.13.1"),
                b"\x04\x03\x01\x02\x03",
            ),
        )
    )
    assert firmware_value == {"Firmware version": "1.2.3"}

    aaguid_fallback = attestation_module._serialize_extension_value(
        SimpleNamespace(
            oid=ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"),
            value=x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"),
                b"\x04\x02\xAA\xBB",
            ),
        )
    )
    assert "Hex value" in aaguid_fallback

    class _BadStr:
        def __str__(self):
            raise RuntimeError("cannot stringify")

        def __repr__(self):
            return "<bad-str-value>"

    fallback_repr = attestation_module._serialize_extension_value(
        SimpleNamespace(oid=ObjectIdentifier("1.2.3"), value=_BadStr())
    )
    assert fallback_repr == "<bad-str-value>"


def test_format_x509_name_falls_back_to_string_when_rfc4514_fails():
    attestation_module = pytest.importorskip("server.app.attestation")

    class _BrokenName:
        def rfc4514_string(self):
            raise ValueError("cannot format")

        def __str__(self):
            return "BrokenNameFallback"

    assert attestation_module.format_x509_name(_BrokenName()) == "BrokenNameFallback"
