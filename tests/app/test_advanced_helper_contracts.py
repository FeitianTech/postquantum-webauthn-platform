from __future__ import annotations

import base64

import pytest


def test_algorithm_name_normalization_lookup_and_coercion_matrix():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._normalize_algorithm_name_key(" FIDO ALG ES-256 (ECDSA) ") == "ES256"
    assert advanced_module._normalize_algorithm_name_key("") == ""
    assert advanced_module._normalize_algorithm_name_key("COSE ALG RS-256") == "RS256"

    assert advanced_module._lookup_named_cose_algorithm("ES256") == -7
    assert advanced_module._lookup_named_cose_algorithm("FIDO ALG RS-256") == -257
    assert advanced_module._lookup_named_cose_algorithm("unknown") is None

    assert advanced_module._coerce_cose_algorithm(-7) == -7
    assert advanced_module._coerce_cose_algorithm(3.0) == 3
    assert advanced_module._coerce_cose_algorithm(3.5) is None
    assert advanced_module._coerce_cose_algorithm("-257") == -257
    assert advanced_module._coerce_cose_algorithm("ES256") == -7
    assert advanced_module._coerce_cose_algorithm("algorithm id: -49") == -49
    assert advanced_module._coerce_cose_algorithm(True) is None


def test_storage_id_and_summary_helpers_strip_heavy_fields_and_add_artifact_markers():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    storage_id = advanced_module._generate_storage_id("abcdefghijklmnopqrstuvwxyz")
    assert "::" in storage_id
    assert storage_id.split("::")[0] == "abcdefghijklmnopqrstuvwx"

    assert advanced_module._summarize_properties({"attestationChecks": {"x": 1}}) is None
    props = advanced_module._summarize_properties({"residentKey": True, "attestationChecks": {"x": 1}})
    assert props == {"residentKey": True}

    assert advanced_module._summarize_relying_party({"registrationData": {"x": 1}}) is None
    rp = advanced_module._summarize_relying_party({"credentialId": "abc", "registrationData": {"x": 1}})
    assert rp == {"credentialId": "abc"}

    stored = {
        "credentialId": "cred",
        "registrationResponse": {"big": True},
        "properties": {"residentKey": True, "attestationChecks": {"x": 1}},
        "relyingParty": {"credentialId": "cred", "registrationData": {"blob": True}},
    }
    summary = advanced_module._summarize_stored_credential(stored, "storage-id")

    assert "registrationResponse" not in summary
    assert summary["properties"] == {"residentKey": True}
    assert summary["relyingParty"] == {"credentialId": "cred"}
    assert summary["storageId"] == "storage-id"
    assert summary["hasServerArtifact"] is True


def test_extract_credential_id_and_algorithm_from_mapping_and_objects():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    mapping = {"credential_id": b"cred", "public_key": {3: -7}}
    assert advanced_module._extract_credential_id(mapping) == b"cred"
    assert advanced_module._extract_credential_algorithm(mapping) == -7

    class _CredentialObj:
        credential_id = b"obj-cred"
        public_key = {"alg": -257}

    assert advanced_module._extract_credential_id(_CredentialObj()) == b"obj-cred"
    assert advanced_module._extract_credential_algorithm(_CredentialObj()) == -257

    class _IndexablePublicKey:
        alg = -8

        def __getitem__(self, key):
            if key == 3:
                return -8
            raise KeyError(key)

    class _IndexableCredentialObj:
        credential_id = None
        public_key = _IndexablePublicKey()

    assert advanced_module._extract_credential_id(_IndexableCredentialObj()) is None
    assert advanced_module._extract_credential_algorithm(_IndexableCredentialObj()) == -8


def test_optional_bool_flag_and_first_value_helpers():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._coerce_optional_bool(True) is True
    assert advanced_module._coerce_optional_bool(0) is False
    assert advanced_module._coerce_optional_bool("yes") is True
    assert advanced_module._coerce_optional_bool("No") is False
    assert advanced_module._coerce_optional_bool(float("nan")) is None
    assert advanced_module._coerce_optional_bool("maybe") is None

    mapping = {"resident": "maybe", "residentKey": "true"}
    assert advanced_module._extract_flag_from_mapping(mapping, ("resident", "residentKey")) is True
    assert advanced_module._extract_flag_from_mapping({}, ("resident",)) is None

    values = {"first": None, "second": 0, "third": "x"}
    assert advanced_module._select_first(values, ("first", "second", "third")) == 0


def test_base64_assertion_and_binary_extraction_helpers():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    encoded = base64.urlsafe_b64encode(b"abc").decode("ascii").rstrip("=")
    assert advanced_module._decode_base64url(encoded) == b"abc"

    assert advanced_module._decode_base64url_bytes(encoded) == b"abc"
    assert advanced_module._decode_base64url_bytes(b"xyz") == b"xyz"
    assert advanced_module._decode_base64url_bytes("%%%") == b""

    assert advanced_module._extract_assertion_credential_id({"rawId": encoded}) == b"abc"
    assert advanced_module._extract_assertion_credential_id({"id": b"id-bytes"}) == b"id-bytes"
    assert advanced_module._extract_assertion_credential_id({"rawId": "%%%"}) == b""

    assert advanced_module._extract_binary_value({"$hex": "616263"}) == b"abc"
    assert advanced_module._extract_binary_value({"$base64": "YWJj"}) == b"abc"
    assert advanced_module._extract_binary_value({"$base64url": "YWJj"}) == b"abc"
    assert advanced_module._extract_binary_value("plain") == "plain"


def test_custom_algorithm_detection_and_attestation_logging(monkeypatch):
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._is_custom_cose_algorithm(None) is False
    assert advanced_module._is_custom_cose_algorithm(-7) is False
    assert advanced_module._is_custom_cose_algorithm(-50) is False
    assert advanced_module._is_custom_cose_algorithm(-99999) is True

    log_calls = []
    monkeypatch.setattr(
        advanced_module.app.logger,
        "info",
        lambda message, payload: log_calls.append((message, payload)),
        raising=False,
    )

    class _Flag:
        UP = 0x01
        UV = 0x04
        BE = 0x08
        BS = 0x10
        AT = 0x40
        ED = 0x80

    class _CredentialData:
        aaguid = b"\x00" * 16
        credential_id = b"credential"
        public_key = {3: -7, -2: b"x" * 32, -3: b"y" * 32}

    class _AuthData:
        FLAG = _Flag
        rp_id_hash = b"\x11" * 32
        flags = _Flag.UP | _Flag.AT
        counter = 7
        credential_data = _CredentialData()
        extensions = {"credProps": {"rk": True}}

        def __bytes__(self):
            return b"\x00" * 37

    advanced_module._log_authenticator_attestation_response(
        "packed",
        _AuthData(),
        {"alg": -7},
        b"\x01\x02\x03",
    )

    assert len(log_calls) == 1
    assert "Authenticator attestation response" in log_calls[0][0]
    assert '"fmt": "packed"' in log_calls[0][1]
    assert "rawAttestationObject" in log_calls[0][1]

    log_calls.clear()
    advanced_module._log_authenticator_attestation_response("packed", None, {}, b"\x01")
    assert log_calls == []
