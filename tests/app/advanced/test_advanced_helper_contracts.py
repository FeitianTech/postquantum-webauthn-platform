from __future__ import annotations

from server.app.routes.advanced import parsing as advanced_parsing
from server.app.routes.advanced import summary as advanced_summary
from server.app.webauthn import client_credentials, cose_algorithms


def test_storage_id_and_summary_helpers_strip_heavy_fields_and_add_artifact_markers():
    storage_id = advanced_summary._generate_storage_id("abcdefghijklmnopqrstuvwxyz")
    assert "::" in storage_id
    assert storage_id.split("::")[0] == "abcdefghijklmnopqrstuvwx"

    assert advanced_summary._summarize_properties({"attestationChecks": {"x": 1}}) is None
    props = advanced_summary._summarize_properties({"residentKey": True, "attestationChecks": {"x": 1}})
    assert props == {"residentKey": True}

    assert advanced_summary._summarize_relying_party({"registrationData": {"x": 1}}) is None
    rp = advanced_summary._summarize_relying_party({"credentialId": "abc", "registrationData": {"x": 1}})
    assert rp == {"credentialId": "abc"}

    stored = {
        "credentialId": "cred",
        "registrationResponse": {"big": True},
        "properties": {"residentKey": True, "attestationChecks": {"x": 1}},
        "relyingParty": {"credentialId": "cred", "registrationData": {"blob": True}},
    }
    summary = advanced_summary._summarize_stored_credential(stored, "storage-id")

    assert "registrationResponse" not in summary
    assert summary["properties"] == {"residentKey": True}
    assert summary["relyingParty"] == {"credentialId": "cred"}
    assert summary["storageId"] == "storage-id"
    assert summary["hasServerArtifact"] is True


def test_extract_credential_algorithm_from_mapping_and_objects():
    mapping = {"credential_id": b"cred", "public_key": {3: -7}}
    assert cose_algorithms.credential_algorithm(mapping) == -7

    class _CredentialObj:
        credential_id = b"obj-cred"
        public_key = {"alg": -257}

    assert cose_algorithms.credential_algorithm(_CredentialObj()) == -257

    class _IndexablePublicKey:
        alg = -8

        def __getitem__(self, key):
            if key == 3:
                return -8
            raise KeyError(key)

    class _IndexableCredentialObj:
        credential_id = None
        public_key = _IndexablePublicKey()

    assert cose_algorithms.credential_algorithm(_IndexableCredentialObj()) == -8


def test_optional_bool_flag_and_first_value_helpers():
    assert advanced_parsing._coerce_optional_bool(True) is True
    assert advanced_parsing._coerce_optional_bool(0) is False
    assert advanced_parsing._coerce_optional_bool("yes") is True
    assert advanced_parsing._coerce_optional_bool("No") is False
    assert advanced_parsing._coerce_optional_bool(float("nan")) is None
    assert advanced_parsing._coerce_optional_bool("maybe") is None

    mapping = {"resident": "maybe", "residentKey": "true"}
    assert advanced_parsing._extract_flag_from_mapping(mapping, ("resident", "residentKey")) is True
    assert advanced_parsing._extract_flag_from_mapping({}, ("resident",)) is None

    values = {"first": None, "second": 0, "third": "x"}
    assert client_credentials.select_first(values, ("first", "second", "third")) == 0
    assert client_credentials.select_first(values, ("first", "second", "third"), skip_none=False) is None
