from __future__ import annotations

import base64

from server.app import encoding
from server.app.routes.advanced import parsing as advanced_parsing
from server.app.routes.advanced import summary as advanced_summary
from server.app.webauthn import client_binary, client_credentials, cose_algorithms


def test_algorithm_name_normalization_lookup_and_coercion_matrix():
    assert cose_algorithms.normalise_name(" FIDO ALG ES-256 (ECDSA) ") == "ES256"
    assert cose_algorithms.normalise_name("") == ""
    assert cose_algorithms.normalise_name("COSE ALG RS-256") == "RS256"

    assert cose_algorithms.lookup_name("ES256") == -7
    assert cose_algorithms.lookup_name("FIDO ALG RS-256") == -257
    assert cose_algorithms.lookup_name("unknown") is None

    assert cose_algorithms.coerce_cose_algorithm(-7) == -7
    assert cose_algorithms.coerce_cose_algorithm(3.0) == 3
    assert cose_algorithms.coerce_cose_algorithm(3.5) is None
    assert cose_algorithms.coerce_cose_algorithm("-257") == -257
    assert cose_algorithms.coerce_cose_algorithm("ES256") == -7
    assert cose_algorithms.coerce_cose_algorithm("algorithm id: -49") == -49
    assert cose_algorithms.coerce_cose_algorithm(True) is None


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


def test_base64_assertion_and_binary_extraction_helpers():
    encoded = base64.urlsafe_b64encode(b"abc").decode("ascii").rstrip("=")
    assert encoding.decode_base64url(encoded) == b"abc"

    assert client_binary.decode_base64url_bytes(encoded) == b"abc"
    assert client_binary.decode_base64url_bytes(b"xyz") == b"xyz"
    assert client_binary.decode_base64url_bytes("%%%") == b""

    assert client_binary.extract_assertion_credential_id({"rawId": encoded}) == b"abc"
    assert client_binary.extract_assertion_credential_id({"id": b"id-bytes"}) == b"id-bytes"
    # Was b"" here and None on the simple side; the two share one helper now.
    assert client_binary.extract_assertion_credential_id({"rawId": "%%%"}) is None

    assert client_binary.unwrap_request_value({"$hex": "616263"}) == b"abc"
    assert client_binary.unwrap_request_value({"$base64": "YWJj"}) == b"abc"
    assert client_binary.unwrap_request_value({"$base64url": "YWJj"}) == b"abc"
    assert client_binary.unwrap_request_value("plain") == "plain"
