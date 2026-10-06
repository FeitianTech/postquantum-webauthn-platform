"""Tests for the summary of a stored advanced credential the page keeps."""

from __future__ import annotations

from server.app.routes.advanced import summary as advanced_summary


def test_the_summary_leaves_out_the_heavy_fields_and_names_its_storage():
    summary = advanced_summary._summarize_stored_credential(
        {
            "credentialId": "credential",
            "attestationObject": "heavy",
            "properties": {"residentKey": True, "attestationChecks": {"heavy": True}},
            "relyingParty": {"rpId": "localhost", "registrationData": {"heavy": True}},
        },
        "storage-id",
    )

    assert summary == {
        "credentialId": "credential",
        "properties": {"residentKey": True},
        "relyingParty": {"rpId": "localhost"},
        "storageId": "storage-id",
        "localStorageId": "storage-id",
        "artifactVersion": 1,
        "hasServerArtifact": True,
    }


def test_sections_that_are_no_objects_or_only_heavy_are_left_out():
    for properties, relying_party in (("not an object", ["not an object"]), ({"attestationChecks": {}}, {"registrationData": {}})):
        summary = advanced_summary._summarize_stored_credential(
            {"credentialId": "credential", "properties": properties, "relyingParty": relying_party},
            "storage-id",
        )

        assert "properties" not in summary
        assert "relyingParty" not in summary


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
