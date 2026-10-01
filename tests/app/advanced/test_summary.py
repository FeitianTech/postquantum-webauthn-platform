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
