from __future__ import annotations

from server.app.routes.advanced import summary as advanced_summary


def test_summary_helpers_drop_non_mapping_inputs_and_nested_non_mapping_sections():
    assert advanced_summary._summarize_properties("not-a-mapping") is None
    assert advanced_summary._summarize_relying_party(["not-a-mapping"]) is None

    summary = advanced_summary._summarize_stored_credential(
        {
            "credentialId": "cred",
            "registrationResponse": {"heavy": True},
            "properties": "invalid-shape",
            "relyingParty": ["invalid-shape"],
        },
        "storage-id",
    )

    assert "registrationResponse" not in summary
    assert "properties" not in summary
    assert "relyingParty" not in summary
    assert summary["storageId"] == "storage-id"
    assert summary["localStorageId"] == "storage-id"
