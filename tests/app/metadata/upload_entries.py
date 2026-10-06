"""The smallest metadata entry a visitor can upload."""

from __future__ import annotations


def minimal_entry(description: str) -> dict:
    """An entry with an AAGUID and a statement that only describes it."""

    return {
        "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "metadataStatement": {
            "description": description,
        },
    }


def _entry_payload(*, aaguid: str, description: str):
    return {
        "aaguid": aaguid,
        "statusReports": [],
        "timeOfLastStatusChange": "2026-01-01",
        "metadataStatement": {
            "description": description,
            "authenticatorVersion": 1,
            "schema": 3,
            "upv": [],
            "attestationTypes": [],
            "userVerificationDetails": [],
            "keyProtection": [],
            "matcherProtection": [],
            "attachmentHint": [],
            "tcDisplay": [],
            "attestationRootCertificates": [],
        },
    }
