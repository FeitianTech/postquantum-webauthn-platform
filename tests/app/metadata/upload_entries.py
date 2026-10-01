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
