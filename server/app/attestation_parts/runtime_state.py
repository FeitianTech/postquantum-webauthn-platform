"""Shared constants for the attestation_parts fragments.

This module is the single home for the constants the attestation runtime
shares between fragments and re-exports through :mod:`server.app.attestation`.
It is deliberately a leaf: it imports nothing from ``server.app`` and nothing
from its sibling fragments, so any fragment can depend on it without creating
a cycle.

Unlike the metadata runtime, the attestation fragments keep no mutable state --
there are no caches, locks or ``global`` statements to park here, only these
two lookup tables, which are read and never rebound.
"""
from __future__ import annotations

from typing import Any

from cryptography.x509.oid import ObjectIdentifier

AAGUID_EXTENSION_OID = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

EXTENSION_DISPLAY_METADATA: dict[str, dict[str, Any]] = {
    "1.3.6.1.4.1.41482.13.1": {
        "friendly_name": "Yubico: Firmware version",
    },
    "1.3.6.1.4.1.41482.2": {
        "friendly_name": "Yubico: Device identifier",
    },
    "1.3.6.1.4.1.41482.1.1": {
        "friendly_name": "Security Key by Yubico Series",
    },
    "1.3.6.1.4.1.45724.1.1.4": {
        "friendly_name": "FIDO: Device AAGUID",
    },
    "1.3.6.1.4.1.45724.2.1.1": {
        "friendly_name": "FIDO: Transports",
    },
    "2.5.29.14": {
        "friendly_name": "Subject key id",
    },
    "2.5.29.35": {
        "friendly_name": "Authority key identifier",
    },
    "2.5.29.19": {
        "friendly_name": "X509v3 Basic Constraints",
        "header": "X509v3 Basic Constraints",
        "include_oid_in_header": False,
    },
}
