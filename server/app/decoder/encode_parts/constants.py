"""Shared constants for encoder CTAP helpers."""
from __future__ import annotations

import re
from typing import Dict, Sequence, Tuple


_CTAP_LABELED_KEY_PATTERN = re.compile(r"^\s*(-?\d+)\s*\(([^)]+)\)\s*$")

_CTAP_FIELD_LABELS: Dict[str, Dict[int, str]] = {
    "makeCredentialRequest": {
        1: "clientDataHash",
        2: "rp",
        3: "user",
        4: "pubKeyCredParams",
        5: "excludeList",
        6: "extensions",
        7: "options",
        8: "pinUvAuthParam",
        9: "pinUvAuthProtocol",
        10: "enterpriseAttestation",
        11: "largeBlobKey",
    },
    "getAssertionRequest": {
        1: "rpId",
        2: "clientDataHash",
        3: "allowList",
        4: "extensions",
        5: "options",
        6: "pinUvAuthParam",
        7: "pinUvAuthProtocol",
        8: "largeBlobKey",
    },
    "makeCredentialResponse": {
        1: "fmt",
        2: "authData",
        3: "attStmt",
        4: "epAtt",
        5: "largeBlobKey",
        6: "extensions",
    },
    "getAssertionResponse": {
        1: "credential",
        2: "authData",
        3: "signature",
        4: "user",
        5: "numberOfCredentials",
        6: "userSelected",
        7: "largeBlobKey",
        8: "extensions",
    },
}

_CTAP_REQUIRED_FIELDS: Dict[str, Sequence[int]] = {
    "makeCredentialRequest": (1, 2, 3, 4),
    "getAssertionRequest": (1, 2),
    "makeCredentialResponse": (1, 2),
    "getAssertionResponse": (2, 3),
}

_CTAP_PREFIX_DETAILS: Dict[str, Tuple[int, str]] = {
    "makeCredentialRequest": (0x01, "command"),
    "getAssertionRequest": (0x02, "command"),
    "makeCredentialResponse": (0x00, "status"),
    "getAssertionResponse": (0x00, "status"),
}
