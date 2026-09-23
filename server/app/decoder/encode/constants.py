"""Shared constants for encoder CTAP helpers."""
from __future__ import annotations

import re
from collections.abc import Sequence

from .. import ctap_tables

_CTAP_LABELED_KEY_PATTERN = re.compile(r"^\s*(-?\d+)\s*\(([^)]+)\)\s*$")

_CTAP_FIELD_LABELS: dict[str, dict[int, str]] = {
    "makeCredentialRequest": ctap_tables.MAKE_CREDENTIAL_PARAMETERS,
    "getAssertionRequest": ctap_tables.GET_ASSERTION_PARAMETERS,
    "makeCredentialResponse": ctap_tables.MAKE_CREDENTIAL_RESPONSE,
    "getAssertionResponse": ctap_tables.GET_ASSERTION_RESPONSE,
}

_CTAP_REQUIRED_FIELDS: dict[str, Sequence[int]] = {
    "makeCredentialRequest": (1, 2, 3, 4),
    "getAssertionRequest": (1, 2),
    "makeCredentialResponse": (1, 2),
    "getAssertionResponse": (2, 3),
}

_CTAP_PREFIX_DETAILS: dict[str, tuple[int, str]] = {
    "makeCredentialRequest": (ctap_tables.MAKE_CREDENTIAL, "command"),
    "getAssertionRequest": (ctap_tables.GET_ASSERTION, "command"),
    "makeCredentialResponse": (ctap_tables.SUCCESS, "status"),
    "getAssertionResponse": (ctap_tables.SUCCESS, "status"),
}
