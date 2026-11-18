"""Operator-trusted attestation CAs, read from the environment by ``create_app()``.

``FIDO_SERVER_TRUSTED_ATTESTATION_CA_SUBJECTS`` and
``FIDO_SERVER_TRUSTED_ATTESTATION_CA_FINGERPRINTS`` become
``TRUSTED_ATTESTATION_CA_SUBJECTS`` and ``TRUSTED_ATTESTATION_CA_FINGERPRINTS``.
"""
from __future__ import annotations

import os
import re
from typing import Any

from cryptography import x509


def _canonical_subject(text: str) -> str:
    """A subject name (RFC 4514) as cryptography writes a certificate's, which the trust check
    compares (``rfc4514_string``): blank space around the commas between its attributes
    dropped, an escaped comma (``\\,``) kept in its value; as written when it does not read."""

    joined = ",".join(part.strip() for part in re.split(r"(?<!\\),", text))
    try:
        return x509.Name.from_rfc4514_string(joined).rfc4514_string()
    except ValueError:
        return joined


def _parse_trusted_ca_subjects(raw_value: str | None) -> set[str] | None:
    """CA subject names, one per line or separated by ``;``: the commas in a subject separate
    its attributes (``CN=Root,O=Org`` is one subject), so a subject is trusted whole, never
    by its parts."""

    if raw_value is None:
        return None

    components = re.split(r"[;\n]+", raw_value)
    subjects = {_canonical_subject(component.strip()) for component in components if component.strip()}
    if not subjects:
        return None
    return subjects


def _parse_trusted_ca_fingerprints(raw_value: str | None) -> set[str] | None:
    """Normalise a list of hexadecimal fingerprints for trusted CA certificates."""

    if raw_value is None:
        return None

    components = re.split(r"[,;\n]+", raw_value)
    fingerprints = set()
    for component in components:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", component)
        if cleaned:
            normalised = cleaned.upper()
            # Require at least 20 bytes / 40 hex characters to avoid trivial matches.
            if len(normalised) >= 40:
                fingerprints.add(normalised)
    if not fingerprints:
        return None
    return fingerprints


def config_from_env() -> dict[str, Any]:
    """The trusted-CA settings ``create_app()`` puts into ``app.config``."""

    return {
        "TRUSTED_ATTESTATION_CA_SUBJECTS": _parse_trusted_ca_subjects(
            os.environ.get("FIDO_SERVER_TRUSTED_ATTESTATION_CA_SUBJECTS")
        ),
        "TRUSTED_ATTESTATION_CA_FINGERPRINTS": _parse_trusted_ca_fingerprints(
            os.environ.get("FIDO_SERVER_TRUSTED_ATTESTATION_CA_FINGERPRINTS")
        ),
    }
