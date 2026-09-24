"""How a certificate's signature algorithm is spelled: ``ECDSA_SHA256``, ``ED25519_SHA512``.

The one spelling for the certificate views (``attestation/certificate_names``)
and the MDS explorer (``mds_snapshot``). A leaf that imports nothing from the
app, so ``tools/update_mds_snapshot.py`` reaches it without Flask: the
attestation package it would otherwise live in imports the whole attestation
stack.
"""
from __future__ import annotations

import re
from typing import Any

__all__ = [
    "format_algorithm_component",
    "format_hash_name",
    "implied_hash_name",
    "join_algorithm_info",
    "normalise_signature_algorithm_name",
]

_HASH_NORMALISE_PATTERN = re.compile(r"sha-?(\d{3})$", re.IGNORECASE)


def format_algorithm_component(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text or text == "—":
        return ""
    return text.replace(" ", "")


def format_hash_name(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    match = _HASH_NORMALISE_PATTERN.match(text)
    if match:
        return f"SHA{match.group(1)}"
    return text.replace("-", "").replace(" ", "").upper()


# RSASSA-PSS (RFC 4055): cryptography names it "rsassaPss", others "RSASSA-PSS".
_RSASSA_PSS_OID = "1.2.840.113549.1.1.10"


def normalise_signature_algorithm_name(name: str) -> str:
    """The algorithm part of a signature's spelling, from its name or dotted OID.

    RSASSA-PSS is told from PKCS#1 v1.5 by name or OID; its hash is the one its
    parameters name, which the callers read from the certificate and pass to
    :func:`join_algorithm_info`.
    """

    text = (name or "").strip()
    if not text:
        return ""

    lowered = text.lower()
    compact = lowered.replace("-", "").replace("_", "").replace(" ", "")
    if "ecdsa" in lowered:
        return "ECDSA"
    if "rsassapss" in compact or text == _RSASSA_PSS_OID:
        return "RSASSA-PSS"
    if "rsa" in lowered:
        return "RSASSA-PKCS1-v1_5"
    if "ed25519" in lowered:
        return "ED25519"
    if "ed448" in lowered:
        return "ED448"
    if "dsa" in lowered:
        return "DSA"

    return text.replace("-", "").replace(" ", "").upper()


def implied_hash_name(algorithm_name: str) -> str:
    """The hash an EdDSA signature fixes, which the certificate does not name separately."""

    lowered = algorithm_name.lower()
    if "ed25519" in lowered:
        return "SHA512"
    if "ed448" in lowered:
        return "SHAKE256"
    return ""


def join_algorithm_info(algorithm_component: str, hash_component: Any) -> str:
    """``ALGORITHM_HASH``, dropping an empty part and a hash that repeats the algorithm."""

    components: list[str] = []
    for part in (format_algorithm_component(algorithm_component), format_hash_name(hash_component)):
        if part and (not components or part.lower() != components[-1].lower()):
            components.append(part)
    return "_".join(components)
