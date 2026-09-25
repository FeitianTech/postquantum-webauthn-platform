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
_SHA3_HASH_PATTERN = re.compile(r"sha-?3-?(\d{3})$", re.IGNORECASE)


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
    match = _SHA3_HASH_PATTERN.match(text)
    if match:
        return f"SHA3-{match.group(1)}"
    match = _HASH_NORMALISE_PATTERN.match(text)
    if match:
        return f"SHA{match.group(1)}"
    return text.replace("-", "").replace(" ", "").upper()


# RSASSA-PSS (RFC 4055): cryptography names it "rsassaPss", others "RSASSA-PSS".
_RSASSA_PSS_OID = "1.2.840.113549.1.1.10"
# NIST's signature OIDs (2.16.840.1.101.3.4.3.x) as a dotted OID reaches this
# module: ECDSA and RSA PKCS#1 v1.5 with SHA3 (.9-.16), which cryptography 50
# names "Unknown OID", so the callers pass the dotted form (the hash is read from
# the certificate); and pure ML-DSA (FIPS 204, .17-.19), which has no separate
# hash. cryptography 50 names ML-DSA itself, and those names meet the ML-DSA
# pattern below; the OIDs are here for a dotted form from any other source.
_NIST_SIGNATURE_OIDS = {
    **{f"2.16.840.1.101.3.4.3.{arc}": "ECDSA" for arc in (9, 10, 11, 12)},
    **{f"2.16.840.1.101.3.4.3.{arc}": "RSASSA-PKCS1-v1_5" for arc in (13, 14, 15, 16)},
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}
_ML_DSA_PATTERN = re.compile(r"mldsa(44|65|87)?")


def normalise_signature_algorithm_name(name: str) -> str:
    """The algorithm part of a signature's spelling, from its name or dotted OID.

    RSASSA-PSS is told from PKCS#1 v1.5, and ML-DSA from DSA, by name or OID; a
    signature's hash (RSASSA-PSS's is the one its parameters name) is read from
    the certificate by the callers and passed to :func:`join_algorithm_info`.
    """

    text = (name or "").strip()
    if not text:
        return ""

    if text in _NIST_SIGNATURE_OIDS:
        return _NIST_SIGNATURE_OIDS[text]
    lowered = text.lower()
    compact = lowered.replace("-", "").replace("_", "").replace(" ", "")
    if "ecdsa" in lowered:
        return "ECDSA"
    if "rsassapss" in compact or text == _RSASSA_PSS_OID:
        return "RSASSA-PSS"
    ml_dsa = _ML_DSA_PATTERN.search(compact)
    if ml_dsa:
        # Before "dsa": ML-DSA is not DSA, and its parameter set is part of its name.
        return f"ML-DSA-{ml_dsa.group(1)}" if ml_dsa.group(1) else "ML-DSA"
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
