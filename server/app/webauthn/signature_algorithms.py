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


# RSASSA-PSS (RFC 4055): cryptography names it "rsassaPss", others "RSASSA-PSS" or "RSA-PSS".
_RSASSA_PSS_OID = "1.2.840.113549.1.1.10"
# NIST's signature OIDs (2.16.840.1.101.3.4.3.x, the CSOR sigAlgs arc) as a
# dotted OID reaches this module, which is how the callers pass one cryptography
# 50 names "Unknown OID". Each gives the algorithm and the hash its OID fixes
# ("" where the certificate names the hash, or there is none):
# - DSA with SHA-224/256 (.1, .2; cryptography names these), SHA-384/512 (.3, .4)
#   and SHA3 (.5-.8), whose hash cryptography cannot read either;
# - ECDSA and RSA PKCS#1 v1.5 with SHA3 (.9-.16; the hash is read from the certificate);
# - pure ML-DSA (FIPS 204, .17-.19) and SLH-DSA (FIPS 205, .20-.31), with no
#   separate hash (cryptography 50 names ML-DSA itself, and those names meet the
#   ML-DSA pattern below; the OIDs are here for a dotted form from any source);
# - HashML-DSA (FIPS 204 section 5.4, .32-.34) and HashSLH-DSA (FIPS 205 section
#   10.2, .35-.46), whose OID fixes the pre-hash the certificate names nowhere else.
_SLH_DSA_SETS = tuple(
    f"{family}-{bits}{speed}" for family in ("SHA2", "SHAKE") for bits in (128, 192, 256) for speed in "sf"
)
_HASH_SLH_DSA_HASHES = ("SHA256", "SHA256", "SHA512", "SHA512", "SHA512", "SHA512") + ("SHAKE128",) * 2 + ("SHAKE256",) * 4
_NIST_SIGNATURE_OIDS: dict[str, tuple[str, str]] = {
    **{f"2.16.840.1.101.3.4.3.{arc}": ("DSA", f"SHA{bits}") for arc, bits in zip((1, 2, 3, 4), (224, 256, 384, 512))},
    **{f"2.16.840.1.101.3.4.3.{arc}": ("DSA", f"SHA3-{bits}") for arc, bits in zip((5, 6, 7, 8), (224, 256, 384, 512))},
    **{f"2.16.840.1.101.3.4.3.{arc}": ("ECDSA", "") for arc in (9, 10, 11, 12)},
    **{f"2.16.840.1.101.3.4.3.{arc}": ("RSASSA-PKCS1-v1_5", "") for arc in (13, 14, 15, 16)},
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", ""),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", ""),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", ""),
    **{f"2.16.840.1.101.3.4.3.{20 + index}": (f"SLH-DSA-{name}", "") for index, name in enumerate(_SLH_DSA_SETS)},
    "2.16.840.1.101.3.4.3.32": ("HashML-DSA-44", "SHA512"),
    "2.16.840.1.101.3.4.3.33": ("HashML-DSA-65", "SHA512"),
    "2.16.840.1.101.3.4.3.34": ("HashML-DSA-87", "SHA512"),
    **{
        f"2.16.840.1.101.3.4.3.{35 + index}": (f"HashSLH-DSA-{name}", hash_name)
        for index, (name, hash_name) in enumerate(zip(_SLH_DSA_SETS, _HASH_SLH_DSA_HASHES))
    },
}
# Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs-19, section 6): ML-DSA and
# a traditional signature under one OID, 1.3.6.1.5.5.7.6.37 to .54 in this order.
# Each is spelled as the draft names it, without "id-". The name fixes the
# pre-hash, so no hash is joined to it.
_COMPOSITE_NAMES = (
    "MLDSA44-RSA2048-PSS-SHA256",
    "MLDSA44-RSA2048-PKCS15-SHA256",
    "MLDSA44-Ed25519-SHA512",
    "MLDSA44-ECDSA-P256-SHA256",
    "MLDSA65-RSA3072-PSS-SHA512",
    "MLDSA65-RSA3072-PKCS15-SHA512",
    "MLDSA65-RSA4096-PSS-SHA512",
    "MLDSA65-RSA4096-PKCS15-SHA512",
    "MLDSA65-ECDSA-P256-SHA512",
    "MLDSA65-ECDSA-P384-SHA512",
    "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
    "MLDSA65-Ed25519-SHA512",
    "MLDSA87-ECDSA-P384-SHA512",
    "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
    "MLDSA87-Ed448-SHAKE256",
    "MLDSA87-RSA3072-PSS-SHA512",
    "MLDSA87-RSA4096-PSS-SHA512",
    "MLDSA87-ECDSA-P521-SHA512",
)
_COMPOSITE_OIDS = {f"1.3.6.1.5.5.7.6.{37 + index}": name for index, name in enumerate(_COMPOSITE_NAMES)}
_COMPOSITE_BY_COMPACT = {name.lower().replace("-", ""): name for name in _COMPOSITE_NAMES}
_ML_DSA_PATTERN = re.compile(r"mldsa(44|65|87)?")
_HASH_ML_DSA_PATTERN = re.compile(r"hashmldsa(44|65|87)")
_SLH_DSA_PATTERN = re.compile(r"(hash)?slhdsa(sha2|shake)(128|192|256)([sf])")
# A name that says its hash: "id-hash-ml-dsa-44-with-sha512", "dsa-with-sha384".
_WITH_HASH_PATTERN = re.compile(r"with-?(sha3-?\d{3}|sha-?\d{3}|shake-?\d{3})$", re.IGNORECASE)


def _compact(text: str) -> str:
    return text.lower().replace("-", "").replace("_", "").replace(" ", "")


def _composite(text: str) -> str | None:
    """The composite ML-DSA ``text`` names, by OID or by name (with or without "id-")."""

    if text in _COMPOSITE_OIDS:
        return _COMPOSITE_OIDS[text]
    compact = _compact(text)
    return _COMPOSITE_BY_COMPACT.get(compact[2:] if compact.startswith("id") else compact)


def normalise_signature_algorithm_name(name: str) -> str:
    """The algorithm part of a signature's spelling, from its name or dotted OID.

    RSASSA-PSS is told from PKCS#1 v1.5, and ML-DSA from DSA, by name or OID; a
    signature's hash (RSASSA-PSS's is the one its parameters name) is read from
    the certificate by the callers and passed to :func:`join_algorithm_info`.
    A composite ML-DSA signature is named whole, before any part of its name
    could be read as ECDSA, RSA or ML-DSA alone; HashML-DSA before ML-DSA, and
    SLH-DSA before DSA.
    """

    text = (name or "").strip()
    if not text:
        return ""

    if text in _NIST_SIGNATURE_OIDS:
        return _NIST_SIGNATURE_OIDS[text][0]
    composite = _composite(text)
    if composite:
        return composite
    lowered = text.lower()
    compact = _compact(text)
    hash_ml_dsa = _HASH_ML_DSA_PATTERN.search(compact)
    if hash_ml_dsa:
        return f"HashML-DSA-{hash_ml_dsa.group(1)}"
    slh_dsa = _SLH_DSA_PATTERN.search(compact)
    if slh_dsa:
        prefix, family, bits, speed = slh_dsa.groups()
        return f"{'Hash' if prefix else ''}SLH-DSA-{family.upper()}-{bits}{speed}"
    if "ecdsa" in lowered:
        return "ECDSA"
    if "rsassapss" in compact or "rsapss" in compact or text == _RSASSA_PSS_OID:
        # "RSA-PSS" and "rsaPSS" too: OpenSSL's and other tools' spelling of it.
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
    """The hash a signature's name or OID fixes, which the certificate does not name separately.

    EdDSA's (SHA-512 for Ed25519, SHAKE256 for Ed448), the one an OID in the table
    above fixes, and the one a name says it is "with". A composite's name holds
    its own, so it gets none here.
    """

    text = (algorithm_name or "").strip()
    if text in _NIST_SIGNATURE_OIDS:
        return _NIST_SIGNATURE_OIDS[text][1]
    if _composite(text):
        return ""
    lowered = text.lower()
    if "ed25519" in lowered:
        return "SHA512"
    if "ed448" in lowered:
        return "SHAKE256"
    with_hash = _WITH_HASH_PATTERN.search(text)
    return with_hash.group(1) if with_hash else ""


def join_algorithm_info(algorithm_component: str, hash_component: Any) -> str:
    """``ALGORITHM_HASH``, dropping an empty part and a hash that repeats the algorithm."""

    components: list[str] = []
    for part in (format_algorithm_component(algorithm_component), format_hash_name(hash_component)):
        if part and (not components or part.lower() != components[-1].lower()):
            components.append(part)
    return "_".join(components)
