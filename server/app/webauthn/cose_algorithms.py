"""A COSE algorithm a client names: a number, a number in text, or a name such as ES256 or ML-DSA-44.

Both ceremonies read the algorithm a request or a stored credential gives with
``coerce_cose_algorithm``; names are matched after ``normalise_name`` drops
punctuation and a ``FIDO_ALG_`` / ``COSE_ALG_`` prefix, then as a suffix, so
"WebAuthn: RS256 (RSASSA)" reads as -257. What follows "(" is a comment; text
that names no algorithm gives its last number, so "SHA-256 (RS256)" reads as 256.
"""
from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

NAME_MAP: dict[str, int] = {
    "ML-DSA-87": -50,
    "ML-DSA-65": -49,
    "ML-DSA-44": -48,
    "EDDSA": -8,
    "ED25519": -19,
    "ED448": -53,
    "ES256": -7,
    "ECDSA256": -7,
    "ECDSA-256": -7,
    "ES256K": -47,
    "ESP256": -9,
    "ESP-256": -9,
    "ES384": -35,
    "ES512": -36,
    "ESP384": -51,
    "ESP-384": -51,
    "ESP512": -52,
    "ESP-512": -52,
    "RS256": -257,
    "RSA256": -257,
    "RS384": -258,
    "RSA384": -258,
    "RS512": -259,
    "RSA512": -259,
    "RS1": -65535,
    "RSASSA-PKCS1-V1_5-SHA1": -65535,
    "PS256": -37,
    "PS384": -38,
    "PS512": -39,
}


def normalise_name(name: str) -> str:
    base = name.strip().split("(")[0]
    if not base:
        return ""
    sanitized = re.sub(r"[^A-Z0-9]", "", base.upper())
    if sanitized.startswith("FIDOALG"):
        sanitized = sanitized[len("FIDOALG"):]
    if sanitized.startswith("COSEALG"):
        sanitized = sanitized[len("COSEALG"):]
    return sanitized


NAME_LOOKUP: dict[str, int] = {key: alg for name, alg in NAME_MAP.items() if (key := normalise_name(name))}

NUMERIC_PATTERN = re.compile(r"-?\d+")


def lookup_name(
    name: str,
) -> int | None:
    normalized_name = normalise_name(name)
    if not normalized_name:
        return None

    direct_match = NAME_LOOKUP.get(normalized_name)
    if direct_match is not None:
        return direct_match

    for alias_key, alg_value in NAME_LOOKUP.items():
        if normalized_name.endswith(alias_key):
            return alg_value
    return None


def coerce_cose_algorithm(
    value: Any,
) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer():
            return int(value)
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return int(stripped, 10)
        except ValueError:
            normalized_alg = lookup_name(stripped)
            if normalized_alg is not None:
                return normalized_alg
            matches = list(NUMERIC_PATTERN.finditer(stripped))
            if matches:
                try:
                    return int(matches[-1].group(0), 10)
                except ValueError:
                    return None
            return None
    return None


def credential_algorithm(value: Any) -> int | None:
    if isinstance(value, Mapping):
        public_key_value = value.get("public_key") or value.get("publicKey")
    else:
        public_key_value = getattr(value, "public_key", None)

    if isinstance(public_key_value, Mapping):
        if 3 in public_key_value:
            raw_alg = public_key_value[3]
        else:
            raw_alg = public_key_value.get("alg")
    else:
        try:
            raw_alg = public_key_value[3]  # type: ignore[index]
        except Exception:
            raw_alg = getattr(public_key_value, "alg", None)

    return coerce_cose_algorithm(raw_alg)
