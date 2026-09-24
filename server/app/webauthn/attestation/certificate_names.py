"""How the certificate views spell X.509 names and signature algorithms.

A leaf: the certificate summary, the extension values and the full certificate
view all use these, so none of them has to import another for them. The
algorithm spellings themselves are ``webauthn/signature_algorithms``', which the
MDS explorer shares.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cryptography.x509.oid import NameOID

from .. import signature_algorithms


def format_x509_name(name: Any) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _derive_certificate_algorithm_info(signature_info: Mapping[str, Any]) -> str:
    if not isinstance(signature_info, Mapping):
        return ""

    algorithm_component = ""
    raw_algorithm_name: Any = signature_info.get("algorithm")
    if isinstance(raw_algorithm_name, Mapping):
        raw_algorithm_name = raw_algorithm_name.get("name")
    if isinstance(raw_algorithm_name, str):
        algorithm_component = signature_algorithms.normalise_signature_algorithm_name(raw_algorithm_name)

    hash_component = ""
    hash_info = signature_info.get("hash")
    if isinstance(hash_info, Mapping):
        hash_component = hash_info.get("name") or ""
    elif hash_info not in (None, ""):
        hash_component = hash_info
    if not hash_component:
        sig_name = signature_info.get("algorithm")
        if isinstance(sig_name, str):
            hash_component = signature_algorithms.implied_hash_name(sig_name)

    return signature_algorithms.join_algorithm_info(algorithm_component, hash_component)


def _extract_common_names(name: Any) -> list[str]:
    values: list[str] = []
    for attribute in name.get_attributes_for_oid(NameOID.COMMON_NAME):
        value = attribute.value
        if isinstance(value, str):
            text = value.strip()
            if text:
                values.append(text)
    return values
