from __future__ import annotations

import re
from typing import Any, List, Mapping


_HASH_NORMALISE_PATTERN = re.compile(r"sha-?(\d{3})$", re.IGNORECASE)


def format_x509_name(name: Any) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _format_algorithm_component(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text or text == "—":
        return ""
    return text.replace(" ", "")


def _format_hash_value(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if not text:
        return ""
    match = _HASH_NORMALISE_PATTERN.match(text)
    if match:
        return f"SHA{match.group(1)}"
    return text.replace("-", "").replace(" ", "").upper()


def _normalise_signature_algorithm_name(name: str) -> str:
    text = (name or "").strip()
    if not text:
        return ""

    lowered = text.lower()
    if "ecdsa" in lowered:
        return "ECDSA"
    if "rsassa-pss" in lowered:
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


def _derive_certificate_algorithm_info(signature_info: Mapping[str, Any]) -> str:
    if not isinstance(signature_info, Mapping):
        return ""

    algorithm_component = ""
    raw_algorithm_name: Any = signature_info.get("algorithm")
    if isinstance(raw_algorithm_name, Mapping):
        raw_algorithm_name = raw_algorithm_name.get("name")
    if isinstance(raw_algorithm_name, str):
        algorithm_component = _normalise_signature_algorithm_name(raw_algorithm_name)

    hash_component = ""
    hash_info = signature_info.get("hash")
    if isinstance(hash_info, Mapping):
        hash_component = hash_info.get("name") or ""
    elif hash_info not in (None, ""):
        hash_component = hash_info
    if not hash_component:
        sig_name = signature_info.get("algorithm")
        if isinstance(sig_name, str):
            lowered = sig_name.lower()
            if "ed25519" in lowered:
                hash_component = "SHA512"
            elif "ed448" in lowered:
                hash_component = "SHAKE256"

    components = []
    for part in (
        _format_algorithm_component(algorithm_component),
        _format_hash_value(hash_component),
    ):
        if part and (not components or part.lower() != components[-1].lower()):
            components.append(part)

    return "_".join(components)


def _extract_common_names(name: Any) -> List[str]:
    values: List[str] = []
    for attribute in name.get_attributes_for_oid(NameOID.COMMON_NAME):
        value = attribute.value
        if isinstance(value, str):
            text = value.strip()
            if text:
                values.append(text)
    return values
