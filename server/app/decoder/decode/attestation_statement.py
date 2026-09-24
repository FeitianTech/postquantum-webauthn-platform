"""Interpret an attestation statement by its format: WebAuthn L3 section 8.

Each format's statement is laid out against the syntax its section defines,
and what is inside is decoded: TPM structures (``tpm_structures``), the
Android KeyDescription (``android_key``), SafetyNet's JWS (``safetynet``),
Apple's nonce (``apple_anonymous``), and each statement of a compound one. A
member the syntax does not define is kept, shown as sent. A format this
decoder does not know is shown as sent and labelled unknown.

The decoder shows; it does not verify. Every view says so, and lists under
``notChecked`` what the format's verification procedure would check that the
decoder did not: signatures, certificate chains, and the values that only
make sense against the authenticator data and client data.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from ...webauthn import pqc
from . import (
    android_key,
    apple_anonymous,
    authenticator_data_findings,
    certificate_summary,
    safetynet,
    tpm_structures,
)
from .keys import hex_json_safe, key_text

NOT_VERIFIED = "not verified: the decoder shows this statement; it checks no signature, chain or value in it"

_CHAIN = "the x5c chain up to a trust anchor"


def interpret(fmt: Any, att_stmt: Any, auth_data: Any = None, *, nested: bool = False) -> dict[str, Any]:
    known = _FORMATS.get(fmt) if isinstance(fmt, str) else None
    if known is None:
        return {
            "fmt": hex_json_safe(fmt),
            "known": False,
            "meaning": "not an attestation statement format WebAuthn L3 section 8 defines; shown as sent",
            "attStmt": hex_json_safe(att_stmt),
        }
    section, types, members, required, read, not_checked = known
    view: dict[str, Any] = {
        "fmt": fmt,
        "known": True,
        "spec": f"WebAuthn L3 section {section}",
        "attestationTypesSupported": types,
        "verification": NOT_VERIFIED,
        "notChecked": list(not_checked),
    }
    if fmt == "compound":
        view.update(_compound(att_stmt, auth_data, nested=nested))
        return view
    if not isinstance(att_stmt, Mapping):
        view["attStmt"] = hex_json_safe(att_stmt)
        view["note"] = f"section {section} defines attStmt as a map; this is not"
        return view
    view["fields"] = read(att_stmt, auth_data)
    missing = [name for name in required if name not in att_stmt]
    if missing:
        view["missing"] = {"members": missing, "note": f"section {section}'s attStmt syntax requires them; absent here"}
    unrecognized = {key_text(key): hex_json_safe(value) for key, value in att_stmt.items() if key not in members}
    if unrecognized:
        view["notInSyntax"] = {
            "members": unrecognized,
            "note": f"not in section {section}'s attStmt syntax; shown as sent",
        }
    return view


def _algorithm(value: Any) -> Any:
    if isinstance(value, int) and not isinstance(value, bool):
        return {"value": value, "name": pqc.describe_algorithm(value)}
    return hex_json_safe(value)


def _signature(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"length": len(value), "hex": value.hex()}
    return hex_json_safe(value)


def _chain(value: Any) -> Any:
    if not isinstance(value, list):
        return {"value": hex_json_safe(value), "note": "x5c is an array of DER certificates; this is not"}
    return {"count": len(value), "certificates": [certificate_summary.summarize(entry) for entry in value]}


def _common(att_stmt: Mapping[Any, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    readers = {"alg": _algorithm, "sig": _signature, "x5c": _chain}
    for name, read in readers.items():
        if name in att_stmt:
            fields[name] = read(att_stmt[name])
    return fields


def _credential_algorithm(auth_data: Any) -> Any:
    """The alg (3) of the credential public key in ``auth_data``, if it has one."""

    if not isinstance(auth_data, bytes):
        return None
    for name, node in authenticator_data_findings.embedded_items(auth_data)[0]:
        if name == "credentialPublicKey":
            for entry in node.get("entries") or []:
                key, value = entry.get("key", {}), entry.get("value", {})
                if key.get("type") == "unsigned" and key.get("value") == 3 and value.get("type") in ("unsigned", "negative"):
                    return value.get("value")
    return None


def _packed(att_stmt: Mapping[Any, Any], auth_data: Any) -> dict[str, Any]:
    fields = _common(att_stmt)
    if "x5c" in att_stmt:
        fields["attestationType"] = "Basic or AttCA (x5c present; which one depends on the trust anchor)"
    else:
        fields["attestationType"] = "Self (no x5c): sig is made with the credential private key"
        credential_alg = _credential_algorithm(auth_data)
        if credential_alg is not None:
            fields["credentialPublicKeyAlg"] = _algorithm(credential_alg)
        fields["note"] = "section 8.2: for self attestation alg must be the credential public key's alg; shown, not compared"
    return fields


def _tpm(att_stmt: Mapping[Any, Any], _auth_data: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if "ver" in att_stmt:
        fields["ver"] = hex_json_safe(att_stmt["ver"])
    fields.update(_common(att_stmt))
    if isinstance(fields.get("sig"), dict):
        fields["sig"]["note"] = "section 8.3 calls sig a TPMT_SIGNATURE; shown as bytes, not parsed"
    for name, read in (("certInfo", tpm_structures.read_tpms_attest), ("pubArea", tpm_structures.read_tpmt_public)):
        value = att_stmt.get(name)
        if isinstance(value, bytes):
            fields[name] = read(value, name)
        elif name in att_stmt:
            fields[name] = {"value": hex_json_safe(value), "note": f"{name} is a byte string; this is not"}
    return fields


def _android_key(att_stmt: Mapping[Any, Any], _auth_data: Any) -> dict[str, Any]:
    fields = _common(att_stmt)
    chain = att_stmt.get("x5c")
    if isinstance(chain, list) and chain and isinstance(chain[0], bytes):
        fields["keyDescription"] = android_key.read_certificate(chain[0])
    return fields


def _safetynet(att_stmt: Mapping[Any, Any], _auth_data: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if "ver" in att_stmt:
        fields["ver"] = {
            "value": hex_json_safe(att_stmt["ver"]),
            "meaning": "the Google Play Services version that produced the response",
        }
    if "response" in att_stmt:
        fields["response"] = safetynet.read_response(att_stmt["response"])
    fields["deprecated"] = safetynet.DEPRECATED
    return fields


def _fido_u2f(att_stmt: Mapping[Any, Any], _auth_data: Any) -> dict[str, Any]:
    fields = _common(att_stmt)
    chain = att_stmt.get("x5c")
    if isinstance(chain, list):
        if len(chain) != 1:
            fields["x5c"]["note"] = f"section 8.6: x5c holds exactly one certificate; this holds {len(chain)}"
        if chain and isinstance(chain[0], bytes):
            fields["attestnCertKey"] = _key_kind(chain[0])
    return fields


def _key_kind(der: bytes) -> str:
    try:
        key = x509.load_der_x509_certificate(der).public_key()
    except ValueError:
        return "unreadable"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name} (section 8.6 requires P-256; shown, not judged)"
    return f"{type(key).__name__} (section 8.6 requires an EC P-256 key; shown, not judged)"


def _none(att_stmt: Mapping[Any, Any], _auth_data: Any) -> dict[str, Any]:
    if att_stmt:
        return {"note": f"section 8.7: attStmt is an empty map; this one has {len(att_stmt)} member(s)"}
    return {}


def _apple(att_stmt: Mapping[Any, Any], _auth_data: Any) -> dict[str, Any]:
    fields = {"x5c": _chain(att_stmt["x5c"])} if "x5c" in att_stmt else {}
    chain = att_stmt.get("x5c")
    if isinstance(chain, list) and chain and isinstance(chain[0], bytes):
        fields["nonce"] = apple_anonymous.read_certificate(chain[0])
    return fields


def _compound(att_stmt: Any, auth_data: Any, *, nested: bool) -> dict[str, Any]:
    if nested:
        return {"note": "section 8.9: a compound statement's statements are not compound; shown as sent",
                "attStmt": hex_json_safe(att_stmt)}
    if not isinstance(att_stmt, list):
        return {"attStmt": hex_json_safe(att_stmt), "note": "section 8.9 defines attStmt as an array of statements"}
    view: dict[str, Any] = {"statements": []}
    for entry in att_stmt:
        if isinstance(entry, Mapping) and "fmt" in entry:
            view["statements"].append(interpret(entry["fmt"], entry.get("attStmt"), auth_data, nested=True))
        else:
            view["statements"].append({"value": hex_json_safe(entry), "note": "each statement is a map with fmt and attStmt"})
    if len(att_stmt) < 2:
        view["note"] = f"section 8.9: [2* nonCompoundAttStmt], at least two statements; this has {len(att_stmt)}"
    return view


_SIG = "sig over authenticatorData || clientDataHash"

# fmt -> (section, attestation types supported, attStmt members, the members its
# syntax requires, reader, what verification would check that is not checked here)
_FORMATS: dict[
    str, tuple[str, str, frozenset, tuple[str, ...], Callable[[Mapping[Any, Any], Any], dict[str, Any]], tuple[str, ...]]
] = {
    "packed": (
        "8.2", "Basic, Self, AttCA", frozenset({"alg", "sig", "x5c"}), ("alg", "sig"), _packed,
        (_SIG, "the attestation certificate requirements of section 8.2.1", _CHAIN,
         "for self attestation: that alg matches the credential public key and sig verifies under it"),
    ),
    "tpm": (
        "8.3", "AttCA", frozenset({"ver", "alg", "x5c", "sig", "certInfo", "pubArea"}),
        ("ver", "alg", "x5c", "sig", "certInfo", "pubArea"), _tpm,
        ("sig over certInfo under aikCert's key", "certInfo.extraData = hash of authenticatorData || clientDataHash",
         "certInfo.attested.name = pubArea's Name", "pubArea's key = the credential public key",
         "the aikCert requirements of section 8.3.1", _CHAIN),
    ),
    "android-key": (
        "8.4", "Basic", frozenset({"alg", "sig", "x5c"}), ("alg", "sig", "x5c"), _android_key,
        (_SIG, "the credCert key = the credential public key", "attestationChallenge = clientDataHash",
         "allApplications absent, origin KM_ORIGIN_GENERATED, purpose KM_PURPOSE_SIGN", _CHAIN),
    ),
    "android-safetynet": (
        "8.5", "Basic", frozenset({"ver", "response"}), ("ver", "response"), _safetynet,
        ("the JWS signature and its chain to attest.android.com",
         "nonce = base64 of SHA-256(authenticatorData || clientDataHash)", "ctsProfileMatch"),
    ),
    "fido-u2f": (
        "8.6", "Basic, AttCA", frozenset({"sig", "x5c"}), ("sig", "x5c"), _fido_u2f,
        ("sig over 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F", _CHAIN),
    ),
    "none": ("8.7", "None", frozenset(), (), _none, ()),
    "apple": (
        "8.8", "Anonymization CA", frozenset({"x5c"}), ("x5c",), _apple,
        ("nonce = SHA-256(authenticatorData || clientDataHash)", "the credCert key = the credential public key", _CHAIN),
    ),
    "compound": ("8.9", "Any", frozenset(), (), _none, ("each statement, by its own format's procedure",)),
}
