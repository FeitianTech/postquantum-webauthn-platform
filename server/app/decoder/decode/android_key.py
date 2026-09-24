"""Read the Android key attestation extension (KeyDescription) of a certificate.

WebAuthn L3 section 8.4.1: an android-key attestation certificate carries its
key's description in extension 1.3.6.1.4.1.11129.2.1.17, whose schema is the
Android Open Source Project's "Key and ID attestation" page (KeyDescription,
AuthorizationList, RootOfTrust, AttestationApplicationId). The enumerated
values are the KeyMint HAL's (hardware/interfaces security/keymint AIDL:
KeyPurpose, Algorithm, Digest, EcCurve, KeyOrigin, SecurityLevel).

``cryptography`` reads all of it: ``x509`` finds the extension and
``hazmat.asn1`` decodes the DER, so no DER is read here by hand. An
AuthorizationList is decoded as a SEQUENCE OF a CHOICE of every tag the schema
defines plus a catch-all, so a tag added after this table is kept as an unknown
entry -- its identifier and content octets as hex -- and never dropped.
ENUMERATED values are matched on their content octets. Each part of the
extension is decoded on its own, so an error names the field it is in.

Nothing here is checked against the attestation: that attestationChallenge
equals clientDataHash, that allApplications is absent, and the origin and
purpose WebAuthn requires, are for a verifier.
"""
from __future__ import annotations

import functools
import operator
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from cryptography import x509
from cryptography.hazmat import asn1

EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"

# KeyMint SecurityLevel, by the content octets of the ENUMERATED.
SECURITY_LEVELS: dict[bytes, str] = {b"\x00": "Software", b"\x01": "TrustedEnvironment", b"\x02": "StrongBox"}
# RootOfTrust's VerifiedBootState, by content octets.
VERIFIED_BOOT_STATES: dict[bytes, str] = {
    b"\x00": "Verified",
    b"\x01": "SelfSigned",
    b"\x02": "Unverified",
    b"\x03": "Failed",
}
PURPOSES = {0: "ENCRYPT", 1: "DECRYPT", 2: "SIGN", 3: "VERIFY", 5: "WRAP_KEY", 6: "AGREE_KEY", 7: "ATTEST_KEY"}
ALGORITHMS = {1: "RSA", 3: "EC", 32: "AES", 33: "TRIPLE_DES", 128: "HMAC"}
DIGESTS = {0: "NONE", 1: "MD5", 2: "SHA1", 3: "SHA_2_224", 4: "SHA_2_256", 5: "SHA_2_384", 6: "SHA_2_512"}
EC_CURVES = {0: "P_224", 1: "P_256", 2: "P_384", 3: "P_521", 4: "CURVE_25519"}
ORIGINS = {0: "GENERATED", 1: "DERIVED", 2: "IMPORTED", 3: "RESERVED", 4: "SECURELY_IMPORTED"}
# KeyDescription fields: attestationVersion and keymasterVersion / keyMintVersion.
ATTESTATION_VERSIONS = {
    1: "Keymaster version 2.0",
    2: "Keymaster version 3.0",
    3: "Keymaster version 4.0",
    4: "Keymaster version 4.1",
    100: "KeyMint version 1.0",
    200: "KeyMint version 2.0",
    300: "KeyMint version 3.0",
    400: "KeyMint version 4.0",
    500: "KeyMint version 5.0",
}
KEYMASTER_VERSIONS = {
    2: "Keymaster version 2.0",
    3: "Keymaster version 3.0",
    4: "Keymaster version 4.0",
    41: "Keymaster version 4.1",
    100: "KeyMint version 1.0",
    200: "KeyMint version 2.0",
    300: "KeyMint version 3.0",
    400: "KeyMint version 4.0",
    500: "KeyMint version 5.0",
}


@asn1.sequence
class _RootOfTrust:
    verified_boot_key: bytes
    device_locked: bool
    verified_boot_state: asn1.TLV
    verified_boot_hash: bytes | None


@asn1.sequence
class _PackageInfo:
    package_name: bytes
    version: int


@asn1.sequence
class _AttestationApplicationId:
    package_infos: asn1.SetOf[_PackageInfo]
    signature_digests: asn1.SetOf[bytes]


# AuthorizationList tags: number -> (name, value type, value names). A SET OF
# INTEGER is taken as its TLV and decoded on its own (see _decode_as).
_SET = asn1.TLV
TAGS: dict[int, tuple[str, Any, dict[int, str] | None]] = {
    1: ("purpose", _SET, PURPOSES),
    2: ("algorithm", int, ALGORITHMS),
    3: ("keySize", int, None),
    4: ("blockMode", _SET, None),
    5: ("digest", _SET, DIGESTS),
    6: ("padding", _SET, None),
    7: ("callerNonce", asn1.Null, None),
    8: ("minMacLength", int, None),
    10: ("ecCurve", int, EC_CURVES),
    11: ("mlDsaVariant", int, None),
    200: ("rsaPublicExponent", int, None),
    203: ("mgfDigest", _SET, DIGESTS),
    303: ("rollbackResistance", asn1.Null, None),
    305: ("earlyBootOnly", asn1.Null, None),
    400: ("activeDateTime", int, None),
    401: ("originationExpireDateTime", int, None),
    402: ("usageExpireDateTime", int, None),
    405: ("usageCountLimit", int, None),
    502: ("userSecureId", int, None),
    503: ("noAuthRequired", asn1.Null, None),
    504: ("userAuthType", int, None),
    505: ("authTimeout", int, None),
    506: ("allowWhileOnBody", asn1.Null, None),
    507: ("trustedUserPresenceReq", asn1.Null, None),
    508: ("trustedConfirmationReq", asn1.Null, None),
    509: ("unlockedDeviceReq", asn1.Null, None),
    600: ("allApplications", asn1.Null, None),  # attestation versions 1 and 2
    701: ("creationDateTime", int, None),
    702: ("origin", int, ORIGINS),
    704: ("rootOfTrust", _RootOfTrust, None),
    705: ("osVersion", int, None),
    706: ("osPatchLevel", int, None),
    709: ("attestationApplicationId", bytes, None),
    710: ("attestationIdBrand", bytes, None),
    711: ("attestationIdDevice", bytes, None),
    712: ("attestationIdProduct", bytes, None),
    713: ("attestationIdSerial", bytes, None),
    714: ("attestationIdImei", bytes, None),
    715: ("attestationIdMeid", bytes, None),
    716: ("attestationIdManufacturer", bytes, None),
    717: ("attestationIdModel", bytes, None),
    718: ("vendorPatchLevel", int, None),
    719: ("bootPatchLevel", int, None),
    720: ("deviceUniqueAttestation", asn1.Null, None),
    723: ("attestationIdSecondImei", bytes, None),
    724: ("moduleHash", bytes, None),
}
_DATE_TIMES = {"activeDateTime", "originationExpireDateTime", "usageExpireDateTime", "creationDateTime"}
_UNKNOWN = "unknown"

# One CHOICE of every tag in the table, and a catch-all for any other: X | Y | ...
_Entry = functools.reduce(
    operator.or_,
    [
        Annotated[asn1.Variant[kind, Literal[name]], asn1.Explicit(number)]
        for number, (name, kind, _names) in TAGS.items()
    ]
    + [asn1.Variant[asn1.TLV, Literal[_UNKNOWN]]],
)


@asn1.sequence
class _KeyDescriptionParts:
    attestation_version: asn1.TLV
    attestation_security_level: asn1.TLV
    keymaster_version: asn1.TLV
    keymaster_security_level: asn1.TLV
    attestation_challenge: asn1.TLV
    unique_id: asn1.TLV
    software_enforced: asn1.TLV
    hardware_enforced: asn1.TLV


@asn1.sequence
class _Wrapper:
    item: asn1.TLV


@functools.cache
def _holder(kind: Any) -> type:
    return asn1.sequence(type("_Holder", (), {"__annotations__": {"value": kind}}))


def _decode_as(tlv: asn1.TLV, kind: Any) -> Any:
    """Decode one TLV as ``kind``: cryptography re-wraps it, then reads it typed."""

    return asn1.decode_der(_holder(kind), asn1.encode_der(_Wrapper(item=tlv))).value


def read_certificate(der: bytes) -> dict[str, Any]:
    """The KeyDescription of the certificate ``der``, or a note saying why there is none."""

    try:
        certificate = x509.load_der_x509_certificate(der)
    except ValueError as exc:
        return {"error": f"the credential certificate is not DER X.509: {exc}"}
    try:
        extension = certificate.extensions.get_extension_for_oid(x509.ObjectIdentifier(EXTENSION_OID))
    except x509.ExtensionNotFound:
        return {"note": f"the credential certificate has no {EXTENSION_OID} extension"}
    raw = extension.value.value if isinstance(extension.value, x509.UnrecognizedExtension) else b""
    return read_key_description(raw)


def read_key_description(der: bytes) -> dict[str, Any]:
    view: dict[str, Any] = {"extension": f"{EXTENSION_OID} (KeyDescription)", "hex": der.hex()}
    errors: list[dict[str, str]] = []
    try:
        parts = asn1.decode_der(_KeyDescriptionParts, der)
    except ValueError as exc:
        view["errors"] = [{"field": "KeyDescription", "error": str(exc)}]
        return view

    version = _field(errors, "attestationVersion", parts.attestation_version, int)
    modern = isinstance(version, int) and version >= 100
    view["attestationVersion"] = _version(version, ATTESTATION_VERSIONS)
    view["attestationSecurityLevel"] = _enumerated(parts.attestation_security_level, SECURITY_LEVELS)
    key_version_name = "keyMintVersion" if modern else "keymasterVersion"
    view[key_version_name] = _version(_field(errors, key_version_name, parts.keymaster_version, int), KEYMASTER_VERSIONS)
    view["keyMintSecurityLevel" if modern else "keymasterSecurityLevel"] = _enumerated(
        parts.keymaster_security_level, SECURITY_LEVELS
    )
    challenge = _field(errors, "attestationChallenge", parts.attestation_challenge, bytes)
    if isinstance(challenge, bytes):
        view["attestationChallenge"] = {
            "hex": challenge.hex(),
            "length": len(challenge),
            "note": "WebAuthn L3 section 8.4: must equal clientDataHash; not checked (the decoder has no clientDataHash)",
        }
    unique_id = _field(errors, "uniqueId", parts.unique_id, bytes)
    if isinstance(unique_id, bytes):
        view["uniqueId"] = {"hex": unique_id.hex(), "length": len(unique_id)}
    view["softwareEnforced"] = _authorization_list(errors, "softwareEnforced", parts.software_enforced)
    hardware = "hardwareEnforced" if modern else "teeEnforced"
    view[hardware] = _authorization_list(errors, hardware, parts.hardware_enforced)
    if errors:
        view["errors"] = errors
    return view


def _field(errors: list[dict[str, str]], name: str, tlv: asn1.TLV, kind: Any) -> Any:
    try:
        return _decode_as(tlv, kind)
    except ValueError as exc:
        errors.append({"field": name, "error": str(exc), "identifier": tlv.tag_bytes.hex(), "content": bytes(tlv.data).hex()})
        return None


def _version(value: Any, names: dict[int, str]) -> Any:
    if not isinstance(value, int):
        return None
    name = names.get(value)
    return {"value": value, "meaning": name} if name else {"value": value}


def _enumerated(tlv: asn1.TLV, names: dict[bytes, str]) -> dict[str, Any]:
    content = bytes(tlv.data)
    view: dict[str, Any] = {"content": content.hex()}
    if tlv.tag_bytes != b"\x0a":
        view["note"] = f"not an ENUMERATED (identifier {tlv.tag_bytes.hex()})"
    elif content in names:
        view["meaning"] = names[content]
    else:
        view["note"] = "not a value the schema names"
    return view


def _authorization_list(errors: list[dict[str, str]], name: str, tlv: asn1.TLV) -> Any:
    entries = _field(errors, name, tlv, list[_Entry])
    if entries is None:
        return None
    view: dict[str, Any] = {}
    unknown: list[dict[str, str]] = []
    for entry in entries:
        if entry.tag == _UNKNOWN:
            unknown.append(
                {"identifier": entry.value.tag_bytes.hex(), "content": bytes(entry.value.data).hex(), "note": "a tag this table does not name; shown as sent"}
            )
            continue
        view[entry.tag] = _entry_value(errors, f"{name}.{entry.tag}", entry.tag, entry.value)
    if unknown:
        view["unknown"] = unknown
    return view


def _entry_value(errors: list[dict[str, str]], field: str, name: str, value: Any) -> Any:
    names = next(table for tag_name, _kind, table in TAGS.values() if tag_name == name)
    if isinstance(value, asn1.TLV):  # a SET OF INTEGER
        numbers = _field(errors, field, value, asn1.SetOf[int])
        if numbers is None:
            return None
        values = numbers.as_list()
        view: dict[str, Any] = {"values": values}
        if names:
            view["meanings"] = [names.get(number, f"{number} (not a value the schema names)") for number in values]
        return view
    if isinstance(value, asn1.Null):
        return {"present": True}
    if isinstance(value, _RootOfTrust):
        root = {
            "verifiedBootKey": value.verified_boot_key.hex(),
            "deviceLocked": value.device_locked,
            "verifiedBootState": _enumerated(value.verified_boot_state, VERIFIED_BOOT_STATES),
        }
        if value.verified_boot_hash is not None:
            root["verifiedBootHash"] = value.verified_boot_hash.hex()
        return root
    if isinstance(value, bytes):
        return _octets(errors, field, name, value)
    view = {"value": value}
    if names and value in names:
        view["meaning"] = names[value]
    elif names:
        view["meaning"] = "not a value the schema names"
    if name in _DATE_TIMES:
        view["utc"] = datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat()
    elif name == "osVersion" and 0 <= value <= 999999:
        view["version"] = f"{value // 10000}.{value // 100 % 100}.{value % 100}"
    return view


def _octets(errors: list[dict[str, str]], field: str, name: str, value: bytes) -> dict[str, Any]:
    view: dict[str, Any] = {"hex": value.hex()}
    if name == "attestationApplicationId":
        try:
            application = asn1.decode_der(_AttestationApplicationId, value)
        except ValueError as exc:
            errors.append({"field": field, "error": str(exc)})
            return view
        view["packages"] = [
            {"name": _text(info.package_name), "version": info.version} for info in application.package_infos.as_list()
        ]
        view["signatureDigests"] = [digest.hex() for digest in application.signature_digests.as_list()]
    elif name.startswith("attestationId"):
        view["text"] = _text(value)
    return view


def _text(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex()
