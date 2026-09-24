"""Interpret extensions: authenticator inputs and outputs, and client results.

Where extensions occur, and what defines them:

* authenticator extension inputs: the extensions parameter of
  authenticatorMakeCredential (0x06) and authenticatorGetAssertion (0x04),
  CTAP 2.2 sections 6.1 and 6.2;
* authenticator extension outputs: the extensions in authenticator data under
  its ED flag, WebAuthn L3 sections 6.1 and 9.5;
* unsigned extension outputs: makeCredential response member 0x06,
  getAssertion response member 0x08, CTAP 2.2 sections 6.1 and 6.2;
* client extension outputs: a PublicKeyCredential's clientExtensionResults,
  WebAuthn L3 section 10.1, plus the client outputs CTAP 2.2 section 12 defines.

Each entry keeps the value as sent and adds what it means where the defining
section says. An identifier neither CTAP 2.2 section 12 nor WebAuthn L3 section
10 defines is kept, labelled unknown. Nothing is verified: an hmac-secret
output, for one, is shown as the encrypted bytes it is.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from ... import encoding
from ...webauthn import pqc
from .. import ctap_tables
from .binary import _describe_cose_key
from .keys import MISSING, get_mapping_entry, hex_json_safe, key_text

MAKE_CREDENTIAL_INPUT = "makeCredential input"
GET_ASSERTION_INPUT = "getAssertion input"
MAKE_CREDENTIAL_OUTPUT = "makeCredential output"
GET_ASSERTION_OUTPUT = "getAssertion output"
MAKE_CREDENTIAL_UNSIGNED = "makeCredential unsigned output"
GET_ASSERTION_UNSIGNED = "getAssertion unsigned output"
CLIENT_OUTPUT = "client output"

_ROLE_SPECS = {
    MAKE_CREDENTIAL_INPUT: "CTAP 2.2 section 6.1 (0x06 extensions), section 12",
    GET_ASSERTION_INPUT: "CTAP 2.2 section 6.2 (0x04 extensions), section 12",
    MAKE_CREDENTIAL_OUTPUT: "WebAuthn L3 sections 6.1 (ED flag) and 9.5; CTAP 2.2 section 12",
    GET_ASSERTION_OUTPUT: "WebAuthn L3 sections 6.1 (ED flag) and 9.5; CTAP 2.2 section 12",
    MAKE_CREDENTIAL_UNSIGNED: "CTAP 2.2 section 6.1 (0x06 unsignedExtensionOutputs), section 12",
    GET_ASSERTION_UNSIGNED: "CTAP 2.2 section 6.2 (0x08 unsignedExtensionOutputs), section 12",
    CLIENT_OUTPUT: "WebAuthn L3 section 10.1; CTAP 2.2 section 12",
}

_UNKNOWN = "not defined in CTAP 2.2 section 12 or WebAuthn L3 section 10; shown as sent"


def block(value: Any, *, role: str, location: str, path: str, basis: str | None = None) -> dict[str, Any]:
    """Interpret the extensions map ``value`` found at ``location``, playing ``role``."""

    result: dict[str, Any] = {"location": location, "path": path, "role": role, "spec": _ROLE_SPECS[role]}
    if basis:
        result["basis"] = basis
    if not isinstance(value, Mapping):
        result["value"] = hex_json_safe(value)
        result["note"] = "extensions are a map from extension identifier to value; this is not a map"
        return result
    interpret = _client_entry if role == CLIENT_OUTPUT else _authenticator_entry
    result["entries"] = {key_text(name): interpret(name, entry, role) for name, entry in value.items()}
    return result


def _authenticator_entry(name: Any, value: Any, role: str) -> dict[str, Any]:
    view: dict[str, Any] = {"value": hex_json_safe(value)}
    section = ctap_tables.EXTENSIONS.get(name) if isinstance(name, str) else None
    if section is None:
        view.update(known=False, meaning=_UNKNOWN)
        return view
    view.update(known=True, spec=f"CTAP 2.2 section {section}")
    interpret = _AUTHENTICATOR.get((name, role))
    if interpret is None:
        view["note"] = f"CTAP 2.2 section {section} defines no {role} for {name}"
    else:
        view.update(interpret(value))
    return view


def _client_entry(name: Any, value: Any, _role: str) -> dict[str, Any]:
    view: dict[str, Any] = {"value": hex_json_safe(value)}
    known = _CLIENT.get(name) if isinstance(name, str) else None
    if known is None:
        view.update(known=False, meaning=_UNKNOWN)
        return view
    spec, interpret = known
    view.update(known=True, spec=spec)
    view.update(interpret(value))
    return view


# -- small readers ------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _unexpected(expected: str) -> dict[str, Any]:
    return {"note": f"expected {expected} here; shown as sent"}


def _requests(meaning: str) -> Callable[[Any], dict[str, Any]]:
    """An input the spec sends only as true."""

    def read(value: Any) -> dict[str, Any]:
        return {"meaning": meaning} if value is True else _unexpected("true")

    return read


def _flag(if_true: str, if_false: str) -> Callable[[Any], dict[str, Any]]:
    def read(value: Any) -> dict[str, Any]:
        if isinstance(value, bool):
            return {"meaning": if_true if value else if_false}
        return _unexpected("a boolean")

    return read


def _blob(meaning: str) -> Callable[[Any], dict[str, Any]]:
    def read(value: Any) -> dict[str, Any]:
        if isinstance(value, bytes):
            return {"length": len(value), "meaning": meaning if value else f"{meaning}: empty"}
        return _unexpected("a byte string")

    return read


def _members(value: Any, names: tuple[str, ...], expected: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _unexpected(expected)
    extra = [key_text(key) for key in value if key not in names]
    view: dict[str, Any] = {}
    if extra:
        view["note"] = f"{', '.join(extra)}: not in the section's CDDL ({', '.join(names)})"
    return view


# -- CTAP 2.2 section 12 -------------------------------------------------------


def _cred_protect(value: Any) -> dict[str, Any]:
    level = ctap_tables.CRED_PROTECT_LEVELS.get(value) if _is_int(value) else None
    if level is None:
        return _unexpected("a credProtect value 0x01, 0x02 or 0x03")
    return {"meaning": f"{level} (0x{value:02x})"}


def _protocol(value: Mapping[Any, Any]) -> tuple[int, str]:
    protocol = get_mapping_entry(value, 4)
    if _is_int(protocol):
        return protocol, f"pinUvAuthProtocol {protocol}, member 0x04"
    return 1, "pinUvAuthProtocol 1: member 0x04 is absent (CTAP 2.2 section 12.7)"


# encrypt() output lengths: PIN/UV auth protocol 1 encrypts without an IV;
# protocol 2 prefixes a 16-byte IV (CTAP 2.2 sections 6.5.6 and 6.5.7).
_SALT_COUNTS = {(1, 32): "one salt", (1, 64): "two salts", (2, 48): "one salt", (2, 80): "two salts"}


def _hmac_secret_input(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _unexpected("a map of keyAgreement (0x01), saltEnc (0x02), saltAuth (0x03), pinUvAuthProtocol (0x04)")
    protocol, basis = _protocol(value)
    members: dict[str, Any] = {}
    for key, entry in value.items():
        name = ctap_tables.HMAC_SECRET_INPUT.get(key) if _is_int(key) else None
        label = f"{key} ({name})" if name else f"{key_text(key)} (not in CTAP 2.2 section 12.7)"
        view: dict[str, Any] = {"value": hex_json_safe(entry)}
        if name == "keyAgreement":
            view.update(_describe_cose_key(entry))
            alg = get_mapping_entry(entry, 3)
            if _is_int(alg):
                view["algorithm"] = pqc.describe_algorithm(alg)
            view["meaning"] = "the platform's key-agreement public key"
        elif name == "saltEnc" and isinstance(entry, bytes):
            count = _SALT_COUNTS.get((protocol, len(entry)))
            view["length"] = len(entry)
            view["meaning"] = (
                f"{count}, encrypted ({basis})"
                if count
                else f"{len(entry)} bytes is not a length {basis} produces for one or two 32-byte salts"
            )
        elif name == "saltAuth" and isinstance(entry, bytes):
            view["length"] = len(entry)
            view["meaning"] = "authenticate(shared secret, saltEnc): 16 bytes with protocol 1, 32 with protocol 2"
        members[label] = view
    return {"members": members}


_OUTPUT_COUNTS = {32: ("one output", 1), 64: ("two outputs", 1), 48: ("one output", 2), 80: ("two outputs", 2)}


def _hmac_secret_output(value: Any) -> dict[str, Any]:
    if not isinstance(value, bytes):
        return _unexpected("a byte string: output1, or output1 || output2, encrypted")
    known = _OUTPUT_COUNTS.get(len(value))
    if known is None:
        return {"length": len(value), "note": "not 32 or 64 bytes (protocol 1), nor 48 or 80 (protocol 2)"}
    count, protocol = known
    iv = ", after a 16-byte IV" if protocol == 2 else ""
    return {
        "length": len(value),
        "meaning": f"{count}, encrypted with PIN/UV auth protocol {protocol}{iv}; not decrypted here",
    }


def _large_blob_make_credential_input(value: Any) -> dict[str, Any]:
    view = _members(value, ctap_tables.LARGE_BLOB_MAKE_CREDENTIAL_INPUT, "a map {support: \"required\" / \"preferred\"}")
    support = get_mapping_entry(value, "support")
    if support in ("required", "preferred"):
        view["meaning"] = f"large blob support {support}"
    return view


def _large_blob_get_assertion_input(value: Any) -> dict[str, Any]:
    view = _members(value, ctap_tables.LARGE_BLOB_GET_ASSERTION_INPUT, "a map of read, write, originalSize")
    if get_mapping_entry(value, "read") is True:
        view["meaning"] = "read the credential's large blob"
    elif isinstance(get_mapping_entry(value, "write"), bytes):
        view["meaning"] = "write a compressed large blob, with its original size"
    return view


def _large_blob_output(value: Any) -> dict[str, Any]:
    view = _members(value, ctap_tables.LARGE_BLOB_OUTPUTS, "a map of supported, written, blob, originalSize")
    blob = get_mapping_entry(value, "blob")
    if isinstance(blob, bytes):
        view["meaning"] = f"the stored blob, {len(blob)} bytes compressed"
    elif isinstance(get_mapping_entry(value, "written"), bool):
        view["meaning"] = "written" if get_mapping_entry(value, "written") else "not written"
    elif get_mapping_entry(value, "supported") is True:
        view["meaning"] = "the new credential supports large blobs"
    return view


def _large_blob_key_output(_value: Any) -> dict[str, Any]:
    return {
        "note": (
            "CTAP 2.2 section 12.3 returns the key as the response member largeBlobKey "
            "(makeCredential 0x05, getAssertion 0x07), not as an extension output"
        )
    }


_AUTHENTICATOR: dict[tuple[str, str], Callable[[Any], dict[str, Any]]] = {
    ("credProtect", MAKE_CREDENTIAL_INPUT): _cred_protect,
    ("credProtect", MAKE_CREDENTIAL_OUTPUT): _cred_protect,
    ("credBlob", MAKE_CREDENTIAL_INPUT): _blob("the blob to store with the credential"),
    ("credBlob", GET_ASSERTION_INPUT): _requests("asks for the credential's credBlob"),
    ("credBlob", MAKE_CREDENTIAL_OUTPUT): _flag(
        "the credBlob was stored", "the credBlob was not stored (too long, or not supported for this credential)"
    ),
    ("credBlob", GET_ASSERTION_OUTPUT): _blob("the credential's credBlob"),
    ("largeBlobKey", MAKE_CREDENTIAL_INPUT): _requests("asks for a largeBlobKey for the new credential"),
    ("largeBlobKey", GET_ASSERTION_INPUT): _requests("asks for the credential's largeBlobKey"),
    ("largeBlobKey", MAKE_CREDENTIAL_OUTPUT): _large_blob_key_output,
    ("largeBlobKey", GET_ASSERTION_OUTPUT): _large_blob_key_output,
    ("largeBlob", MAKE_CREDENTIAL_INPUT): _large_blob_make_credential_input,
    ("largeBlob", GET_ASSERTION_INPUT): _large_blob_get_assertion_input,
    ("largeBlob", MAKE_CREDENTIAL_UNSIGNED): _large_blob_output,
    ("largeBlob", GET_ASSERTION_UNSIGNED): _large_blob_output,
    ("minPinLength", MAKE_CREDENTIAL_INPUT): _requests("asks for the current minimum PIN length"),
    ("minPinLength", MAKE_CREDENTIAL_OUTPUT): lambda value: (
        {"meaning": f"the current minimum PIN length: {value} Unicode code points"}
        if _is_int(value)
        else _unexpected("an unsigned integer")
    ),
    ("pinComplexityPolicy", MAKE_CREDENTIAL_INPUT): _requests("asks whether a PIN complexity policy is enforced"),
    ("pinComplexityPolicy", MAKE_CREDENTIAL_OUTPUT): _flag(
        "a PIN complexity policy is enforced", "no PIN complexity policy is enforced"
    ),
    ("hmac-secret", MAKE_CREDENTIAL_INPUT): _requests("asks for an hmac-secret for the new credential"),
    ("hmac-secret", GET_ASSERTION_INPUT): _hmac_secret_input,
    ("hmac-secret", MAKE_CREDENTIAL_OUTPUT): _flag(
        "the authenticator made the credential's hmac-secret keys", "the authenticator could not make them"
    ),
    ("hmac-secret", GET_ASSERTION_OUTPUT): _hmac_secret_output,
    ("hmac-secret-mc", MAKE_CREDENTIAL_INPUT): _hmac_secret_input,
    ("hmac-secret-mc", MAKE_CREDENTIAL_OUTPUT): _hmac_secret_output,
    ("thirdPartyPayment", MAKE_CREDENTIAL_INPUT): _requests("marks the new credential for third-party payment"),
    ("thirdPartyPayment", GET_ASSERTION_INPUT): _requests("asks whether the credential is for third-party payment"),
    ("thirdPartyPayment", GET_ASSERTION_OUTPUT): _flag(
        "the credential was made for third-party payment", "the credential was not made for third-party payment"
    ),
}


# -- client extension outputs --------------------------------------------------


def _client_bytes(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return encoding.try_decode_base64url(value)
    return None


def _client_blob(meaning: str) -> Callable[[Any], dict[str, Any]]:
    def read(value: Any) -> dict[str, Any]:
        data = _client_bytes(value)
        if data is None:
            return _unexpected("an ArrayBuffer, as base64url in JSON")
        return {"length": len(data), "meaning": meaning if data else f"{meaning}: empty"}

    return read


def _cred_props(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _unexpected("a CredentialPropertiesOutput map")
    rk = value.get("rk", MISSING)
    if rk is True:
        return {"meaning": "rk true: a client-side discoverable credential"}
    if rk is False:
        return {"meaning": "rk false: not a client-side discoverable credential"}
    if rk is MISSING:
        return {"meaning": "rk absent: the client does not know whether the credential is discoverable"}
    return _unexpected("rk as a boolean")


def _prf(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _unexpected("an AuthenticationExtensionsPRFOutputs map")
    view: dict[str, Any] = {}
    enabled = value.get("enabled")
    if isinstance(enabled, bool):
        view["meaning"] = "the credential supports PRF" if enabled else "the credential does not support PRF"
    results = value.get("results")
    if isinstance(results, Mapping):
        view["results"] = {
            name: (
                {"length": len(data)}
                if (data := _client_bytes(results.get(name))) is not None
                else {"note": "not base64url"}
            )
            for name in ("first", "second")
            if name in results
        }
    return view


def _client_large_blob(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _unexpected("an AuthenticationExtensionsLargeBlobOutputs map")
    view: dict[str, Any] = {}
    if isinstance(value.get("supported"), bool):
        view["meaning"] = "large blobs supported" if value["supported"] else "large blobs not supported"
    elif isinstance(value.get("written"), bool):
        view["meaning"] = "the blob was written" if value["written"] else "the blob was not written"
    elif "blob" in value:
        data = _client_bytes(value["blob"])
        view["meaning"] = f"the stored blob, {len(data)} bytes" if data is not None else "blob is not base64url"
    return view


def _hmac_get_secret(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return _unexpected("an HMACGetSecretOutput map")
    return {
        "outputs": {
            name: {"length": len(data)} if (data := _client_bytes(value.get(name))) is not None else {"note": "not base64url"}
            for name in ("output1", "output2")
            if name in value
        }
    }


_CLIENT: dict[str, tuple[str, Callable[[Any], dict[str, Any]]]] = {
    "appid": (
        "WebAuthn L3 section 10.1.1",
        _flag("the FIDO AppID was used: rpIdHash is the AppID's hash, not the RP ID's", "the RP ID was used"),
    ),
    "appidExclude": (
        "WebAuthn L3 section 10.1.2",
        _flag("the client processed appidExclude", "the client did not process appidExclude"),
    ),
    "credProps": ("WebAuthn L3 section 10.1.3", _cred_props),
    "prf": ("WebAuthn L3 section 10.1.4", _prf),
    "largeBlob": ("WebAuthn L3 section 10.1.5", _client_large_blob),
}

# The client outputs CTAP 2.2 section 12 defines, read by the section ctap_tables names.
_CTAP_CLIENT: dict[str, Callable[[Any], dict[str, Any]]] = {
    "credBlob": _flag("the credBlob was stored", "the credBlob was not stored"),
    "getCredBlob": _client_blob("the credential's credBlob"),
    "hmacCreateSecret": _flag("the authenticator processed hmac-secret", "the authenticator did not process hmac-secret"),
    "hmacGetSecret": _hmac_get_secret,
}
_CLIENT.update(
    (name, (f"CTAP 2.2 section {section}", _CTAP_CLIENT[name]))
    for name, section in ctap_tables.CLIENT_EXTENSION_OUTPUTS.items()
)
