"""The requests each characterization scenario sends.

Each scenario is a function of a :class:`harness.Recorder`; the harness records
every request it makes. Between them they walk every exit of the route and
attestation functions Phase 18 moved, success and error alike.
"""
from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from ..security.ceremony_helpers import (
    ORIGIN,
    advanced_public_key_options,
    b64u,
    unb64u,
)
from . import material as m
from .harness import Recorder

EMAIL = "user@example.com"
HEADERS = {"Origin": ORIGIN}
CUSTOM_ALGORITHM = -12345
AAGUID = bytes.fromhex("00112233445566778899aabbccddeeff")

SCENARIOS: dict[str, Callable[[Recorder], None]] = {}


def scenario(name: str):
    def register(function: Callable[[Recorder], None]):
        SCENARIOS[name] = function
        return function

    return register


# -- simple flow -----------------------------------------------------------------


def _simple_begin(r: Recorder, client, *, email: str = EMAIL, credentials: list[Any] | None = None) -> bytes:
    begin = r.post(client, f"/api/register/begin?email={email}", json={"credentials": credentials or []})
    return unb64u(begin.get_json()["publicKey"]["challenge"])


def _simple_register(r: Recorder, client, authenticator, *, email: str = EMAIL, **payload: Any):
    challenge = _simple_begin(r, client, email=email)
    return r.post(
        client,
        f"/api/register/complete?email={email}",
        json=m.registration_payload(authenticator, challenge=challenge, **payload),
        headers=HEADERS,
    )


def _simple_authenticate(r: Recorder, client, authenticator, *, counter: int, valid: bool = True, entry=None):
    begin = r.post(
        client,
        f"/api/authenticate/begin?email={EMAIL}",
        json={"credentials": [entry or authenticator.stored_credential_entry()]},
    )
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    return r.post(
        client,
        f"/api/authenticate/complete?email={EMAIL}",
        json=m.assertion_payload(authenticator, challenge=challenge, counter=counter, valid_signature=valid),
        headers=HEADERS,
    )


@scenario("simple-register-es256")
def _(r: Recorder) -> None:
    _simple_register(r, r.client(), m.Authenticator("simple-es256", aaguid=AAGUID), counter=3)


@scenario("simple-register-ed25519")
def _(r: Recorder) -> None:
    _simple_register(r, r.client(), m.Authenticator("simple-ed25519", key_type="ed25519"))


@scenario("simple-register-rs256")
def _(r: Recorder) -> None:
    _simple_register(r, r.client(), m.Authenticator("simple-rs256", key_type="rs256"))


@scenario("simple-register-mldsa65")
def _(r: Recorder) -> None:
    _simple_register(r, r.client(), m.Authenticator("simple-mldsa65", key_type="ML-DSA-65"))


@scenario("simple-register-packed-self")
def _(r: Recorder) -> None:
    _simple_register(r, r.client(), m.Authenticator("simple-packed-self"), attestation="self")


@scenario("simple-register-packed-x5c-extensions")
def _(r: Recorder) -> None:
    _simple_register(
        r,
        r.client(),
        m.Authenticator("simple-x5c", aaguid=AAGUID),
        attestation="x5c",
        extension_results={"credProps": {"rk": True}, "largeBlob": {"supported": True}, "minPinLength": 8},
        attachment="cross-platform",
        transports=["usb", "nfc"],
    )


@scenario("simple-register-two-credentials-and-exclude-list")
def _(r: Recorder) -> None:
    client = r.client()
    first = m.Authenticator("simple-first")
    _simple_register(r, client, first)
    challenge = _simple_begin(r, client, credentials=[first.stored_credential_entry()])
    r.post(
        client,
        f"/api/register/complete?email={EMAIL}",
        json=m.registration_payload(m.Authenticator("simple-second", key_type="ed25519"), challenge=challenge),
        headers=HEADERS,
    )


@scenario("simple-register-failures")
def _(r: Recorder) -> None:
    authenticator = m.Authenticator("simple-failures")
    client = r.client()
    # No state at all.
    r.post(
        client,
        f"/api/register/complete?email={EMAIL}",
        json=m.registration_payload(authenticator, challenge=b"\x01" * 32),
        headers=HEADERS,
    )
    # Replay of a consumed challenge with the earlier cookie.
    challenge = _simple_begin(r, client)
    cookie = client.get_cookie("session").value
    payload = m.registration_payload(authenticator, challenge=challenge)
    r.post(client, f"/api/register/complete?email={EMAIL}", json=payload, headers=HEADERS)
    client.set_cookie("session", cookie)
    r.post(client, f"/api/register/complete?email={EMAIL}", json=payload, headers=HEADERS)
    # Origin outside the allowlist.
    challenge = _simple_begin(r, client)
    r.post(
        client,
        f"/api/register/complete?email={EMAIL}",
        json=m.registration_payload(authenticator, challenge=challenge, origin="https://elsewhere.example"),
        headers=HEADERS,
    )
    # fido2 accepts this origin for the RP ID; the allowlist does not.
    challenge = _simple_begin(r, client)
    r.post(
        client,
        f"/api/register/complete?email={EMAIL}",
        json=m.registration_payload(authenticator, challenge=challenge, origin="http://localhost:8443"),
        headers=HEADERS,
    )
    # fido2 refuses it: the challenge does not match.
    _simple_begin(r, client)
    r.post(
        client,
        f"/api/register/complete?email={EMAIL}",
        json=m.registration_payload(authenticator, challenge=b"\x02" * 32),
        headers=HEADERS,
    )
    # Attestation checks report an error (cross-origin).
    challenge = _simple_begin(r, client)
    r.post(
        client,
        f"/api/register/complete?email={EMAIL}",
        json=m.registration_payload(authenticator, challenge=challenge, cross_origin=True),
        headers=HEADERS,
    )
    # A name the store refuses.
    _simple_register(r, client, authenticator, email="../escape")


@scenario("simple-authenticate")
def _(r: Recorder) -> None:
    client = r.client()
    authenticator = m.Authenticator("simple-auth")
    _simple_register(r, client, authenticator, counter=5)
    _simple_authenticate(r, client, authenticator, counter=6)
    _simple_authenticate(r, client, authenticator, counter=4)
    _simple_authenticate(r, client, authenticator, counter=9, valid=False)
    r.post(client, f"/api/authenticate/begin?email={EMAIL}", json={"credentials": []})
    r.post(client, f"/api/authenticate/complete?email={EMAIL}", json={}, headers=HEADERS)


@scenario("simple-authenticate-mldsa44")
def _(r: Recorder) -> None:
    client = r.client()
    authenticator = m.Authenticator("simple-auth-mldsa44", key_type="ML-DSA-44")
    _simple_register(r, client, authenticator, counter=1)
    _simple_authenticate(r, client, authenticator, counter=2)


# -- advanced registration -----------------------------------------------------------


def _options(challenge: bytes = b"\x31" * 32, **overrides: Any) -> dict[str, Any]:
    options = advanced_public_key_options(challenge=challenge)
    options.update(overrides)
    return options


def _advanced_register(
    r: Recorder,
    client,
    authenticator,
    *,
    options: dict[str, Any] | None = None,
    begin: bool = True,
    extra: dict[str, Any] | None = None,
    **payload: Any,
):
    options = options or _options()
    challenge = unb64u(options["challenge"]["$base64url"])
    if begin:
        response = r.post(client, "/api/advanced/register/begin", json={"publicKey": copy.deepcopy(options)})
        if response is not None and response.status_code == 200:
            challenge = unb64u(response.get_json()["publicKey"]["challenge"])
    return r.post(
        client,
        "/api/advanced/register/complete",
        json={
            "publicKey": copy.deepcopy(options),
            "__credential_response": m.registration_payload(authenticator, challenge=challenge, **payload),
            **(extra or {}),
        },
        headers=HEADERS,
    )


EVERY_PARAM_SHAPE = [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -8},
    {"type": "public-key", "id": -257},
    {"type": "public-key", "value": -48},
    {"type": "public-key", "alg": -49},
    {"type": "public-key", "alg": -50},
    {"type": "other", "alg": -35},
    {"type": 7, "alg": -36},
    "ES384",
    -37,
    {"type": "public-key", "alg": "not-a-number"},
]

EVERY_EXTENSION = {
    "credProps": True,
    "minPinLength": True,
    "credentialProtectionPolicy": "userVerificationOptionalWithCredentialIDList",
    "enforceCredentialProtectionPolicy": True,
    "largeBlob": {"support": "preferred"},
    "prf": {"eval": {"first": {"$base64url": b64u(b"\x07" * 32)}, "second": "0a0b0c"}},
    "credBlob": {"$base64url": b64u(b"blob")},
    "hmacCreateSecret": True,
}


@scenario("advanced-register-begin-options")
def _(r: Recorder) -> None:
    client = r.client()
    post = lambda options: r.post(client, "/api/advanced/register/begin", json={"publicKey": options})  # noqa: E731
    post(_options())
    post(
        _options(
            pubKeyCredParams=EVERY_PARAM_SHAPE,
            authenticatorSelection={
                "residentKey": "required",
                "userVerification": "required",
                "authenticatorAttachment": "platform",
            },
            attestation="direct",
            timeout=120000,
            hints=["client-device"],
            excludeCredentials=[
                {"type": "public-key", "id": {"$base64url": b64u(b"\x11" * 16)}, "transports": ["usb"]},
                {"type": "public-key", "id": "2222"},
                {"type": "other", "id": "33"},
                "not-a-descriptor",
            ],
            extensions=EVERY_EXTENSION,
        )
    )
    post(_options(pubKeyCredParams=[]))
    post({key: value for key, value in _options().items() if key != "pubKeyCredParams"})
    post(_options(attestation="indirect", authenticatorSelection={"requireResidentKey": True, "userVerification": "discouraged"}))
    post(_options(attestation="enterprise", authenticatorSelection={"residentKey": "discouraged"}, hints=["security-key"], timeout=0))
    post(_options(authenticatorSelection="not-a-mapping", hints=["hybrid", 7]))
    post(_options(extensions={"credProtect": 3, "enforceCredProtect": False, "largeBlob": "required", "prf": {}}))


@scenario("advanced-register-begin-pqc-unavailable")
def _(r: Recorder) -> None:
    from server.app.webauthn import pqc

    r.env.monkeypatch.setattr(pqc, "detect_available_pqc_algorithms", lambda: (set(), "liboqs unavailable"))
    client = r.client()
    post = lambda options: r.post(client, "/api/advanced/register/begin", json={"publicKey": options})  # noqa: E731
    post(_options(pubKeyCredParams=[{"type": "public-key", "alg": -48}, {"type": "public-key", "alg": -49}]))
    post(_options(pubKeyCredParams=[{"type": "public-key", "alg": -50}, {"type": "public-key", "alg": -7}]))
    post({key: value for key, value in _options().items() if key != "pubKeyCredParams"})


@scenario("advanced-register-begin-failures")
def _(r: Recorder) -> None:
    client = r.client()
    post = lambda body: r.post(client, "/api/advanced/register/begin", json=body)  # noqa: E731
    post({})
    post({"publicKey": {}})
    post({"publicKey": {key: value for key, value in _options().items() if key != "rp"}})
    post({"publicKey": {key: value for key, value in _options().items() if key != "user"}})
    post({"publicKey": {key: value for key, value in _options().items() if key != "challenge"}})
    post({"publicKey": _options(user={"id": "00", "name": ""})})
    post({"publicKey": _options(user={"id": "zz-not-hex", "name": "user@example.com"})})
    post({"publicKey": _options(user={"name": "user@example.com", "displayName": "No Id"})})
    post({"publicKey": {**_options(), "challenge": "zz-not-hex"}})
    post({"publicKey": {**_options(), "challenge": "0102"}})
    post({"publicKey": _options(extensions=["not", "a", "mapping"])})
    post({"publicKey": ["not", "a", "mapping"]})


@scenario("advanced-register-none-es256")
def _(r: Recorder) -> None:
    _advanced_register(r, r.client(), m.Authenticator("adv-es256", aaguid=AAGUID), counter=7)


@scenario("advanced-register-packed-self-ed25519")
def _(r: Recorder) -> None:
    _advanced_register(
        r, r.client(), m.Authenticator("adv-ed25519", key_type="ed25519"), attestation="self",
        options=_options(pubKeyCredParams=[{"type": "public-key", "alg": -8}]),
    )


@scenario("advanced-register-packed-x5c-everything")
def _(r: Recorder) -> None:
    options = _options(
        pubKeyCredParams=[{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
        authenticatorSelection={"residentKey": "preferred", "authenticatorAttachment": "cross-platform"},
        attestation="direct",
        hints=["security-key"],
        excludeCredentials=[{"type": "public-key", "id": {"$base64url": b64u(b"\x44" * 16)}}],
        extensions=EVERY_EXTENSION,
    )
    _advanced_register(
        r,
        r.client(),
        m.Authenticator("adv-x5c", aaguid=AAGUID),
        options=options,
        attestation="x5c",
        attachment="cross-platform",
        transports=["usb", "nfc", 7],
        extension_results={
            "credProps": {"rk": False},
            "largeBlob": {"written": True},
            "minPinLength": 6,
            "prf": {"enabled": True},
        },
    )


@scenario("advanced-register-mldsa44-self")
def _(r: Recorder) -> None:
    _advanced_register(
        r, r.client(), m.Authenticator("adv-mldsa44", key_type="ML-DSA-44"), attestation="self",
        options=_options(pubKeyCredParams=[{"type": "public-key", "alg": -48}]),
    )


@scenario("advanced-register-rs256-and-cred-protect")
def _(r: Recorder) -> None:
    client = r.client()
    authenticator = m.Authenticator("adv-rs256", key_type="rs256")
    for index, extensions in enumerate(
        (
            {"credProtect": 3, "enforceCredProtect": True},
            {"credentialProtectionPolicy": 9},
            {"credProtect": "userVerificationRequired"},
            {"largeBlob": {"support": "required"}},
        )
    ):
        _advanced_register(
            r, client, authenticator,
            options=_options(challenge=bytes([0x50 + index]) * 32, extensions=extensions,
                             pubKeyCredParams=[{"type": "public-key", "alg": -257}]),
            extension_results={"credProps": True, "largeBlob": index % 2 == 0},
        )


@scenario("advanced-register-user-handles")
def _(r: Recorder) -> None:
    client = r.client()
    authenticator = m.Authenticator("adv-user-handles")
    for index, user in enumerate(
        (
            {"id": {"$base64url": b64u(b"handle")}, "name": "a@example.com", "displayName": "A"},
            {"id": "zz-not-hex", "name": "b@example.com"},
            {"name": "c@example.com"},
        )
    ):
        options = _options(challenge=bytes([0x60 + index]) * 32, user=user)
        # No begin: the request editor supplies its own state, so the user handle is not validated there.
        _advanced_register(
            r, client, authenticator, options=options, begin=False,
            extra={"__session_state": {"challenge": b64u(bytes([0x60 + index]) * 32), "user_verification": "discouraged"}},
        )


@scenario("advanced-register-complete-failures")
def _(r: Recorder) -> None:
    client = r.client()
    authenticator = m.Authenticator("adv-failures")
    post = lambda body: r.post(client, "/api/advanced/register/complete", json=body, headers=HEADERS)  # noqa: E731
    credential = m.registration_payload(authenticator, challenge=b"\x31" * 32)
    post({"publicKey": _options()})
    post({"__credential_response": credential})
    post({"publicKey": _options(user={"id": "00", "name": ""}), "__credential_response": credential})
    # No state anywhere.
    post({"publicKey": _options(), "__credential_response": credential})
    # A replayed server challenge is reported, not rejected.
    begin = r.post(client, "/api/advanced/register/begin", json={"publicKey": _options()})
    cookie = client.get_cookie("session").value
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    good = {"publicKey": _options(), "__credential_response": m.registration_payload(authenticator, challenge=challenge)}
    post(good)
    client.set_cookie("session", cookie)
    post(good)
    # Origin outside the allowlist: one fido2 refuses, one only the allowlist refuses.
    _advanced_register(r, client, authenticator, origin="https://elsewhere.example")
    _advanced_register(r, client, authenticator, origin="http://localhost:8443")
    # fido2 refuses it.
    r.post(client, "/api/advanced/register/begin", json={"publicKey": _options()})
    post({"publicKey": _options(), "__credential_response": m.registration_payload(authenticator, challenge=b"\x09" * 32)})
    # Cross-origin: an attestation error, reported.
    _advanced_register(r, client, authenticator, cross_origin=True)


@scenario("advanced-register-attachment-hints")
def _(r: Recorder) -> None:
    client = r.client()
    authenticator = m.Authenticator("adv-attachment")
    platform_only = _options(hints=["client-device"])
    _advanced_register(r, client, authenticator, options=platform_only)
    _advanced_register(r, client, authenticator, options=platform_only, attachment="cross-platform")
    _advanced_register(r, client, authenticator, options=platform_only, attachment="platform")
    _advanced_register(
        r, client, authenticator, begin=False, attachment="cross-platform",
        options=_options(authenticatorSelection={"authenticatorAttachment": "platform"}),
        extra={"__session_state": {"challenge": b64u(b"\x31" * 32), "user_verification": "preferred"}},
    )


@scenario("advanced-register-client-state-rp")
def _(r: Recorder) -> None:
    client = r.client()
    authenticator = m.Authenticator("adv-client-state")
    state = {"__session_state": {"challenge": b64u(b"\x31" * 32), "user_verification": "discouraged"}}
    _advanced_register(r, client, authenticator, begin=False, extra=state)
    options = _options()
    options.pop("rp")
    options["rpId"] = "localhost"
    _advanced_register(r, client, authenticator, begin=False, extra=state, options=options)


# -- advanced authentication ---------------------------------------------------------


def _auth_options(challenge: bytes = b"\x71" * 32, **overrides: Any) -> dict[str, Any]:
    return {"challenge": {"$base64url": b64u(challenge)}, **overrides}


def _advanced_authenticate(
    r: Recorder,
    client,
    authenticator,
    *,
    entries: list[Any] | None = None,
    options: dict[str, Any] | None = None,
    begin: bool = True,
    counter: int = 1,
    valid: bool = True,
    attachment: str | None = None,
    extra: dict[str, Any] | None = None,
):
    options = options or _auth_options()
    entries = entries if entries is not None else [authenticator.stored_credential_entry(declared_algorithm=-7)]
    challenge = unb64u(options["challenge"]["$base64url"])
    if begin:
        response = r.post(
            client, "/api/advanced/authenticate/begin",
            json={"publicKey": copy.deepcopy(options), "__storedCredentials": entries},
        )
        if response is not None and response.status_code == 200:
            challenge = unb64u(response.get_json()["publicKey"]["challenge"])
    return r.post(
        client,
        "/api/advanced/authenticate/complete",
        json={
            "publicKey": copy.deepcopy(options),
            "__storedCredentials": entries,
            "__assertion_response": m.assertion_payload(
                authenticator, challenge=challenge, counter=counter, valid_signature=valid, attachment=attachment
            ),
            **(extra or {}),
        },
        headers=HEADERS,
    )


@scenario("advanced-authenticate-begin-options")
def _(r: Recorder) -> None:
    client = r.client()
    es256 = m.Authenticator("adv-auth-es256")
    ed25519 = m.Authenticator("adv-auth-ed25519", key_type="ed25519")
    entries = [
        {**es256.stored_credential_entry(declared_algorithm=-7), "authenticatorAttachment": "cross-platform"},
        {**ed25519.stored_credential_entry(declared_algorithm=-8, resident=False), "authenticatorAttachment": "platform"},
    ]
    post = lambda options, stored=entries: r.post(  # noqa: E731
        client, "/api/advanced/authenticate/begin", json={"publicKey": options, "__storedCredentials": stored}
    )
    allow = [
        {"type": "public-key", "id": {"$base64url": b64u(es256.credential_id)}},
        {"type": "public-key", "id": es256.credential_id.hex()},
        {"type": "public-key", "id": "zz-not-hex"},
        {"type": "other", "id": "00"},
        "not-a-descriptor",
    ]
    post(_auth_options(allowCredentials=allow, userVerification="required", timeout=30000))
    post(_auth_options(allowCredentials=[{"type": "public-key", "id": "0badbeef"}], userVerification="discouraged"))
    post(_auth_options(hints=["security-key"], allowCredentials=allow))
    post(_auth_options(hints=["client-device"]))
    post(_auth_options(hints=["hybrid"], timeout=0))
    post(_auth_options())
    post(_auth_options(extensions={
        "largeBlob": {"read": True},
        "prf": {"eval": {"first": {"$base64url": b64u(b"\x01" * 32)}, "second": "0203"}},
        "appid": "https://localhost",
    }))
    post(_auth_options(extensions={"largeBlob": {"write": "0a0b"}, "prf": {"eval": {}}, "credBlob": True}))
    post(_auth_options(extensions={"largeBlob": {"other": 1}, "prf": "not-a-mapping"}))
    post(_auth_options(extensions={"largeBlob": "plain"}))


@scenario("advanced-authenticate-begin-failures")
def _(r: Recorder) -> None:
    client = r.client()
    es256 = m.Authenticator("adv-auth-begin-failures")
    platform_entry = {**es256.stored_credential_entry(declared_algorithm=-7), "authenticatorAttachment": "platform"}
    non_resident = es256.stored_credential_entry(declared_algorithm=-7, resident=False)
    post = lambda body: r.post(client, "/api/advanced/authenticate/begin", json=body)  # noqa: E731
    post({})
    post({"publicKey": {"timeout": 1}})
    post({"publicKey": _auth_options(), "__storedCredentials": []})
    post({"publicKey": _auth_options(challenge=b"")})
    post({"publicKey": {"challenge": "zz-not-hex"}, "__storedCredentials": [platform_entry]})
    allow = [{"type": "public-key", "id": {"$base64url": b64u(es256.credential_id)}}]
    post({"publicKey": _auth_options(hints=["security-key"], allowCredentials=allow), "__storedCredentials": [platform_entry]})
    post({"publicKey": _auth_options(hints=["security-key"]), "__storedCredentials": [platform_entry]})
    post({"publicKey": _auth_options(), "storedCredentials": [non_resident]})
    post({"publicKey": _auth_options(), "credentials": ["not-a-credential"]})
    post({"publicKey": _auth_options(extensions=["not", "a", "mapping"]), "__storedCredentials": [platform_entry]})


@scenario("advanced-authenticate-complete")
def _(r: Recorder) -> None:
    client = r.client()
    es256 = m.Authenticator("adv-auth-complete")
    _advanced_authenticate(r, client, es256, counter=3)
    _advanced_authenticate(
        r, client, es256, counter=2,
        entries=[{**es256.stored_credential_entry(declared_algorithm=-7), "signCount": 10}],
    )
    _advanced_authenticate(r, client, es256, counter=4, valid=False)
    _advanced_authenticate(
        r, client, es256, counter=5,
        options=_auth_options(allowCredentials=[{"type": "public-key", "id": {"$base64url": b64u(es256.credential_id)}}]),
        extra={"__hash_algorithm": "SHA-384"},
    )
    _advanced_authenticate(r, client, es256, counter=6, extra={"__hash_algorithm": 256})
    ed25519 = m.Authenticator("adv-auth-complete-ed25519", key_type="ed25519")
    _advanced_authenticate(r, client, ed25519, entries=[ed25519.stored_credential_entry(declared_algorithm=-8)])
    mldsa = m.Authenticator("adv-auth-complete-mldsa65", key_type="ML-DSA-65")
    _advanced_authenticate(r, client, mldsa, entries=[mldsa.stored_credential_entry(declared_algorithm=-49)])
    exotic = es256.cose_key_with_declared_algorithm(CUSTOM_ALGORITHM)
    _advanced_authenticate(
        r, client, es256, valid=False,
        entries=[es256.stored_credential_entry(declared_algorithm=CUSTOM_ALGORITHM, cose_key_bytes=exotic)],
    )
    _advanced_authenticate(
        r, client, es256, valid=False,
        entries=[es256.stored_credential_entry(declared_algorithm=CUSTOM_ALGORITHM)],
    )


@scenario("advanced-authenticate-complete-failures")
def _(r: Recorder) -> None:
    client = r.client()
    es256 = m.Authenticator("adv-auth-complete-failures")
    entry = es256.stored_credential_entry(declared_algorithm=-7)
    assertion = m.assertion_payload(es256, challenge=b"\x71" * 32)
    post = lambda body: r.post(client, "/api/advanced/authenticate/complete", json=body, headers=HEADERS)  # noqa: E731
    post({"publicKey": _auth_options(), "__storedCredentials": [entry]})
    post({"publicKey": "not-a-mapping", "__assertion_response": assertion})
    post({"publicKey": _auth_options(), "__assertion_response": assertion, "__storedCredentials": ["bad"]})
    post({"publicKey": _auth_options(), "__assertion_response": assertion})
    # A non-discoverable credential with an empty allow list.
    post({
        "publicKey": _auth_options(),
        "__assertion_response": assertion,
        "__storedCredentials": [es256.stored_credential_entry(declared_algorithm=-7, resident=False)],
    })
    # No state, then the client-supplied fallback state.
    post({"publicKey": _auth_options(), "__assertion_response": assertion, "__storedCredentials": [entry]})
    post({
        "publicKey": _auth_options(),
        "__assertion_response": assertion,
        "__storedCredentials": [entry],
        "__session_state": {"challenge": b64u(b"\x71" * 32), "user_verification": "preferred"},
    })
    # Origin outside the allowlist.
    post({
        "publicKey": _auth_options(),
        "__assertion_response": m.assertion_payload(es256, challenge=b"\x71" * 32, origin="https://elsewhere.example"),
        "__storedCredentials": [entry],
        "__session_state": {"challenge": b64u(b"\x71" * 32), "user_verification": "preferred"},
    })
    # A replayed server challenge is reported, not rejected.
    begin = r.post(client, "/api/advanced/authenticate/begin", json={"publicKey": _auth_options(), "__storedCredentials": [entry]})
    cookie = client.get_cookie("session").value
    challenge = unb64u(begin.get_json()["publicKey"]["challenge"])
    replayed = {
        "publicKey": _auth_options(),
        "__storedCredentials": [entry],
        "__assertion_response": m.assertion_payload(es256, challenge=challenge, counter=2),
    }
    post(replayed)
    client.set_cookie("session", cookie)
    post(replayed)
    # Attachment enforcement against the hints of begin.
    roaming = [{**entry, "authenticatorAttachment": "cross-platform"}]
    hinted = _auth_options(hints=["security-key"])
    _advanced_authenticate(r, client, es256, options=hinted, entries=roaming)
    _advanced_authenticate(r, client, es256, options=hinted, entries=roaming, attachment="platform")
    _advanced_authenticate(r, client, es256, options=hinted, entries=roaming, attachment="cross-platform")
    # Legacy session credentials, when the request carries none.
    with client.session_transaction() as session:
        session["advanced_auth_credentials"] = ["unparseable"]
    post({"publicKey": _auth_options(), "__assertion_response": assertion})


# -- decoder -------------------------------------------------------------------------


@scenario("decoder-attestation-objects")
def _(r: Recorder) -> None:
    client = r.client()
    for payload in m.captured_attestation_objects().values():
        r.post(client, "/api/decode", json={"payload": payload.hex()})


# -- storage failures and RP fallbacks -------------------------------------------------


@scenario("simple-register-store-unwritable")
def _(r: Recorder) -> None:
    from server.app.storage import credentials

    # A regular file where the store's directory should be: reads and writes both fail.
    blocker = r.env.tmp_path / "blocker"
    blocker.write_text("not a directory")
    r.env.monkeypatch.setattr(credentials, "_LOCAL_CREDENTIAL_BASE", str(blocker / "credentials"))
    _simple_register(r, r.client(), m.Authenticator("simple-unwritable"))


@scenario("simple-register-save-fails")
def _(r: Recorder) -> None:
    from server.app.storage import credentials

    client = r.client()
    # A stored credential, so the read before each save below reads a record.
    _simple_register(r, client, m.Authenticator("simple-save-first"))
    write = credentials.replace_file

    def _fails(path: str, payload: bytes) -> None:
        raise OSError("no space left on device")

    # The read succeeds; the write raises before anything lands.
    r.env.monkeypatch.setattr(credentials, "replace_file", _fails)
    _simple_register(r, client, m.Authenticator("simple-save-fails"))

    def _lands_then_fails(path: str, payload: bytes) -> None:
        write(path, payload)
        raise OSError("connection reset after the write")

    # The write lands, then raises: the re-read finds the credential stored.
    r.env.monkeypatch.setattr(credentials, "replace_file", _lands_then_fails)
    _simple_register(r, client, m.Authenticator("simple-save-lands"))


@scenario("advanced-register-artifact-store-fails")
def _(r: Recorder) -> None:
    from server.app import credential_artifacts

    client = r.client()
    authenticator = m.Authenticator("adv-artifact-fails")
    r.env.monkeypatch.setattr(credential_artifacts, "store_credential_artifact", lambda *_a, **_k: False)
    _advanced_register(r, client, authenticator)

    def _raise(*_args, **_kwargs):
        raise OSError("bucket unreachable")

    r.env.monkeypatch.setattr(credential_artifacts, "store_credential_artifact", _raise)
    _advanced_register(r, client, authenticator, options=_options(challenge=b"\x32" * 32))


@scenario("advanced-authenticate-rp-fallbacks")
def _(r: Recorder) -> None:
    client = r.client()
    es256 = m.Authenticator("adv-auth-rp")
    entry = es256.stored_credential_entry(declared_algorithm=-7)
    state = {"__session_state": {"challenge": b64u(b"\x71" * 32), "user_verification": "preferred"}}
    # The request's own rp, then its rpId, when the session has no RP.
    _advanced_authenticate(r, client, es256, begin=False, entries=[entry], extra=state,
                           options=_auth_options(rp={"id": "localhost", "name": "Named RP"}))
    _advanced_authenticate(r, client, es256, begin=False, entries=[entry], extra=state, options=_auth_options(rpId="localhost"))
    # The registration RP left in the session by an advanced register begin.
    r.post(client, "/api/advanced/register/begin", json={"publicKey": _options()})
    _advanced_authenticate(r, client, es256, begin=False, entries=[entry], extra=state)
    # An assertion for a credential the request did not list.
    stranger = m.Authenticator("adv-auth-stranger")
    _advanced_authenticate(r, client, stranger, entries=[entry], valid=False)
