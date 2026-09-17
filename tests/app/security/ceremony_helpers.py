"""Real-crypto WebAuthn ceremony builders for the security regression tests.

These helpers deliberately use genuine key material and genuine signatures
(``cryptography``'s EC / Ed25519 primitives) and never stub out any
verification code path. A test that needs a ceremony to fail makes it fail by
producing genuinely wrong bytes, not by patching the verifier.

Only *storage* side effects are stubbed by the tests that use these helpers.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Mapping, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fido2 import cbor
from fido2.cose import ES256, EdDSA

RP_ID = "localhost"
ORIGIN = "http://localhost"

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40


def b64u(raw: bytes) -> str:
    """Encode bytes as unpadded base64url."""

    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64u(value: str) -> bytes:
    """Decode unpadded base64url back to bytes."""

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class Authenticator:
    """A minimal software authenticator backed by a real signing key."""

    def __init__(
        self,
        *,
        credential_id: bytes = b"\x42" * 32,
        aaguid: bytes = b"\x00" * 16,
        key_type: str = "es256",
    ) -> None:
        self.credential_id = credential_id
        self.aaguid = aaguid
        self.key_type = key_type
        if key_type == "es256":
            self._private_key: Any = ec.generate_private_key(ec.SECP256R1())
            self.cose_key: Mapping[int, Any] = ES256.from_cryptography_key(
                self._private_key.public_key()
            )
        elif key_type == "ed25519":
            self._private_key = ed25519.Ed25519PrivateKey.generate()
            self.cose_key = EdDSA.from_cryptography_key(self._private_key.public_key())
        else:  # pragma: no cover - defensive guard
            raise ValueError(f"unsupported key type: {key_type}")

    # -- key material -----------------------------------------------------

    @property
    def cose_key_bytes(self) -> bytes:
        return cbor.encode(self.cose_key)

    def cose_key_with_declared_algorithm(self, algorithm: int) -> bytes:
        """Return this key's CBOR with COSE label 3 overridden.

        Used to build a credential whose own key declares an algorithm this
        server cannot verify.
        """

        mutated = dict(self.cose_key)
        mutated[3] = algorithm
        return cbor.encode(mutated)

    def sign(self, message: bytes) -> bytes:
        if self.key_type == "es256":
            return self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return self._private_key.sign(message)

    # -- ceremony material ------------------------------------------------

    def authenticator_data(
        self,
        *,
        rp_id: str = RP_ID,
        counter: int = 0,
        include_credential: bool = True,
        user_verified: bool = True,
        cose_key_bytes: Optional[bytes] = None,
    ) -> bytes:
        flags = FLAG_UP
        if user_verified:
            flags |= FLAG_UV
        if include_credential:
            flags |= FLAG_AT

        data = (
            hashlib.sha256(rp_id.encode("utf-8")).digest()
            + bytes([flags])
            + counter.to_bytes(4, "big")
        )
        if include_credential:
            key_bytes = self.cose_key_bytes if cose_key_bytes is None else cose_key_bytes
            data += (
                self.aaguid
                + len(self.credential_id).to_bytes(2, "big")
                + self.credential_id
                + key_bytes
            )
        return data

    def stored_credential_entry(
        self,
        *,
        declared_algorithm: Optional[int] = None,
        cose_key_bytes: Optional[bytes] = None,
        resident: bool = True,
    ) -> dict[str, Any]:
        """Build the client-supplied credential record the advanced tab sends.

        ``declared_algorithm`` populates the ``algorithm`` field, which is
        independent of the COSE key's own label 3 -- that independence is the
        heart of the custom-algorithm bypass.
        """

        entry: dict[str, Any] = {
            "credentialId": b64u(self.credential_id),
            "publicKey": b64u(
                self.cose_key_bytes if cose_key_bytes is None else cose_key_bytes
            ),
            "aaguid": b64u(self.aaguid),
            "resident": resident,
        }
        if declared_algorithm is not None:
            entry["algorithm"] = declared_algorithm
        return entry


def client_data(
    *,
    challenge: bytes,
    ceremony_type: str,
    origin: str = ORIGIN,
    cross_origin: bool = False,
) -> bytes:
    """Serialise a clientDataJSON blob."""

    return json.dumps(
        {
            "type": ceremony_type,
            "challenge": b64u(challenge),
            "origin": origin,
            "crossOrigin": cross_origin,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def attestation_object(auth_data: bytes, *, fmt: str = "none", att_stmt: Optional[Mapping[str, Any]] = None) -> bytes:
    return cbor.encode(
        {"fmt": fmt, "attStmt": dict(att_stmt or {}), "authData": auth_data}
    )


def registration_payload(
    authenticator: Authenticator,
    *,
    challenge: bytes,
    origin: str = ORIGIN,
    rp_id: str = RP_ID,
    cross_origin: bool = False,
    cose_key_bytes: Optional[bytes] = None,
    counter: int = 0,
) -> dict[str, Any]:
    """Build a complete, genuinely-signed registration response."""

    data = client_data(
        challenge=challenge, ceremony_type="webauthn.create", origin=origin,
        cross_origin=cross_origin,
    )
    auth_data = authenticator.authenticator_data(
        rp_id=rp_id, cose_key_bytes=cose_key_bytes, counter=counter
    )
    return {
        "id": b64u(authenticator.credential_id),
        "rawId": b64u(authenticator.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(data),
            "attestationObject": b64u(attestation_object(auth_data)),
        },
        "clientExtensionResults": {},
    }


def assertion_payload(
    authenticator: Authenticator,
    *,
    challenge: bytes,
    origin: str = ORIGIN,
    rp_id: str = RP_ID,
    counter: int = 1,
    valid_signature: bool = True,
) -> dict[str, Any]:
    """Build an assertion response.

    With ``valid_signature=False`` the signature is a real signature over the
    WRONG message -- structurally well formed, cryptographically invalid.
    """

    data = client_data(challenge=challenge, ceremony_type="webauthn.get", origin=origin)
    auth_data = authenticator.authenticator_data(
        rp_id=rp_id, counter=counter, include_credential=False
    )
    signed_message = auth_data + hashlib.sha256(data).digest()
    if not valid_signature:
        signed_message = b"not-the-assertion-message" + signed_message
    signature = authenticator.sign(signed_message)

    return {
        "id": b64u(authenticator.credential_id),
        "rawId": b64u(authenticator.credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64u(data),
            "authenticatorData": b64u(auth_data),
            "signature": b64u(signature),
        },
        "clientExtensionResults": {},
    }


def advanced_public_key_options(
    *,
    challenge: bytes,
    rp_id: str = RP_ID,
    username: str = "user@example.com",
) -> dict[str, Any]:
    return {
        "rp": {"id": rp_id, "name": "Demo server"},
        "user": {
            "id": b"user-handle".hex(),
            "name": username,
            "displayName": "A. User",
        },
        "challenge": {"$base64url": b64u(challenge)},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    }
