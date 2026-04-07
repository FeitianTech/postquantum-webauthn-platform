from __future__ import annotations

import hashlib
from types import MappingProxyType
from typing import Any, Mapping, Optional

import pytest

from fido2.cose import CoseKey
from fido2.features import webauthn_json_mapping
from fido2.utils import websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    AttestedCredentialData,
    AuthenticationExtensionsClientOutputs,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorData,
    CollectedClientData,
)


def _credential_data() -> AttestedCredentialData:
    cose_key = CoseKey.parse(
        {1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32}
    )
    return AttestedCredentialData.create(b"\x00" * 16, b"cred-id", cose_key)


def _auth_data(flags: AuthenticatorData.FLAG) -> AuthenticatorData:
    credential_data = _credential_data() if flags & AuthenticatorData.FLAG.AT else b""
    extensions = {"credProps": {"rk": True}} if flags & AuthenticatorData.FLAG.ED else None
    return AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        flags,
        7,
        credential_data,
        extensions,
    )


def test_binary_type_string_representations_and_flag_helpers():
    aaguid = Aaguid(b"\x11" * 16)
    assert repr(aaguid).startswith("AAGUID(")

    credential_data = _credential_data()
    assert str(credential_data) == repr(credential_data)

    with pytest.raises(ValueError, match="Wrong length"):
        AttestedCredentialData(bytes(credential_data) + b"\x00")

    auth_data = _auth_data(
        AuthenticatorData.FLAG.UP
        | AuthenticatorData.FLAG.UV
        | AuthenticatorData.FLAG.BE
        | AuthenticatorData.FLAG.BS
        | AuthenticatorData.FLAG.AT
        | AuthenticatorData.FLAG.ED
    )

    assert str(auth_data) == repr(auth_data)
    assert auth_data.is_user_verified() is True
    assert auth_data.is_backup_eligible() is True
    assert auth_data.is_backed_up() is True
    assert auth_data.is_attested() is True
    assert auth_data.has_extension_data() is True

    attestation_object = AttestationObject.create("none", auth_data, {})
    assert str(attestation_object) == repr(attestation_object)


def test_collected_client_data_hashing_and_string_representation():
    client_data = CollectedClientData.create(
        CollectedClientData.TYPE.CREATE.value,
        b"challenge-bytes",
        "https://example.com",
    )

    assert str(client_data) == repr(client_data)
    assert client_data.get_hash("SHA-512") == hashlib.sha512(bytes(client_data)).digest()


def test_attestation_and_assertion_response_from_dict_clientdata_alias_paths(monkeypatch):
    monkeypatch.setattr(webauthn_json_mapping, "_enabled", False, raising=False)

    client_data = CollectedClientData.create(
        CollectedClientData.TYPE.CREATE.value,
        b"challenge",
        "https://example.com",
    )
    auth_data = _auth_data(AuthenticatorData.FLAG.UP)
    attestation_object = AttestationObject.create("none", auth_data, {})

    extension_results = MappingProxyType({"credProps": {"rk": True}})
    attestation_response = AuthenticatorAttestationResponse.from_dict(
        {
            "clientData": websafe_encode(bytes(client_data)),
            "attestationObject": websafe_encode(bytes(attestation_object)),
            "extensionResults": extension_results,
        }
    )

    assert attestation_response["clientData"] == attestation_response.client_data
    assert attestation_response["extensionResults"] == {"credProps": {"rk": True}}
    assert (
        AuthenticatorAttestationResponse._parse_value(
            Optional[Mapping[str, Any]], extension_results
        )
        is extension_results
    )

    assertion_extensions = MappingProxyType({"largeBlob": {"supported": True}})
    assertion_response = AuthenticatorAssertionResponse.from_dict(
        {
            "clientData": websafe_encode(bytes(client_data)),
            "authenticatorData": websafe_encode(bytes(auth_data)),
            "signature": websafe_encode(b"sig"),
            "extensionResults": assertion_extensions,
        }
    )

    assert assertion_response["clientData"] == assertion_response.client_data
    assert assertion_response["extensionResults"] == {
        "largeBlob": {"supported": True}
    }
    assert (
        AuthenticatorAssertionResponse._parse_value(
            Optional[Mapping[str, Any]], assertion_extensions
        )
        is assertion_extensions
    )


def test_authentication_extensions_client_outputs_mapping_contract():
    wrapped_mapping = MappingProxyType({"enabled": True})
    outputs = AuthenticationExtensionsClientOutputs(
        {
            "credBlob": b"\x01\x02",
            "wrapped": wrapped_mapping,
            "largeBlob": {"supported": True},
            "ignored": None,
        }
    )

    assert list(outputs) == ["credBlob", "wrapped", "largeBlob"]
    assert len(outputs) == 3
    assert outputs["credBlob"] == websafe_encode(b"\x01\x02")
    assert outputs["wrapped"] == {"enabled": True}
    assert outputs.large_blob == {"supported": True}
    assert repr(outputs) == repr(dict(outputs))