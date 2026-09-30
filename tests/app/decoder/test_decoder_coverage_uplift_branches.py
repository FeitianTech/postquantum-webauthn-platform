from __future__ import annotations

import base64

from server.app.decoder.decode import authenticator_data as decode_authenticator_data
from server.app.decoder.decode import credential_json


def test_decode_public_key_credential_marks_authentication_without_attestation(monkeypatch):
    auth_bytes = b"\x00" * 37
    monkeypatch.setattr(
        decode_authenticator_data,
        "_describe_authenticator_data_bytes",
        lambda _value: {"parsed": True},
    )

    credential = {
        "id": "cred-id",
        "type": "public-key",
        "response": {
            "authenticatorData": base64.b64encode(auth_bytes).decode("ascii"),
        },
    }

    result = credential_json.decode_public_key_credential(credential)
    assert result["format"] == "PublicKeyCredential (authentication)"
    assert result["decoded"]["response"]["authenticatorData"]["details"] == {"parsed": True}
