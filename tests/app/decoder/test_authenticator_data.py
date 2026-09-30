"""``decoder.decode.authenticator_data``: authenticator data as the decoder describes it."""
from __future__ import annotations

import hashlib

from fido2.webauthn import AuthenticatorData

from server.app.decoder.decode import authenticator_data as decode_authenticator_data


def test_extension_outputs_are_shown_with_what_they_name():
    auth_data = AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.ED,
        5,
        b"",
        {"credProtect": 2},
    )

    extensions = decode_authenticator_data._describe_authenticator_data_bytes(bytes(auth_data))["extensions"]

    assert extensions["raw"] == {"credProtect": 2}
    assert extensions["summary"]["credProtectLabel"] == "userVerificationOptionalWithCredentialIDList"
