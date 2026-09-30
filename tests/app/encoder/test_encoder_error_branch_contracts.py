import pytest

from server.app.decoder.encode import ctap_encode as encode_ctap_encode
from server.app.decoder.encode import ctap_fields as encode_ctap_fields


def test_ctap_request_and_response_encoders_raise_for_missing_required_fields():
    with pytest.raises(ValueError, match="requires pubKeyCredParams"):
        encode_ctap_encode._encode_make_credential_request(
            {
                "clientDataHash": "00",
                "rp": {"id": "example.com"},
                "user": {"id": "00"},
            }
        )

    with pytest.raises(ValueError, match="non-empty string"):
        encode_ctap_encode._encode_get_assertion_request(
            {
                "rpId": "",
                "clientDataHash": "00",
            }
        )

    with pytest.raises(ValueError, match="non-empty string"):
        encode_ctap_encode._encode_make_credential_response(
            {
                "fmt": "",
                "authData": "00",
            }
        )

    with pytest.raises(ValueError, match="Unable to interpret authData"):
        encode_ctap_encode._encode_get_assertion_response(
            {
                "signature": "00",
            }
        )


def test_ctap_support_helpers_raise_expected_errors():
    with pytest.raises(ValueError, match="must be an array"):
        encode_ctap_fields._encode_allow_list("not-a-list")

    with pytest.raises(ValueError, match="must be a boolean"):
        encode_ctap_fields._ensure_bool(5, "flag")
