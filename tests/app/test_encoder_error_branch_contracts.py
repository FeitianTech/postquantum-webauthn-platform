import pytest


def test_encoder_high_level_handlers_validate_input_types():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="expects a JSON object"):
        encode_module._encode_public_key_credential([])

    with pytest.raises(ValueError, match="must be provided as a JSON object"):
        encode_module._encode_client_data([])

    with pytest.raises(ValueError, match="Unable to interpret authenticatorData"):
        encode_module._encode_authenticator_data({"authenticatorData": {"bad": True}})

    with pytest.raises(ValueError, match="Unable to interpret attestationObject"):
        encode_module._encode_attestation_object({"attestationObject": {"bad": True}})

    with pytest.raises(ValueError, match="Unable to interpret certificate"):
        encode_module._encode_x509_certificate({"certificate": {"bad": True}})


def test_ctap_request_and_response_encoders_raise_for_missing_required_fields():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="requires pubKeyCredParams"):
        encode_module._encode_make_credential_request(
            {
                "clientDataHash": "00",
                "rp": {"id": "example.com"},
                "user": {"id": "00"},
            }
        )

    with pytest.raises(ValueError, match="non-empty string"):
        encode_module._encode_get_assertion_request(
            {
                "rpId": "",
                "clientDataHash": "00",
            }
        )

    with pytest.raises(ValueError, match="non-empty string"):
        encode_module._encode_make_credential_response(
            {
                "fmt": "",
                "authData": "00",
            }
        )

    with pytest.raises(ValueError, match="Unable to interpret authData"):
        encode_module._encode_get_assertion_response(
            {
                "signature": "00",
            }
        )


def test_ctap_support_helpers_raise_expected_errors():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="must be an array"):
        encode_module._encode_allow_list("not-a-list")

    with pytest.raises(ValueError, match="must be a boolean"):
        encode_module._ensure_bool(5, "flag")

    assert encode_module._determine_ctap_prefix({"code": 0x01, "kind": "command"}, None) == (1, "command")
    assert encode_module._determine_ctap_prefix({}, "unknown") == (None, None)


def test_canonical_integer_and_length_helpers_reject_invalid_values():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="non-negative"):
        encode_module._encode_major_type_with_length(2, -1)

    with pytest.raises(ValueError, match="non-negative"):
        encode_module._encode_unsigned_integer(2, -1)

    with pytest.raises(ValueError, match="64 bits"):
        encode_module._encode_unsigned_integer(2, 1 << 80)


def test_cbor_simple_value_encoder_type_and_range_guards():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    encoder = encode_module._CanonicalCBOREncoder()

    class _BadSimple:
        def __init__(self, value):
            self.value = value

    with pytest.raises(TypeError, match="must be an integer"):
        encoder._encode_cbor_simple_value(_BadSimple("x"))

    with pytest.raises(ValueError, match="between 0 and 255"):
        encoder._encode_cbor_simple_value(_BadSimple(999))

    with pytest.raises(ValueError, match="reserved"):
        encoder._encode_cbor_simple_value(_BadSimple(25))


def test_extract_generic_binary_payload_recursive_failure_path():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    payload = {
        "first": {"nested": {"still": "text"}},
        "second": [{"none": None}, {"more": "text"}],
    }

    with pytest.raises(ValueError, match="Unable to extract binary payload"):
        encode_module._extract_generic_binary_payload(payload)
