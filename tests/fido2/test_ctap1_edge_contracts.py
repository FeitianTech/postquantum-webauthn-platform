from fido2.ctap1 import RegistrationData


def test_registration_data_parses_single_byte_certificate_length_branch():
    public_key = b"P" * 65
    key_handle = b"K"
    certificate = b"\x30\x01\xff"  # tag=0x30, single-byte length=1, payload=0xff
    signature = b"\xaa\xbb"

    payload = b"\x05" + public_key + b"\x01" + key_handle + certificate + signature
    parsed = RegistrationData(payload)

    assert parsed.public_key == public_key
    assert parsed.key_handle == key_handle
    assert parsed.certificate == certificate
    assert parsed.signature == signature