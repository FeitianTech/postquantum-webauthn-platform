import base64

import pytest

from server.app.decoder.encode import binary_extract as encode_binary_extract


def test_extract_generic_binary_payload_cycle_and_pem_label_fallbacks():
    cyclic = {}
    cyclic["self"] = cyclic
    cyclic["nested"] = {"payload": [{"base64": base64.b64encode(b"abc").decode("ascii")}]} 

    extracted = encode_binary_extract._extract_generic_binary_payload(cyclic)
    assert extracted == b"abc"

    assert encode_binary_extract._determine_pem_label({"binary": {"encoding": "cert"}}) == "cert"
    assert encode_binary_extract._determine_pem_label({"other": True}) == "DATA"


def test_a_ctap_view_names_one_message_the_encoder_builds():
    from server.app.decoder.encode import ctap_view_reader

    with pytest.raises(ValueError, match="ctapDecoded names no CTAP message"):
        ctap_view_reader.one_message({})
    with pytest.raises(ValueError, match="ctapDecoded.makeCredentialRequest must be an object"):
        ctap_view_reader.one_message({"makeCredentialRequest": "not-a-map"})
    with pytest.raises(ValueError, match="ctapDecoded holds 2 messages"):
        ctap_view_reader.one_message({"makeCredentialRequest": "not-a-map", "getAssertionRequest": "still-not-a-map"})
