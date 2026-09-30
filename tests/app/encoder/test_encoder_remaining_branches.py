import base64

import pytest

from server.app.decoder.encode import binary_extract as encode_binary_extract
from server.app.decoder.encode import ctap_numeric as encode_ctap_numeric


def test_normalize_ctap_extra_value_and_nested_key_sanitization_branches():
    value = {
        " 1 (alpha) ": {"2 (beta)": {"bytes": [1, 2]}},
        "": "blank-key",
        9: "numeric-key",
        "items": [{"3 (gamma)": "x"}],
    }

    normalized = encode_ctap_numeric._normalize_ctap_extra_value(value)

    assert "alpha" in normalized
    assert normalized["alpha"]["beta"] == b"\x01\x02"
    assert "" in normalized
    assert "9" in normalized
    assert normalized["items"][0]["gamma"] == "x"


def test_extract_generic_binary_payload_cycle_and_pem_label_fallbacks():
    cyclic = {}
    cyclic["self"] = cyclic
    cyclic["nested"] = {"payload": [{"base64": base64.b64encode(b"abc").decode("ascii")}]} 

    extracted = encode_binary_extract._extract_generic_binary_payload(cyclic)
    assert extracted == b"abc"

    assert encode_binary_extract._determine_pem_label({"binary": {"encoding": "cert"}}) == "cert"
    assert encode_binary_extract._determine_pem_label({"other": True}) == "DATA"


def test_a_ctap_view_names_one_message_the_encoder_builds():
    from server.app.decoder.encode import ctap_views

    with pytest.raises(ValueError, match="ctapDecoded names no CTAP message"):
        ctap_views.one_message({})
    with pytest.raises(ValueError, match="ctapDecoded.makeCredentialRequest must be an object"):
        ctap_views.one_message({"makeCredentialRequest": "not-a-map"})
    with pytest.raises(ValueError, match="ctapDecoded holds 2 messages"):
        ctap_views.one_message({"makeCredentialRequest": "not-a-map", "getAssertionRequest": "still-not-a-map"})
