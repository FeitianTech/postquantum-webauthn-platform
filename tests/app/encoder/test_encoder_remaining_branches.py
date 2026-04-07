import base64

import pytest


def test_normalize_ctap_extra_value_and_nested_key_sanitization_branches():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    value = {
        " 1 (alpha) ": {"2 (beta)": {"bytes": [1, 2]}},
        "": "blank-key",
        9: "numeric-key",
        "items": [{"3 (gamma)": "x"}],
    }

    normalized = encode_module._normalize_ctap_extra_value(value)

    assert "alpha" in normalized
    assert normalized["alpha"]["beta"] == b"\x01\x02"
    assert "" in normalized
    assert "9" in normalized
    assert normalized["items"][0]["gamma"] == "x"


def test_extract_generic_binary_payload_cycle_and_pem_label_fallbacks():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    cyclic = {}
    cyclic["self"] = cyclic
    cyclic["nested"] = {"payload": [{"base64": base64.b64encode(b"abc").decode("ascii")}]} 

    extracted = encode_module._extract_generic_binary_payload(cyclic)
    assert extracted == b"abc"

    assert encode_module._determine_pem_label({"binary": {"encoding": "cert"}}) == "cert"
    assert encode_module._determine_pem_label({"other": True}) == "DATA"


def test_extract_binary_input_candidate_priority_string_and_sequence_paths():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert (
        encode_module._extract_binary_input({"hex": "aabb"}, "field")
        == b"\xaa\xbb"
    )
    assert (
        encode_module._extract_binary_input(
            {"base64": base64.b64encode(b"xyz").decode("ascii")},
            "field",
        )
        == b"xyz"
    )
    assert encode_module._extract_binary_input("aabb", "field") == b"\xaa\xbb"
    assert encode_module._extract_binary_input([7, 8, 9], "field") == b"\x07\x08\x09"

    with pytest.raises(ValueError, match="Unable to interpret field"):
        encode_module._extract_binary_input({"value": {"bad": True}}, "field")


def test_encode_ctap_from_decoded_and_structure_none_paths():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._encode_ctap_from_structure("not-mapping") == (None, None)

    decoded = {
        "makeCredentialRequest": "not-a-map",
        "getAssertionRequest": "still-not-a-map",
    }
    assert encode_module._encode_ctap_from_decoded(decoded) == (None, None)
