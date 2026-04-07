from __future__ import annotations

from collections.abc import Mapping

import cbor2
import pytest


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_encode_cbor_value_uses_root_mapping_as_ctap_source():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    payload = {
        "fmt": "none",
        "authData": b"\x00" * 37,
    }

    encoded = encode_module._encode_cbor_value(payload)

    assert encoded["success"] is True
    assert "ctapDecoded" in encoded["data"]
    assert "makeCredentialResponse" in encoded["data"]["ctapDecoded"]


def test_extract_ctap_numeric_payload_salvage_classification_errors_are_preserved():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="Missing field 0x02"):
        encode_module._extract_ctap_numeric_payload(
            {
                "01": "fmt-only",
                "nonNumericKey": True,
            }
        )


def test_extract_ctap_numeric_payload_skips_visited_mappings_in_recursive_inputs():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    loop: dict[str, object] = {}
    loop["self"] = loop

    numeric_map, ctap_type = encode_module._extract_ctap_numeric_payload(
        [
            loop,
            {
                "1": "example.com",
                "2": _b64url(b"\x11" * 32),
            },
        ]
    )

    assert ctap_type == "getAssertionRequest"
    assert numeric_map[1] == "example.com"


def test_sanitize_numeric_mapping_and_pem_label_defaults():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="at least one CTAP field"):
        encode_module._sanitize_ctap_numeric_mapping({})

    assert encode_module._normalize_pem_label(" !!! ") == "DATA"


class _DuplicateEncodedKeyMap(Mapping):
    def __getitem__(self, key):
        if key == b"a":
            return 1
        if key == memoryview(b"a"):
            return 2
        raise KeyError(key)

    def __iter__(self):
        yield b"a"
        yield memoryview(b"a")

    def __len__(self):
        return 2

    def items(self):
        return [(b"a", 1), (memoryview(b"a"), 2)]


def test_canonical_encoder_exercises_tag_float_simple_and_duplicate_key_guard():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    encoder = encode_module._CanonicalCBOREncoder()

    tagged = cbor2.CBORTag(42, [1, 2])
    canonical = encoder.canonicalize_structure(tagged)
    assert isinstance(canonical, cbor2.CBORTag)
    assert canonical.value == [1, 2]

    float_encoded = encoder._encode_simple(1.5)
    assert float_encoded[:1] in {b"\xf9", b"\xfa", b"\xfb"}

    simple_encoded = encoder._encode_simple(cbor2.CBORSimpleValue(16))
    assert simple_encoded == bytes([0xE0 | 16])

    with pytest.raises(ValueError, match="Duplicate CBOR map key"):
        encoder._sorted_map_items(_DuplicateEncodedKeyMap())


def test_primitive_coercion_and_attestation_statement_residual_paths():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    assert encode_module._ensure_int(7, "field") == 7
    with pytest.raises(ValueError, match="integer value"):
        encode_module._ensure_int("not-an-int", "field")

    assert encode_module._ensure_bool(True, "flag") is True

    assert encode_module._encode_attestation_statement(None) is None
    assert encode_module._encode_attestation_statement(b"\xAA") == b"\xAA"
    assert encode_module._encode_credential_descriptor(b"\xBB") == b"\xBB"


def test_require_certificate_bytes_handles_empty_pem_decoding_and_non_mapping_failure():
    encode_module = pytest.importorskip("server.app.decoder.encode")

    with pytest.raises(ValueError, match="Unable to decode certificate PEM contents"):
        encode_module._require_certificate_bytes({"pem": "===="}, 0)

    with pytest.raises(ValueError, match=r"x5c\[1\]"):
        encode_module._require_certificate_bytes({"pem": 123}, 1)
