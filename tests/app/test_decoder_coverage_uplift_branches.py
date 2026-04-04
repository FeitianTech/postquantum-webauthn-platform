from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest
from fido2.utils import ByteBuffer


def test_get_mapping_entry_accepts_bytebuffer_key_variants():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._get_mapping_entry({1: "int"}, ByteBuffer(b"\x01")) == "int"
    assert decode_module._get_mapping_entry({"1": "str"}, ByteBuffer(b"\x01")) == "str"


def test_decode_public_key_credential_marks_authentication_without_attestation(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    auth_bytes = b"\x00" * 37
    monkeypatch.setattr(
        decode_module,
        "_describe_authenticator_data_bytes",
        lambda _value: {"parsed": True},
        raising=False,
    )

    credential = {
        "id": "cred-id",
        "type": "public-key",
        "response": {
            "authenticatorData": base64.b64encode(auth_bytes).decode("ascii"),
        },
    }

    result = decode_module._decode_public_key_credential(credential)
    assert result["format"] == "PublicKeyCredential (authentication)"
    assert result["decoded"]["response"]["authenticatorData"]["details"] == {"parsed": True}


def test_parse_cbor_item_covers_simple_and_single_double_precision_float_paths():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    simple_node, _ = decode_module._parse_cbor_item(b"\xf8\x2a", 0)
    single_node, _ = decode_module._parse_cbor_item(b"\xfa\x3f\x80\x00\x00", 0)
    double_node, _ = decode_module._parse_cbor_item(
        b"\xfb\x3f\xf0\x00\x00\x00\x00\x00\x00", 0
    )

    assert simple_node["type"] == "simple"
    assert simple_node["value"] == 42
    assert single_node["precision"] == "single"
    assert single_node["value"] == 1.0
    assert double_node["precision"] == "double"
    assert double_node["value"] == 1.0


def test_decode_cbor_sequence_uses_structure_to_value_when_fallback_structure_parse_succeeds(
    monkeypatch,
):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        decode_module.cbor,
        "decode_from",
        lambda _payload: (_ for _ in ()).throw(ValueError("boom")),
        raising=False,
    )

    class _BrokenDecoder:
        def __init__(self, *_args, **_kwargs):
            pass

        def decode(self):
            raise ValueError("boom")

    monkeypatch.setattr(decode_module.cbor2, "CBORDecoder", _BrokenDecoder, raising=False)
    monkeypatch.setattr(
        decode_module,
        "_decode_cbor_structure",
        lambda _payload: (
            {
                "majorType": 0,
                "type": "unsigned",
                "value": 7,
                "summary": "7",
                "byteLength": 1,
            },
            1,
        ),
        raising=False,
    )

    structures, values, consumed, remaining = decode_module._decode_cbor_sequence(b"\x01")
    assert structures and structures[0]["majorType"] == 0
    assert values == [7]
    assert consumed == 1
    assert remaining == b""


def test_merge_ctap_make_credential_consumes_raw_signature_bytes_in_extra_values():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    structure = {
        "entries": [
            {
                "keySummary": "3",
                "key": {"majorType": 0, "value": 3},
                "value": {"summary": "placeholder"},
            }
        ],
        "length": 1,
        "summary": "map[1]",
    }
    value = {"al&": "sig"}

    merged_structure, merged_value, extra_structures, extra_values, signature = (
        decode_module._merge_ctap_make_credential(
            structure,
            value,
            [{"summary": "attStmt"}],
            [memoryview(b"\xaa\xbb\xcc")],
        )
    )

    assert signature == b"\xaa\xbb\xcc"
    assert merged_value[3]["sig"] == b"\xaa\xbb\xcc"
    assert merged_value[3]["alg"] == -7
    assert extra_structures == []
    assert extra_values == []
    assert merged_structure["entries"][-1]["keySummary"] == "3"


def test_repair_get_assertion_entries_recovers_signature_from_lenient_map_entries(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        decode_module,
        "_extract_get_assertion_trailing_from_raw",
        lambda _raw: (None, {}),
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_split_get_assertion_trailing_fields",
        lambda signature: (signature, {}),
        raising=False,
    )

    base_structure = {"entries": [], "length": 0, "summary": "map[0]"}

    monkeypatch.setattr(
        decode_module,
        "_extract_lenient_map_entries",
        lambda _raw: [(3, bytearray(b"\x01\x02"))],
        raising=False,
    )
    _, repaired_value_int_key, repaired_sig_int_key = decode_module._repair_get_assertion_entries(
        dict(base_structure),
        {},
        raw_bytes=b"\xa1",
    )
    assert repaired_sig_int_key == b"\x01\x02"
    assert repaired_value_int_key[3] == b"\x01\x02"

    monkeypatch.setattr(
        decode_module,
        "_extract_lenient_map_entries",
        lambda _raw: [(3, "not-bytes"), (b"\x99", 1)],
        raising=False,
    )
    _, repaired_value_bytes_key, repaired_sig_bytes_key = decode_module._repair_get_assertion_entries(
        dict(base_structure),
        {},
        raw_bytes=b"\xa1",
    )
    assert repaired_sig_bytes_key == b"\x99"
    assert repaired_value_bytes_key[3] == b"\x99"


def test_try_decode_cbor_merges_assertion_signature_for_direct_get_assertion_classification(
    monkeypatch,
):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    structure = {"byteLength": 1, "entries": [], "length": 0, "summary": "map[0]"}
    monkeypatch.setattr(
        decode_module,
        "_decode_cbor_sequence",
        lambda _payload: ([structure], [{2: b"auth"}], 1, b""),
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_classify_ctap_map",
        lambda _value: "get_assertion_output",
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_repair_get_assertion_entries",
        lambda structure, value, raw_bytes=None: (structure, {2: b"auth", 3: b"\xbb"}, b"\xbb"),
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_build_get_assertion_expanded_json",
        lambda _value, _raw: {"path": "direct"},
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_interpret_ctap_cbor_value",
        lambda _value: None,
        raising=False,
    )

    result = decode_module._try_decode_cbor(b"\x00\xa0", "hex")
    assert result is not None
    assert result["decoded"]["ctap"]["signatureLength"] == 1
    assert result["decoded"]["expandedJson"]["path"] == "direct"


def test_try_decode_cbor_promotes_other_classification_when_repair_finds_signature(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    structure = {"byteLength": 1, "entries": [], "length": 0, "summary": "map[0]"}
    monkeypatch.setattr(
        decode_module,
        "_decode_cbor_sequence",
        lambda _payload: ([structure], [{2: b"auth"}], 1, b""),
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_classify_ctap_map",
        lambda _value: "other",
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_repair_get_assertion_entries",
        lambda structure, value, raw_bytes=None: (structure, {2: b"auth", 3: b"\xaa"}, b"\xaa"),
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_build_get_assertion_expanded_json",
        lambda _value, _raw: {"path": "promoted"},
        raising=False,
    )
    monkeypatch.setattr(
        decode_module,
        "_interpret_ctap_cbor_value",
        lambda _value: None,
        raising=False,
    )

    result = decode_module._try_decode_cbor(b"\xa0", "hex")
    assert result is not None
    assert result["decoded"]["expandedJson"]["path"] == "promoted"


def test_att_stmt_extension_header_and_authenticator_data_fallback_helpers():
    decode_module = pytest.importorskip("server.app.decoder.decode")

    assert decode_module._format_att_stmt_for_expanded_json(b"\xaa")["sig"] == "aa"
    assert decode_module._format_att_stmt_for_expanded_json(7)["value"] == 7

    assert (
        decode_module._format_certificate_extension_header(
            {
                "includeOidInHeader": False,
                "oid": "1.2.3",
                "friendlyName": "1.2.3",
            }
        )
        == "1.2.3"
    )
    assert (
        decode_module._format_certificate_extension_header(
            {
                "includeOidInHeader": False,
                "friendlyName": "Friendly name only",
            }
        )
        == "Friendly name only"
    )

    assert decode_module._build_authenticator_data_lines(
        None,
        {"rpIdHash": {"hex": "aabb"}},
    ) == ["aabb"]


def test_build_subject_key_identifier_lines_derives_digest_when_ski_extension_missing(monkeypatch):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    class _Extensions:
        def get_extension_for_oid(self, _oid):
            raise decode_module.x509.ExtensionNotFound(
                "missing",
                decode_module.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            )

    class _Certificate:
        extensions = _Extensions()

        def public_key(self):
            return object()

    monkeypatch.setattr(
        decode_module.x509,
        "load_der_x509_certificate",
        lambda _der: _Certificate(),
        raising=False,
    )
    monkeypatch.setattr(
        decode_module.x509.SubjectKeyIdentifier,
        "from_public_key",
        lambda _public_key: SimpleNamespace(digest=b"\x01\x23"),
        raising=False,
    )

    result = decode_module._build_subject_key_identifier_lines(
        {"derBase64": base64.b64encode(b"\x30\x01").decode("ascii")}
    )
    assert result == decode_module.format_hex_bytes_lines(b"\x01\x23")


def test_extract_authenticator_bytes_from_attestation_uses_raw_base64_and_handles_decode_failure(
    monkeypatch,
):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    monkeypatch.setattr(
        decode_module,
        "_extract_bytes_from_binary",
        lambda _entry: None,
        raising=False,
    )

    class _FakeAttestation:
        def __init__(self, _raw):
            self.auth_data = b"\x11\x22"

    monkeypatch.setattr(decode_module, "AttestationObject", _FakeAttestation, raising=False)
    extracted = decode_module._extract_authenticator_bytes_from_attestation(
        {"raw": " AQI= "}
    )
    assert extracted == b"\x11\x22"

    monkeypatch.setattr(
        decode_module.base64,
        "b64decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("invalid")),
        raising=False,
    )
    assert (
        decode_module._extract_authenticator_bytes_from_attestation({"raw": "AQI="})
        is None
    )


def test_extract_attestation_certificate_handles_non_string_chain_entries_and_serializer_errors(
    monkeypatch,
):
    decode_module = pytest.importorskip("server.app.decoder.decode")

    class _BytesEntry:
        def __bytes__(self):
            return b"\x01\x02"

    monkeypatch.setattr(
        decode_module,
        "serialize_attestation_certificate",
        lambda _cert: (_ for _ in ()).throw(RuntimeError("boom")),
        raising=False,
    )
    assert decode_module._extract_attestation_certificate({"x5c": [_BytesEntry()]}) is None

    class _BadBytesEntry:
        def __bytes__(self):
            raise TypeError("bad-bytes")

    assert decode_module._extract_attestation_certificate({"x5c": [_BadBytesEntry()]}) is None
