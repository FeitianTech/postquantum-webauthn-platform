"""``decoder.encode.binary_extract``: the bytes format PEM or DER encodes, found in the JSON, and the PEM label."""

from __future__ import annotations

import base64
import json

import pytest

from server.app.decoder.encode import binary_extract as encode_binary_extract
from server.app.decoder.encode import text as encode_text


def _pem(value):
    return encode_text.encode_payload_text(json.dumps(value), "PEM")["data"]["pem"]


def test_the_bytes_are_found_wherever_the_json_holds_them():
    value = {"first": {"nested": {"still": "text"}}, "nested": {"payload": [{"base64": base64.b64encode(b"abc").decode("ascii")}]}}

    assert _pem(value) == "-----BEGIN DATA-----\nYWJj\n-----END DATA-----"


@pytest.mark.parametrize("fmt", ["PEM", "DER"])
def test_json_that_holds_no_bytes_is_refused(fmt):
    value = {"first": {"nested": {"still": "text"}}, "second": [{"none": None}, {"more": "text"}]}

    with pytest.raises(ValueError, match="Unable to extract binary payload for encoding"):
        encode_text.encode_payload_text(json.dumps(value), fmt)


@pytest.mark.parametrize(
    ("labels", "label"),
    [
        ({"pemLabel": "certificate request"}, "CERTIFICATE_REQUEST"),
        ({"binary": {"encoding": "cert"}}, "CERT"),
        ({"label": " !!! "}, "DATA"),
        ({}, "DATA"),
    ],
)
def test_the_pem_label_is_the_one_the_json_names_in_upper_case(labels, label):
    assert _pem({"data": "616263", **labels}).startswith(f"-----BEGIN {label}-----\n")


def test_an_object_met_again_is_not_searched_twice():
    # JSON holds no cycle; a direct call gives the search one.
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    cyclic["nested"] = {"payload": [{"base64": base64.b64encode(b"abc").decode("ascii")}]}

    assert encode_binary_extract._extract_generic_binary_payload(cyclic) == b"abc"


def test_nested_binary_payload_is_extracted_and_missing_bytes_are_refused():
    payload = {'meta': {'ignored': True}, 'container': {'payload': [{'other': 'x'}, {'binary': {'hex': 'aabbcc'}}]}}
    extracted = encode_binary_extract._extract_generic_binary_payload(payload)
    assert extracted == b'\xaa\xbb\xcc'
    with pytest.raises(ValueError, match='Unable to extract binary payload'):
        encode_binary_extract._extract_generic_binary_payload({'value': None})
