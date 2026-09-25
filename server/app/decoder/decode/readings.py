"""The readings the decoder tries on binary input, in order: the first that reads the bytes is taken.

Each reading returns the decoder's result for the bytes, or ``None`` when they
are not what it reads. The last, CBOR, always answers: with the item it read,
or by raising where the input stops being well-formed CBOR.

The readings reach the pipeline's helpers through the module, so a test that
patches one there patches it here too.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from . import ctap, pipeline

Result = dict[str, Any]
Reading = Callable[[bytes, str, bool], "Result | None"]


def _lone_ctap_byte(data: bytes, encoding: str, lenient: bool) -> Result | None:
    # A single byte CTAP names is a status or command byte. Read as text it is
    # at most an ASCII digit, which would otherwise be shown as a JSON number:
    # 0x31 (PIN_INVALID) as 1.
    if len(data) == 1 and ctap._extract_ctap_prefix(data)[0] is not None:
        return ctap._try_decode_cbor(data, encoding, lenient=lenient)
    return None


def _utf8_pem(data: bytes, encoding: str, lenient: bool) -> Result | None:
    text = pipeline._try_decode_utf8(data)
    if not (text and pipeline._looks_like_pem(text)):
        return None
    result = pipeline._decode_pem_certificates(text)
    result["inputEncoding"] = encoding
    result["binary"] = pipeline._binary_summary(data, encoding)
    return result


def _utf8_json(data: bytes, encoding: str, lenient: bool) -> Result | None:
    text = pipeline._try_decode_utf8(data)
    if not text:
        return None
    json_obj, json_findings = pipeline._read_json(text)
    if json_obj is None:
        return None
    if isinstance(json_obj, Mapping) and pipeline._is_client_data_dict(json_obj):
        result = {
            "format": "WebAuthn client data (binary)",
            "inputEncoding": encoding,
            "decoded": pipeline._describe_client_data_from_bytes(data),
            "binary": pipeline._binary_summary(data, encoding),
        }
    else:
        result = {
            "format": "JSON (binary)",
            "inputEncoding": encoding,
            "decoded": json_obj,
            "binary": pipeline._binary_summary(data, encoding),
        }
    if json_findings:
        ctap._attach_findings(result, json_findings)
    return result


def _der_certificate(data: bytes, encoding: str, lenient: bool) -> Result | None:
    return pipeline._try_decode_certificate_bytes(data, encoding)


def _attestation_object(data: bytes, encoding: str, lenient: bool) -> Result | None:
    return pipeline._try_decode_attestation_object(data, encoding)


def _authenticator_data(data: bytes, encoding: str, lenient: bool) -> Result | None:
    return pipeline._try_decode_authenticator_data(data, encoding)


def _cbor(data: bytes, encoding: str, lenient: bool) -> Result | None:
    # Whatever is left is read as CBOR, strictly: input that is not
    # well-formed CBOR fails here, with the offset where it goes wrong. Only a
    # request for lenient decoding reads past that, and it lists what it skipped.
    return ctap._try_decode_cbor(data, encoding, lenient=lenient)


BINARY_READINGS: tuple[tuple[str, Reading], ...] = (
    ("a lone CTAP command or status byte", _lone_ctap_byte),
    ("PEM text", _utf8_pem),
    ("JSON text", _utf8_json),
    ("a DER certificate", _der_certificate),
    ("an attestation object", _attestation_object),
    ("authenticator data", _authenticator_data),
    ("CBOR", _cbor),
)


def read_binary(data: bytes, encoding: str, *, lenient: bool = False) -> Result:
    """The result of the first reading in ``BINARY_READINGS`` that reads ``data``."""

    for _name, reading in BINARY_READINGS:
        result = reading(data, encoding, lenient)
        if result is not None:
            return result
    raise AssertionError("CBOR, the last reading, answers or raises")  # pragma: no cover
