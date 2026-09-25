"""The readings the decoder tries on binary input, in order: the first that reads the bytes is taken.

Each reading returns the decoder's result for the bytes, or ``None`` when they
are not what it reads. The last, CBOR, always answers: with the item it read,
or by raising where the input stops being well-formed CBOR.

Two readings can both read one input whole (``ambiguous_input`` lists every
such pair). The decoder never picks silently: each reading that reads the
bytes whole, other than the one taken, is named in an ``ambiguous-input``
finding. "Whole" is strict whatever the request asked for: one well-formed CBOR
item and nothing after it, authenticator data exactly as long as its flags say,
JSON as RFC 8259 has it.

The readings reach the pipeline's helpers through the module, so a test that
patches one there patches it here too.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from cryptography import x509

from . import ambiguous_input, cbor_parser, ctap, ctap_prefix, json_input, pipeline
from .ambiguous_input import finding

Result = dict[str, Any]
Reading = Callable[[bytes, str, bool], "Result | None"]

# What each whole reading is called in a finding.
LONE_CTAP_BYTE = "a CTAP command or status byte"
PEM_TEXT = "PEM text"
JSON_TEXT = "JSON text"
DER_CERTIFICATE = "a DER certificate"
CBOR_ITEM = "one CBOR item"
CTAP_MESSAGE = "a CTAP command or status byte and one CBOR item"
AUTHENTICATOR_DATA = "authenticator data"


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
    json_obj, json_findings = pipeline._read_json(text, lenient=lenient, in_bytes=True)
    if json_obj is json_input.NOT_JSON:
        return None
    if isinstance(json_obj, Mapping) and pipeline._is_client_data_dict(json_obj):
        result = {
            "format": "WebAuthn client data (binary)",
            "inputEncoding": encoding,
            "decoded": pipeline._describe_client_data_from_bytes(data, lenient=lenient),
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


def _one_ctap_message(data: bytes, encoding: str, lenient: bool) -> Result | None:
    # Before authenticator data: about a quarter of all 37-byte CBOR items have a
    # byte 32 without the AT and ED flags, and a real 37-byte getInfo response is
    # one of them, while authenticator data that is also one item (its rpIdHash
    # starting with the head of an item exactly 37 bytes long) is a chance in
    # tens of thousands.
    if ambiguous_input.is_one_ctap_message(data):
        return ctap._try_decode_cbor(data, encoding, lenient=lenient)
    return None


def _authenticator_data(data: bytes, encoding: str, lenient: bool) -> Result | None:
    return pipeline._try_decode_authenticator_data(data, encoding)


def _cbor(data: bytes, encoding: str, lenient: bool) -> Result | None:
    # Whatever is left is read as CBOR, strictly: input that is not
    # well-formed CBOR fails here, with the offset where it goes wrong. Only a
    # request for lenient decoding reads past that, and it lists what it skipped.
    return ctap._try_decode_cbor(data, encoding, lenient=lenient)


BINARY_READINGS: tuple[tuple[str, Reading], ...] = (
    (LONE_CTAP_BYTE, _lone_ctap_byte),
    (PEM_TEXT, _utf8_pem),
    (JSON_TEXT, _utf8_json),
    (DER_CERTIFICATE, _der_certificate),
    ("an attestation object", _attestation_object),
    ("one CTAP message or CBOR item", _one_ctap_message),
    (AUTHENTICATOR_DATA, _authenticator_data),
    ("CBOR", _cbor),
)


def read_binary(data: bytes, encoding: str, *, lenient: bool = False) -> Result:
    """The result of the first reading in ``BINARY_READINGS`` that reads ``data``, the other readings named."""

    for name, reading in BINARY_READINGS:
        result = reading(data, encoding, lenient)
        if result is not None:
            taken = _whole_reading_taken(name, result)
            others = [finding(taken, other) for other in reads_whole(data) if other != taken]
            if others:
                ctap._attach_findings(result, [*(result.get("findings") or []), *others])
            return result
    raise AssertionError("CBOR, the last reading, answers or raises")  # pragma: no cover


def _whole_reading_taken(name: str, result: Result) -> str:
    """Which whole reading a result is: CBOR after a CTAP byte, or an attestation object as the CBOR it is."""

    if name in ("CBOR", "one CTAP message or CBOR item", "an attestation object"):
        framing = (result.get("decoded") or {}).get("ctap")
        sent_a_byte = isinstance(framing, Mapping) and framing.get("code") is not None
        return CTAP_MESSAGE if sent_a_byte and framing.get("payloadLength") else CBOR_ITEM
    return name


def reads_whole(data: bytes) -> list[str]:
    """Every reading that reads all of ``data`` and nothing more, in the decoder's order."""

    return [name for name, whole in _WHOLE if whole(data)]


def _is_lone_ctap_byte(data: bytes) -> bool:
    return len(data) == 1 and ctap_prefix._read_prefix(data)[0] is not None


def _text(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_pem_text(data: bytes) -> bool:
    text = _text(data)
    if not text or not pipeline._looks_like_pem(text):
        return False
    try:
        pipeline._decode_pem_certificates(text)
    except ValueError:
        return False
    return True


def _is_json_text(data: bytes) -> bool:
    text = _text(data)
    if text is None:
        return False
    try:
        return json_input.read_or_none(text)[0] is not json_input.NOT_JSON
    except json_input.JsonConstantError:
        return False


def _is_der_certificate(data: bytes) -> bool:
    try:
        x509.load_der_x509_certificate(data)
    except ValueError:
        return False
    return True


def _is_cbor_item(data: bytes) -> bool:
    try:
        _node, end, _skipped = cbor_parser.decode_item(data)
    except (cbor_parser._CborDecodingError, RecursionError):
        return False
    return end == len(data)


def _is_ctap_message(data: bytes) -> bool:
    prefix, payload = ctap_prefix._read_prefix(data)
    return prefix is not None and bool(payload) and _is_cbor_item(payload)


def _is_authenticator_data(data: bytes) -> bool:
    try:
        pipeline._describe_authenticator_data_bytes(data)
    except ValueError:
        return False
    return True


_WHOLE: tuple[tuple[str, Callable[[bytes], bool]], ...] = (
    (LONE_CTAP_BYTE, _is_lone_ctap_byte),
    (PEM_TEXT, _is_pem_text),
    (JSON_TEXT, _is_json_text),
    (DER_CERTIFICATE, _is_der_certificate),
    (CBOR_ITEM, _is_cbor_item),
    (CTAP_MESSAGE, _is_ctap_message),
    (AUTHENTICATOR_DATA, _is_authenticator_data),
)
