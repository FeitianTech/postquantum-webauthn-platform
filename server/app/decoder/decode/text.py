"""The decoder's entry, ``decode_payload_text``: text in, the answer out.

Text is read as JSON (``credential_json``), as PEM (``pem``), or as bytes
(``binary_text``) that ``readings`` reads in order; ``answer`` builds the answer.
"""
from __future__ import annotations

from typing import Any

from ...encoding import try_decode_base64, try_decode_base64url
from . import (
    ambiguous_input,
    answer,
    binary_text,
    credential_json,
    ctap,
    json_input,
    pem,
    readings,
)


def _decode_binary_payload(data: bytes, encoding: str, *, lenient: bool = False) -> dict[str, Any]:
    # The readings, in order, are decode/readings.py's.
    return readings.read_binary(data, encoding, lenient=lenient)


class _ReadAsBase64Error(ValueError):
    """Odd-length hexadecimal digits read as base64, whose bytes then did not decode."""

    def __init__(self, exc: ValueError, digits: int) -> None:
        for field in ("offset", "path"):
            if hasattr(exc, field):
                setattr(self, field, getattr(exc, field))
        super().__init__(f"{exc} (the input was read as base64: as hexadecimal, its {digits} digits are an odd number)")


def decode_payload_text(value: str, *, lenient: bool = False) -> dict[str, Any]:
    """Decode ``value`` into a structured representation.

    CBOR is parsed strictly. ``lenient`` asks for a best-effort parse of CBOR
    that is not well-formed; the response then says so (``decodeMode``) and
    lists each item it kept partially or stepped over. JSON is RFC 8259's: text
    holding NaN or Infinity is refused with its offset, unless ``lenient`` (see
    ``json_input``).

    Text that is both hexadecimal and a JSON number is read by the precedence
    in ``ambiguous_input``, and the response names the reading not taken.
    """

    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Decoder input is empty.")

    # Offsets count from the input as sent, blank space before it included.
    parsed_json, json_findings = json_input.read_or_none(trimmed, lenient=lenient, base=len(value) - len(value.lstrip()))
    ambiguity = ambiguous_input.check(trimmed, parsed_json)
    if ambiguity is not None and ambiguity["readAs"] == "hex":
        parsed_json, json_findings = json_input.NOT_JSON, []
    if parsed_json is not json_input.NOT_JSON:
        result, taken = credential_json.decode_json_object(parsed_json, raw_text=trimmed, lenient=lenient), "json"
    elif pem.looks_like_pem(trimmed):
        result, taken = pem.decode_pem_certificates(trimmed), "pem"
    else:
        data, encoding = binary_text.decode_binary_input(trimmed)
        taken = "hex" if encoding == "hex" else "base64"
        try:
            result = _decode_binary_payload(data, encoding, lenient=lenient)
        except ValueError as exc:
            digits = binary_text.odd_hex_digits(trimmed) if encoding != "hex" else 0
            if not digits:
                raise
            raise _ReadAsBase64Error(exc, digits) from exc

    noted = ([ambiguity] if ambiguity is not None else []) + _other_text_readings(trimmed, taken) + json_findings
    if noted:
        ctap._attach_findings(result, [*noted, *(result.get("findings") or [])])
    # JSON is read leniently too, not only CBOR: the answer says how it was read.
    result.setdefault("decodeMode", "lenient" if lenient else "strict")
    return answer._prepare_decoder_response(result)


def _other_text_readings(text: str, taken: str) -> list[dict[str, Any]]:
    """The later text readings that read ``text`` whole: PEM inside JSON, and base64 some reading reads whole.

    The text's order is JSON, PEM, hexadecimal, base64; JSON digits that are also
    hexadecimal have ``ambiguous_input.check``'s finding.
    """

    found: list[dict[str, Any]] = []
    if taken == "json" and pem.looks_like_pem(text):
        try:
            pem.decode_pem_certificates(text)
        except ValueError:
            pass
        else:
            found.append(ambiguous_input.finding("json", "pem"))
    if taken != "base64":
        data = try_decode_base64url(text) or try_decode_base64(text)
        whole = readings.reads_whole(data) if data else []
        if whole:
            found.append(ambiguous_input.finding(taken, "base64", f" ({len(data)} bytes, read whole as {whole[0]})"))
    return found
