"""The decoder's entry, ``decode_payload_text``: text in, the answer out.

Text is read as JSON (``credential_json``), as PEM (``pem``), or as bytes
(``binary_text``) that ``readings`` reads in order; ``answer`` builds the answer.
"""
from __future__ import annotations

import math
from typing import Any

from ...encoding import try_decode_base64, try_decode_base64url
from .. import item_budget
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


def decode_payload_text(
    value: str, *, lenient: bool = False, max_items: int = item_budget.DEFAULT_MAX_ITEMS
) -> dict[str, Any]:
    """Decode ``value`` into a structured representation.

    CBOR is parsed strictly. ``lenient`` asks for a best-effort parse of CBOR
    that is not well-formed; the response then says so (``decodeMode``) and
    lists each item it kept partially or stepped over. JSON is RFC 8259's: text
    holding NaN or Infinity, or a number beyond the range of a double, is refused
    with its offset, unless ``lenient`` (see ``json_input``).

    Text that is both hexadecimal and a JSON number is read by the precedence
    in ``ambiguous_input``, and the response names the reading not taken.

    Every reading of the input counts against one budget of ``max_items``
    (``item_budget``): past it, the input is refused with ``ItemLimitError``;
    what they spell in EDN to name parts of it, against ``MAX_SPELLING_UNITS``,
    past which it is refused with ``SpellingLimitError``.
    """

    with item_budget.limit(max_items):
        return _decode(value, lenient)


def _decode(value: str, lenient: bool) -> dict[str, Any]:
    trimmed = value.strip()
    if not trimmed:
        raise ValueError("Decoder input is empty.")

    parsed_json, json_findings, ambiguity = _read_json(value, trimmed, lenient)
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


def _read_json(value: str, trimmed: str, lenient: bool) -> tuple[Any, list[dict[str, Any]], dict[str, Any] | None]:
    """``trimmed`` read as JSON and its findings (``NOT_JSON`` when it is not, or is read as
    hexadecimal), and the ``ambiguous_input`` finding when it is hexadecimal digits too.

    Digits that are a number beyond a double's range (``994e21...``) are a number JSON
    refuses strictly and reads leniently as written: the precedence still decides
    whether they are hexadecimal, as for any other number.
    """

    # Offsets count from the input as sent, blank space before it included.
    base = len(value) - len(value.lstrip())
    try:
        parsed, findings = json_input.read_or_none(trimmed, lenient=lenient, base=base)
    except json_input.JsonRangeError as refused:
        ambiguity = ambiguous_input.check(trimmed, math.inf) if refused.path == "$" else None
        if ambiguity is None or ambiguity["readAs"] != "hex":
            raise
        return json_input.NOT_JSON, [], ambiguity
    whole_number_out_of_range = any(
        finding["code"] == "json-number-out-of-range" and finding["path"] == "$" for finding in findings
    )
    ambiguity = ambiguous_input.check(trimmed, math.inf if whole_number_out_of_range else parsed)
    if ambiguity is not None and ambiguity["readAs"] == "hex":
        return json_input.NOT_JSON, [], ambiguity
    return parsed, findings, ambiguity


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
