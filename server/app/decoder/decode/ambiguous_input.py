"""The decoder's readings, in order, and every pair of them that can both read one input.

The decoder takes the first reading, in the order below, that reads its input,
and never picks silently: every later reading that also reads the input whole
is named in an ``ambiguous-input`` finding (``readAs``: the reading taken;
``alsoValidAs``: the one not taken). "Whole" is strict whatever the request
asked for: one well-formed CBOR item and nothing after it, authenticator data
exactly as long as its flags say, JSON as RFC 8259 has it.

The text, in order:

1. JSON (RFC 8259, ``null`` too). The exception: text of hexadecimal digits that
   is also a JSON number is hexadecimal when its bytes are one CTAP message (an
   optional CTAP command or status byte, then at most one well-formed CBOR item,
   and nothing after it: ``31`` is the byte 0x31, PIN_INVALID; ``8101`` is
   ``[1]``; ``10`` is the integer 16), and the JSON number otherwise (``99``:
   0x99 announces a two-byte array length the input does not have; ``1234``:
   0x12, then a stray 0x34). Either way ``check`` below names the other.
2. PEM, the ``-----BEGIN CERTIFICATE-----`` armour.
3. Hexadecimal: an even number of digits, perhaps after ``0x``, perhaps with
   ``:`` between them. An odd number is no hexadecimal.
4. base64url, then base64 (text in both alphabets is both, and says so).

Pairs of text readings: JSON and hexadecimal (digits: ``check``); JSON and PEM
(PEM armour on one line inside a JSON string); JSON, PEM or hexadecimal, and
base64 (``eAE0`` is the hex bytes ea e0, and the base64 78 01 34, the text item
"4"). A text reading that gives bytes counts as reading the text whole only
when some binary reading below reads those bytes whole.

The bytes, in order (``readings.py``):

1. A CTAP command or status byte, alone.
2. PEM text, in UTF-8.
3. JSON text, in UTF-8 (client data, or any other JSON).
4. A DER certificate.
5. An attestation object: one CBOR item, read as WebAuthn's attestation object.
6. One CTAP message or one CBOR item, whole: before authenticator data, because
   about a quarter of all 37-byte items have a byte 32 without the AT and ED
   flags (a real 37-byte getInfo response is one), while authenticator data that
   is also one item is a chance in tens of thousands.
7. Authenticator data.
8. CBOR: one item after an optional CTAP command or status byte (and whatever
   follows it, reported), or, when asked, a lenient reading of what is not
   well-formed.

The readings that read bytes whole, for these findings: a CTAP command or
status byte; PEM text; JSON text; a DER certificate; one CBOR item; a CTAP
command or status byte and one CBOR item; authenticator data. Pairs that occur:

- a CTAP byte, alone, and one CBOR item: ``05`` is TIMEOUT and the integer 5;
  and JSON text: ``31`` is also the text "1";
- JSON text and one CBOR item: the bytes "85" are the integer -54;
- JSON text and a CTAP message: a line feed and 1 (0a 31) is CREDENTIAL_MGMT and -18;
- JSON text and authenticator data: 37 bytes of JSON whose byte 32 is flags
  without AT or ED;
- a CTAP message and one CBOR item: 41 00 is CREDENTIAL_MGMT_PRE and 0, or the
  byte string h'00'. (41 ab, whose second byte is no item, is read as h'ab',
  and ``ctap-prefix-not-read`` names the command);
- one CBOR item or a CTAP message, and authenticator data: any 37 bytes that
  are one item, whose byte 32 has neither AT nor ED -- a 37-byte getInfo
  response, say. Read as the item;
- PEM text, and anything else: PEM armour is none of the others, so none;
- a DER certificate, and anything else: no pair is known (0x30, SEQUENCE, is
  the CBOR integer -17 with bytes after it), but the check is made.

What one reading reads is not also another reading when it is the same item
read for more: an attestation object is one CBOR item, client data is JSON
text. Those are not named. What is named, beside the bytes' readings:

- the CTAP message a map is, by its shape: a map with no CTAP byte can be any of
  them and is also a plain CBOR map (``{1: "x", 2: h'01', 3: {}}`` is a
  makeCredential response's shape and a getAssertion request's); after a status
  byte, the responses (``ctap_classify.shape_findings``); after a command byte,
  none: the command says which;
- a PublicKeyCredential that is also client data (its members make both).

The test for well-formed CBOR is strict whether or not the request asked for
lenient decoding, so the reading taken never depends on it.
"""
from __future__ import annotations

import re
from typing import Any

from . import cbor_parser, ctap_prefix

_HEX_DIGITS = re.compile(r"[0-9A-Fa-f]+")


def check(text: str, parsed_json: Any) -> dict[str, Any] | None:
    """The finding for ``text`` when it reads both ways, saying which reading won."""

    if not isinstance(parsed_json, (int, float)) or isinstance(parsed_json, bool):
        return None
    if len(text) % 2 or not _HEX_DIGITS.fullmatch(text):
        return None
    if is_one_ctap_message(bytes.fromhex(text)):
        read_as, also, message = (
            "hex",
            "json",
            f"the input is also the JSON number {text}; it was read as hexadecimal, because "
            "those bytes are one well-formed CBOR item (after any CTAP command or status byte)",
        )
    else:
        read_as, also, message = (
            "json",
            "hex",
            f"the input is also hexadecimal (h'{text.lower()}'); it was read as the JSON number "
            f"{text}, because those bytes are not one well-formed CBOR item",
        )
    return {
        "code": "ambiguous-input",
        "category": "input",
        "offset": 0,
        "path": "$",
        "readAs": read_as,
        "alsoValidAs": also,
        "message": message,
    }


def is_one_ctap_message(data: bytes) -> bool:
    """A CTAP command or status byte on its own, or at most one before a single well-formed CBOR item."""

    prefix, payload = ctap_prefix._extract_ctap_prefix(data)
    if not payload:
        return prefix is not None
    try:
        _node, end, _skipped = cbor_parser.decode_item(data, len(data) - len(payload))
    except cbor_parser._CborDecodingError:
        return False
    return end == len(data)


def finding(read_as: str, also: str, detail: str = "") -> dict[str, Any]:
    """The ``ambiguous-input`` finding: the input was read as ``read_as``, and ``also`` reads it whole too."""

    return {
        "code": "ambiguous-input",
        "category": "input",
        "offset": 0,
        "path": "$",
        "readAs": read_as,
        "alsoValidAs": also,
        "message": (
            f"the input is also {also}{detail}; it was read as {read_as}, which comes first in the "
            "decoder's order of readings (decode/ambiguous_input.py)"
        ),
    }
