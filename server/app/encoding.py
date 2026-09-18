"""Single source of truth for binary/text encodings on the Python side.

Every base64, base64url and hexadecimal conversion in ``server/`` goes through
this module. It exists because the same conversion used to be open-coded in
about twenty files with mutually incompatible strictness, which let malformed
input decode to *wrong bytes* instead of being rejected.

Strictness contract
-------------------
Decoding is **strict by default**: input outside the declared alphabet is an
error, never something silently dropped. ``base64.b64decode`` defaults to
``validate=False``, which discards non-alphabet characters, so plain English
text "decodes" to garbage; every decoder here passes ``validate=True`` and also
checks the alphabet up front so ``-``/``_`` cannot slip into a standard-base64
decode (or vice versa).

Two relaxations are available, and both must be asked for explicitly:

``lenient=True``
    Drop characters outside the alphabet before decoding, i.e. the old
    ``validate=False`` behaviour. :func:`sniff` records this on the result as
    :attr:`SniffResult.lenient` so a caller can never lose track of it.

``allow_odd_length=True`` (hex only)
    Left-pad an odd-length hex string with ``0``. Strict hex rejects it,
    because "abc" is as likely to be a truncated string as it is to be 0x0abc.

Whitespace is *not* leniency: removing it cannot change the decoded bytes, so
``ignore_whitespace`` defaults to ``True``. Hex separators (``:`` and a ``0x``
prefix) can change the reading of a string, so ``allow_separators`` defaults to
``False``.

Encoding
--------
``base64url`` output is **unpadded** (the WebAuthn wire convention).
``base64`` output is **padded** standard base64, and is only used where a
consumer genuinely requires it -- see ``storage.convert_bytes_for_json``.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

__all__ = [
    "EncodingError",
    "SniffResult",
    "decode_base64",
    "decode_base64url",
    "decode_hex",
    "decode_pem_body",
    "encode_base64",
    "encode_base64url",
    "encode_hex",
    "sniff",
    "try_decode_base64",
    "try_decode_base64url",
    "try_decode_hex",
    "try_sniff",
]

_BASE64URL_ALPHABET = re.compile(r"\A[A-Za-z0-9_-]*={0,2}\Z")
_BASE64_ALPHABET = re.compile(r"\A[A-Za-z0-9+/]*={0,2}\Z")
_HEX_ALPHABET = re.compile(r"\A[0-9A-Fa-f]*\Z")
_WHITESPACE = re.compile(r"\s+")
_PEM_ARMOUR = re.compile(r"^-----(BEGIN|END).*-----$")

#: Encoding labels returned by :func:`sniff`.
BASE64 = "base64"
BASE64URL = "base64url"
HEX = "hex"


class EncodingError(ValueError):
    """Raised when input cannot be decoded under the requested contract."""


@dataclass(frozen=True)
class SniffResult:
    """The bytes :func:`sniff` recovered *and* how it actually read them."""

    data: bytes
    encoding: str
    #: ``True`` when the input is valid base64 *and* valid base64url and both
    #: yield these exact bytes, so ``encoding`` is a label of convenience
    #: rather than a determination. Callers that report the encoding to a user
    #: should say so instead of asserting one.
    ambiguous: bool = False
    #: ``True`` only when the caller asked for a relaxation and it was applied.
    lenient: bool = False


def _prepare(text: str, *, ignore_whitespace: bool) -> str:
    if not isinstance(text, str):
        raise EncodingError(f"expected str, got {type(text).__name__}")
    return _WHITESPACE.sub("", text) if ignore_whitespace else text


def _pad(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def _b64_decode_strict(value: str, *, urlsafe: bool) -> bytes:
    """Decode ``value`` with padding normalised, rejecting stray characters."""

    body = value.rstrip("=")
    if len(body) % 4 == 1:
        raise EncodingError("invalid base64 length")
    translated = body.translate(str.maketrans("-_", "+/")) if urlsafe else body
    try:
        return base64.b64decode(_pad(translated), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EncodingError(f"invalid base64 data: {exc}") from exc


def encode_base64url(data: bytes) -> str:
    """Encode ``data`` as unpadded base64url."""

    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def decode_base64url(
    text: str,
    *,
    ignore_whitespace: bool = True,
    lenient: bool = False,
) -> bytes:
    """Decode base64url ``text``, rejecting anything outside ``A-Za-z0-9_-``.

    ``+`` and ``/`` are rejected: they belong to standard base64, and accepting
    them here is how a base64 payload ends up silently read as base64url.
    """

    cleaned = _prepare(text, ignore_whitespace=ignore_whitespace)
    if lenient:
        cleaned = re.sub(r"[^A-Za-z0-9_=-]", "", cleaned)
    elif not _BASE64URL_ALPHABET.fullmatch(cleaned):
        raise EncodingError("input is not base64url")
    return _b64_decode_strict(cleaned, urlsafe=True)


def encode_base64(data: bytes) -> str:
    """Encode ``data`` as padded standard base64."""

    return base64.b64encode(bytes(data)).decode("ascii")


def decode_base64(
    text: str,
    *,
    ignore_whitespace: bool = True,
    lenient: bool = False,
) -> bytes:
    """Decode standard base64 ``text``, rejecting anything outside ``A-Za-z0-9+/``.

    ``-`` and ``_`` are rejected so a base64url payload cannot be misread here.
    """

    cleaned = _prepare(text, ignore_whitespace=ignore_whitespace)
    if lenient:
        cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", cleaned)
    elif not _BASE64_ALPHABET.fullmatch(cleaned):
        raise EncodingError("input is not standard base64")
    return _b64_decode_strict(cleaned, urlsafe=False)


def encode_hex(data: bytes) -> str:
    """Encode ``data`` as lowercase hexadecimal."""

    return bytes(data).hex()


def decode_hex(
    text: str,
    *,
    ignore_whitespace: bool = True,
    allow_separators: bool = False,
    allow_odd_length: bool = False,
) -> bytes:
    """Decode hexadecimal ``text``.

    An odd number of digits is an error unless ``allow_odd_length`` is set, in
    which case the value is left-padded with ``0`` -- the guess the old
    open-coded decoders made silently.
    """

    cleaned = _prepare(text, ignore_whitespace=ignore_whitespace)
    if allow_separators:
        cleaned = re.sub(r"\A0[xX]|:", "", cleaned)
    if not _HEX_ALPHABET.fullmatch(cleaned):
        raise EncodingError("input is not hexadecimal")
    if len(cleaned) % 2:
        if not allow_odd_length:
            raise EncodingError("hexadecimal input has an odd number of digits")
        cleaned = "0" + cleaned
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:  # pragma: no cover - alphabet already checked
        raise EncodingError(f"invalid hexadecimal data: {exc}") from exc


def decode_pem_body(text: str, *, lenient: bool = False) -> bytes:
    """Decode the base64 body of a PEM block, ignoring ``-----`` armour lines."""

    body = "".join(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not _PEM_ARMOUR.match(line.strip())
    )
    if not body:
        raise EncodingError("no PEM body present")
    return decode_base64(body, lenient=lenient)


def try_decode_base64url(text: str, **kwargs: object) -> bytes | None:
    """:func:`decode_base64url`, returning ``None`` instead of raising."""

    try:
        return decode_base64url(text, **kwargs)  # type: ignore[arg-type]
    except EncodingError:
        return None


def try_decode_base64(text: str, **kwargs: object) -> bytes | None:
    """:func:`decode_base64`, returning ``None`` instead of raising."""

    try:
        return decode_base64(text, **kwargs)  # type: ignore[arg-type]
    except EncodingError:
        return None


def try_decode_hex(text: str, **kwargs: object) -> bytes | None:
    """:func:`decode_hex`, returning ``None`` instead of raising."""

    try:
        return decode_hex(text, **kwargs)  # type: ignore[arg-type]
    except EncodingError:
        return None


def sniff(
    text: str,
    *,
    allow_separators: bool = True,
    allow_odd_length_hex: bool = False,
    lenient: bool = False,
) -> SniffResult:
    """Decode ``text`` and report which encoding actually matched.

    Precedence is hex, then base64url, then base64. The encoding is decided by
    which strict decoder succeeded -- never by scanning for ``-``/``_`` and
    assuming. When the input is confined to ``A-Za-z0-9`` both base64 variants
    decode to the same bytes; that is reported as ``base64`` with
    :attr:`SniffResult.ambiguous` set, rather than asserted as either one.
    """

    cleaned = _prepare(text, ignore_whitespace=True)
    if not cleaned:
        raise EncodingError("no binary data present")

    hex_candidate = re.sub(r"0[xX]|:", "", cleaned) if allow_separators else cleaned
    if hex_candidate and _HEX_ALPHABET.fullmatch(hex_candidate):
        odd = bool(len(hex_candidate) % 2)
        data = decode_hex(
            hex_candidate,
            allow_odd_length=allow_odd_length_hex,
        )
        return SniffResult(data, HEX, lenient=odd and allow_odd_length_hex)

    has_url_chars = "-" in cleaned or "_" in cleaned
    has_std_chars = "+" in cleaned or "/" in cleaned

    if has_url_chars and has_std_chars:
        raise EncodingError("input mixes base64 and base64url alphabets")

    if has_url_chars:
        return SniffResult(
            decode_base64url(cleaned, lenient=lenient), BASE64URL, lenient=lenient
        )
    if has_std_chars:
        return SniffResult(
            decode_base64(cleaned, lenient=lenient), BASE64, lenient=lenient
        )

    return SniffResult(
        decode_base64(cleaned, lenient=lenient),
        BASE64,
        ambiguous=True,
        lenient=lenient,
    )


def try_sniff(text: str, **kwargs: object) -> SniffResult | None:
    """:func:`sniff`, returning ``None`` instead of raising."""

    try:
        return sniff(text, **kwargs)  # type: ignore[arg-type]
    except EncodingError:
        return None
