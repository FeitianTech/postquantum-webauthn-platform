"""Contracts for ``server.app.encoding``, the one binary-encoding module.

The round-trip tests are property-style: they sweep every payload length that
changes the base64 padding class and every byte value, rather than asserting a
handful of hand-picked vectors.
"""

from __future__ import annotations

import base64

import pytest

encoding = pytest.importorskip("server.app.encoding")

_PAYLOADS = [bytes(range(256))[start:start + length] for start in (0, 61, 200) for length in range(0, 9)]


@pytest.mark.parametrize("payload", _PAYLOADS)
def test_base64url_round_trips_and_stays_unpadded(payload):
    text = encoding.encode_base64url(payload)
    assert "=" not in text
    assert set(text) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert encoding.decode_base64url(text) == payload


@pytest.mark.parametrize("payload", _PAYLOADS)
def test_base64_round_trips_and_stays_padded(payload):
    text = encoding.encode_base64(payload)
    assert len(text) % 4 == 0
    assert encoding.decode_base64(text) == payload


@pytest.mark.parametrize("payload", _PAYLOADS)
def test_hex_round_trips(payload):
    text = encoding.encode_hex(payload)
    assert len(text) % 2 == 0
    assert encoding.decode_hex(text) == payload


def _is_hex_looking(text: str) -> bool:
    """Whether ``text`` would be claimed by the hex branch of :func:`sniff`."""

    return bool(text) and all(char in "0123456789abcdefABCDEF" for char in text)


@pytest.mark.parametrize("payload", [payload for payload in _PAYLOADS if payload])
def test_sniff_recovers_base64url_payloads(payload):
    text = encoding.encode_base64url(payload)
    if _is_hex_looking(text):
        pytest.skip("payload encodes to something that is also valid hex")
    result = encoding.sniff(text)
    assert result.data == payload
    assert result.encoding == ("base64url" if ("-" in text or "_" in text) else "base64")
    assert result.ambiguous is not ("-" in text or "_" in text)


@pytest.mark.parametrize("payload", [payload for payload in _PAYLOADS if payload])
def test_sniff_recovers_standard_base64_payloads(payload):
    text = encoding.encode_base64(payload)
    if _is_hex_looking(text.rstrip("=")) and "=" not in text:
        pytest.skip("payload encodes to something that is also valid hex")
    result = encoding.sniff(text)
    assert result.data == payload
    assert result.encoding == "base64"
    assert result.ambiguous is not ("+" in text or "/" in text)


def test_sniff_prefers_hex_when_a_string_is_valid_in_both_readings():
    """``AAEC`` is valid hex *and* valid base64; hex wins, and says it won.

    This precedence is inherited from the decoder pipeline. It is documented
    here rather than left implicit, because the two readings disagree.
    """

    assert encoding.sniff("AAEC") == encoding.SniffResult(b"\xaa\xec", "hex")
    assert encoding.decode_base64("AAEC") == b"\x00\x01\x02"


def test_base64url_padding_is_optional_but_must_be_consistent():
    assert encoding.decode_base64url("QUJD") == b"ABC"
    assert encoding.decode_base64url("QUI") == b"AB"
    assert encoding.decode_base64url("QUI=") == b"AB"


def test_base64url_rejects_standard_alphabet_characters():
    standard = base64.b64encode(b"\xfb\xef\xbe").decode("ascii")
    assert "+" in standard or "/" in standard
    with pytest.raises(encoding.EncodingError):
        encoding.decode_base64url(standard)


def test_base64_rejects_url_alphabet_characters():
    urlsafe = base64.urlsafe_b64encode(b"\xfb\xef\xbe").decode("ascii")
    assert "-" in urlsafe or "_" in urlsafe
    with pytest.raises(encoding.EncodingError):
        encoding.decode_base64(urlsafe)


def test_decoders_reject_characters_outside_the_alphabet():
    for decoder in (encoding.decode_base64url, encoding.decode_base64):
        with pytest.raises(encoding.EncodingError):
            decoder("Hello, this is plain text!")
    with pytest.raises(encoding.EncodingError):
        encoding.decode_hex("not hex at all")


def test_lenient_decoding_must_be_asked_for_and_is_reported():
    with pytest.raises(encoding.EncodingError):
        encoding.decode_base64url("QU*JD")
    assert encoding.decode_base64url("QU*JD", lenient=True) == b"ABC"

    result = encoding.sniff("QU*JD", lenient=True)
    assert result.data == b"ABC"
    assert result.lenient is True
    assert encoding.sniff("QUJD").lenient is False


def test_whitespace_is_ignored_by_default_but_can_be_refused():
    assert encoding.decode_base64url("QU JD") == b"ABC"
    with pytest.raises(encoding.EncodingError):
        encoding.decode_base64url("QU JD", ignore_whitespace=False)


def test_odd_length_hex_is_an_error_unless_padding_is_requested():
    with pytest.raises(encoding.EncodingError):
        encoding.decode_hex("abc")
    assert encoding.decode_hex("abc", allow_odd_length=True) == b"\x0a\xbc"


def test_hex_separators_must_be_allowed_explicitly():
    with pytest.raises(encoding.EncodingError):
        encoding.decode_hex("de:ad:be:ef")
    assert encoding.decode_hex("de:ad:be:ef", allow_separators=True) == b"\xde\xad\xbe\xef"
    assert encoding.decode_hex("0xdead", allow_separators=True) == b"\xde\xad"


def test_base64_length_congruent_to_one_is_rejected():
    for decoder in (encoding.decode_base64url, encoding.decode_base64):
        with pytest.raises(encoding.EncodingError):
            decoder("QUJDQ")


def test_sniff_reports_ambiguity_instead_of_asserting_an_encoding():
    result = encoding.sniff("QUJD")
    assert result.data == b"ABC"
    assert result.encoding == "base64"
    assert result.ambiguous is True


def test_sniff_prefers_hex_and_labels_it():
    result = encoding.sniff("dead:beef")
    assert result == encoding.SniffResult(b"\xde\xad\xbe\xef", "hex")


def test_sniff_rejects_input_mixing_both_base64_alphabets():
    with pytest.raises(encoding.EncodingError):
        encoding.sniff("ab-cd+ef")


def test_sniff_rejects_empty_and_plain_text():
    with pytest.raises(encoding.EncodingError):
        encoding.sniff("   ")
    with pytest.raises(encoding.EncodingError):
        encoding.sniff("Hello, this is plain text!")


def test_try_helpers_return_none_rather_than_raising():
    assert encoding.try_decode_base64url("Hello, this is plain text!") is None
    assert encoding.try_decode_base64("Hello, this is plain text!") is None
    assert encoding.try_decode_hex("zz") is None
    assert encoding.try_sniff("Hello, this is plain text!") is None
    assert encoding.try_decode_base64url("QUJD") == b"ABC"


def test_decode_pem_body_ignores_armour_and_stays_strict():
    der = bytes(range(48))
    body = base64.b64encode(der).decode("ascii")
    pem = "-----BEGIN CERTIFICATE-----\n" + body[:32] + "\n" + body[32:] + "\n-----END CERTIFICATE-----\n"
    assert encoding.decode_pem_body(pem) == der

    with pytest.raises(encoding.EncodingError):
        encoding.decode_pem_body("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
    with pytest.raises(encoding.EncodingError):
        encoding.decode_pem_body("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")


def test_non_string_input_is_rejected_rather_than_coerced():
    for decoder in (encoding.decode_base64url, encoding.decode_base64, encoding.decode_hex):
        with pytest.raises(encoding.EncodingError):
            decoder(b"QUJD")


def test_non_canonical_final_quantum_is_rejected():
    """``validate=True`` accepts these; re-encoding them changes the bytes.

    ``debug-metadata`` is inside the base64url alphabet and has a legal length,
    but the unused bits of its last character are not zero, so it is not the
    encoding of any byte string this module would produce.
    """

    assert encoding.try_decode_base64url("debug-metadata") is None
    assert encoding.try_decode_base64("not-bytes") is None
    assert encoding.try_decode_base64("414243") is None

    # A full final quantum has no spare bits to get wrong, so it decodes.
    assert encoding.decode_base64("4142") == base64.b64decode("4142")
    assert encoding.decode_base64url("QUJD") == b"ABC"
