"""decoder/edn reads EDN back to exactly the bytes it notates.

What ``spell`` writes and what a person writes by hand (RFC 8949 section 8, RFC
8610 appendix G, draft-ietf-cbor-edn-literals): never canonicalised -- map
order, duplicates, head and float widths are the text's -- and anything it
cannot read is refused with the offset in the text.
"""
from __future__ import annotations

import pytest

from server.app.decoder import edn
from server.app.decoder.edn import reader


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Integers, their argument widths, other bases.
        ("0", "00"), ("23", "17"), ("24", "1818"), ("5_0", "1805"), ("5_1", "190005"), ("5_2", "1a00000005"),
        ("5_3", "1b0000000000000005"), ("5_i", "05"), ("-1", "20"), ("-256_1", "3900ff"), ("+7", "07"),
        ("18446744073709551615", "1bffffffffffffffff"), ("-18446744073709551616", "3bffffffffffffffff"),
        ("0x10", "10"), ("-0x10", "2f"), ("0o17", "0f"), ("0b101", "05"), ("-0", "00"), ("007", "07"),
        # Floats: decimal, exponent, hex; widths; the non-finite values; bits.
        ("1.5", "f93e00"), ("1.5_2", "fa3fc00000"), ("1.5_3", "fb3ff8000000000000"), ("1.1", "fb3ff199999999999a"),
        ("100000.0", "fa47c35000"), ("1e3", "f963d0"), ("1.0e+20", "fb4415af1d78b58c40"), ("-0.0", "f98000"),
        ("0x1.8p0", "f93e00"), ("-0x1.8p1_3", "fbc008000000000000"), (".5", "f93800"), ("2.", "f94000"),
        ("NaN", "f97e00"), ("NaN_2", "fa7fc00000"), ("Infinity", "f97c00"), ("-Infinity_3", "fbfff0000000000000"),
        # The largest double, written either way, is in range.
        ("1.7976931348623157e308", "fb7fefffffffffffff"), ("0x1.fffffffffffffp1023", "fb7fefffffffffffff"),
        ("float'7e01'", "f97e01"), ("float'fe00'", "f9fe00"), ("float'7fc00001'", "fa7fc00001"),
        ("float'7ff8000000000001'", "fb7ff8000000000001"),
        # Byte strings every way, with their widths.
        ("h''", "40"), ("h'01ff'", "4201ff"), ("h'01 ff\n 02'", "4301ff02"), ("h'41'_1", "59000141"),
        ("'ab'", "426162"), ("b64'AQI='", "420102"), ("b64'AQI'", "420102"), ("b64'-_8'", "42fbff"),
        ("<<1, 2>>", "420102"), ("<<>>", "40"), ("<<[1]>>_0", "58028101"),
        # Text strings, escapes.
        ('""', "60"), ('"a"_0', "780161"), ('"\\u00e9"', "62c3a9"), ('"\\u{1F600}"', "64f09f9880"),
        ('"\\ud83d\\ude00"', "64f09f9880"), ('"q\\"\\\\\\/\\n"', "657122" + "5c2f0a"), ('"é"', "62c3a9"),
        # Indefinite strings: chunks, none, and the draft's sequence forms.
        ("''_", "5fff"), ('""_', "7fff"), ("(_ h'01', h'02'_0)", "5f4101580102ff"), ('(_ "a", "b")', "7f61616162ff"),
        ("(_ h'')", "5f40ff"), ("ilbs<<>>", "5fff"), ("ilbs<<h'01' h'02'>>", "5f41014102ff"), ('ilts<<"a">>', "7f6161ff"),
        # Arrays and maps: indicators, order and duplicates as written, separators.
        ("[]", "80"), ("[_0]", "9800"), ("[_ ]", "9fff"), ("[_]", "9fff"), ("[1, 2]", "820102"), ("[_0 1, 2]", "98020102"),
        ("[_ 1, 2]", "9f0102ff"), ("[1 2 3]", "83010203"), ("[1, 2,]", "820102"), ("{}", "a0"), ("{_ }", "bfff"),
        ("{1: 2}", "a10102"), ("{_0 1: 2}", "b8010102"), ('{1: "a", 1: "b"}', "a2016161016162"),
        ("{2: 0, 1: 0}", "a202000100"), ('{"1": 0, 1: 0}', "a2613100" + "0100"), ("[\n  [1],\n  2\n]", "82810102"),
        # Tags and simple values.
        ("1(0)", "c100"), ("1_0(0)", "d80100"), ("1(2(0))", "c1c200"), ("24_1(h'00')", "d900184100"),
        ("256(h'')", "d9010040"), ("false", "f4"), ("true", "f5"), ("null", "f6"), ("undefined", "f7"),
        ("simple(0)", "e0"), ("simple(19)", "f3"), ("simple(20)", "f4"), ("simple(32)", "f820"), ("simple(255)", "f8ff"),
        # Comments and blank space anywhere between items.
        ("/ a / [1, /* b */ 2 # c\n, 3 // d\n]", "83010203"), ("  1  ", "01"),
    ],
)
def test_edn_is_encoded_to_exactly_the_bytes_it_notates(text, expected):
    assert edn.encode(text).hex() == expected


@pytest.mark.parametrize(
    ("text", "offset", "reason"),
    [
        ("", 0, "no item"),
        ("1 2", 2, "a CBOR sequence"),
        ("[1, 256_0]", 4, "does not fit"),
        ("24_i", 0, "_i holds an argument of 0..23"),
        ("5_4", 0, "_4 is reserved"),
        ("5_x", 0, "no encoding indicator _x"),
        ("5_", 0, "indefinite length is only for"),
        ("1.1_1", 0, "not exact"),
        # A finite literal is never rounded to infinity (HTTP 500 for a hex float, before).
        ("1e999", 0, "1e999 is beyond the range of a double"),
        ("-1.8e308", 0, "beyond the range of a double"),
        ("0x1p1024", 0, "beyond the range of a double"),
        ("-0x1p1024", 0, "beyond the range of a double"),
        ("0x1.fffffffffffff8p1023", 0, "beyond the range of a double"),
        ("[0, 0x1p99999]", 4, "beyond the range of a double"),
        ("1.5_0", 0, "_1, _2 or _3"),
        ("simple(24)", 0, "not a simple value"),
        ("simple(256)", 0, "not a simple value"),
        ("18446744073709551616", 0, "beyond 64 bits"),
        ("-18446744073709551617", 0, "beyond 64 bits"),
        # However long: Python's own limit on converting decimal text is not the message.
        ("1" * 4301, 0, "beyond 64 bits: write it as a bignum tag"),
        ("[0, -" + "9" * 5000 + "]", 4, "beyond 64 bits: write it as a bignum tag"),
        ("0x" + "f" * 5000, 0, "beyond 64 bits"),
        ("h'0'", 0, "pairs of hex digits"),
        ("h'zz'", 0, "pairs of hex digits"),
        ("b64'@@'", 0, "not base64"),
        ("float'00'", 0, "2, 4 or 8 bytes"),
        ("float'7e00'_2", 0, "no encoding indicator"),
        ('"abc"_', 0, "only an empty literal"),
        ("(_ )", 0, "names no chunks"),
        ("(_h'01')", 2, "blank space"),
        ("(_ h'01', \"a\")", 10, "chunks are definite strings of its own type"),
        ("(_ ''_)", 3, "chunks are definite strings of its own type"),
        ("(_ h'01', (_ h'02'))", 10, "chunks are definite strings of its own type"),
        # (_ ...) notates a string: an integer, array, map, simple value or tag is no chunk.
        ("(_ 1)", 3, "a byte or text string"),
        ("(_ -1)", 3, "a byte or text string"),
        ("(_ [1])", 3, "a byte or text string"),
        ("(_ [])", 3, "a byte or text string"),
        ("(_ {})", 3, "a byte or text string"),
        ("(_ true)", 3, "a byte or text string"),
        ("(_ 1.5)", 3, "a byte or text string"),
        ("(_ 1(2))", 3, "a byte or text string"),
        ("(_ h'01', 2)", 10, "a byte or text string"),
        ("ilbs<<1>>", 6, "a byte or text string"),
        ("[1 2", 4, "expected ']'"),
        ("[[][]]", 3, "separated by a comma or blank space"),
        ("[_01]", 0, "no encoding indicator _01"),
        ("[_0" + "1]", 0, "no encoding indicator"),
        ("{1}", 2, "expected ':'"),
        ("{1: 2", 5, "expected '}'"),
        ("1_(0)", 0, "indefinite length is only for"),
        ("wat", 0, "expected an item"),
        ('"abc', 0, "never closed"),
        ('"\\ud800"', 1, "high surrogate"),
        ('"\\x"', 1, "unknown escape"),
        ('"a\tb"', 2, "control character"),
        ("/ open", 0, "never closed"),
        ("<<1", 3, "expected '>>'"),
    ],
)
def test_edn_that_cannot_be_encoded_is_refused_with_its_offset(text, offset, reason):
    with pytest.raises(ValueError, match=f"^EDN is not valid at offset {offset}: .*{reason}"):
        edn.encode(text)


def test_edn_nested_as_deep_as_the_decoder_reads_is_encoded():
    from server.app.decoder.decode import cbor_parser

    assert reader._MAX_DEPTH == cbor_parser._MAX_DEPTH
    data = edn.encode("[" * 64 + "0" + "]" * 64)

    assert data == bytes([0x81]) * 64 + b"\x00"
    cbor_parser.decode_item(data)


@pytest.mark.parametrize(
    ("text", "offset"),
    [
        ("[" * 65 + "0" + "]" * 65, 65),
        ("[" * 10000, 65),
        ("{1: " * 70 + "0" + "}" * 70, 257),  # the key of the map at depth 64
        ("1(" * 300 + "0" + ")" * 300, 130),
        ("<<" * 350 + ">>" * 350, 130),
        ("(_ " * 70 + "h''" + ")" * 70, 195),
    ],
)
def test_edn_nested_deeper_than_the_decoder_reads_is_refused_with_its_offset(text, offset):
    # Not a RecursionError (HTTP 500): a refusal, as the decoder refuses the bytes.
    with pytest.raises(ValueError, match=f"^EDN is not valid at offset {offset}: items are nested more than 64 deep"):
        edn.encode(text)
