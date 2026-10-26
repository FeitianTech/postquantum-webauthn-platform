"""``accept_encoding``: whether a request's Accept-Encoding takes a gzipped answer.

A substring test took ``gzip;q=0`` (gzip refused) and ``gzipped`` for a yes; the
header is read as RFC 9110 writes it: codings with weights, ``*`` for the rest.
"""
from __future__ import annotations

import pytest

from server.app import accept_encoding


@pytest.mark.parametrize(
    "header",
    [
        "gzip",
        "gzip, deflate, br, zstd",
        "GZIP",
        "x-gzip",
        "*",
        "gzip;q=0.001",
        "gzip;Q=0.5",
        "gzip ; q = 0.8",
        "deflate, gzip;q=1.000",
        "gzip;q=1.",
        "*;q=0, gzip;q=0.1",
        "identity;q=0, gzip;q=0.1",
        "gzip, identity;q=0.5",
        "gzip;q=0.8, *;q=0.1",
        "gzip;level=9",
    ],
)
def test_a_header_that_gives_gzip_a_weight_takes_gzip(header):
    assert accept_encoding.gzip_accepted(header) is True


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        " , ;",
        "identity",
        "br, zstd",
        "gzipped",
        "gzip;q=0",
        "gzip;q=0.000",
        "gzip;Q=0",
        "gzip;q=0, *",
        "*;q=0",
        "gzip;level=1;q=0",
        "x-gzip;q=0",
    ],
)
def test_a_header_that_refuses_gzip_or_never_names_it_takes_none(header):
    assert accept_encoding.gzip_accepted(header) is False


@pytest.mark.parametrize(
    "header",
    ["gzip;q=0.5, identity", "gzip;q=0.5, *;q=0.8", "identity;q=0.9, gzip;q=0.3"],
)
def test_a_client_that_prefers_no_coding_gets_none(header):
    assert accept_encoding.gzip_accepted(header) is False


@pytest.mark.parametrize("weight", ["abc", "1e0", "nan", "inf", "1.5", "2", "-1", "0.0001", ".5", "00.5", "1.001", "0.²", "0.٣", ""])
def test_a_weight_that_is_no_qvalue_drops_its_coding(weight):
    # The coding is then not named at all: only "*" could still take it.
    assert accept_encoding.gzip_accepted(f"gzip;q={weight}") is False
    assert accept_encoding.gzip_accepted(f"gzip;q={weight}, *;q=0.5") is True


def test_a_coding_named_twice_has_its_higher_weight():
    assert accept_encoding.gzip_accepted("gzip;q=0, gzip;q=0.5") is True
    assert accept_encoding.gzip_accepted("gzip;q=0.5, gzip;q=0") is True


def test_gzip_named_beats_x_gzip_and_the_wildcard():
    assert accept_encoding.gzip_accepted("gzip;q=0, x-gzip") is False
    assert accept_encoding.gzip_accepted("gzip, *;q=0") is True


@pytest.mark.parametrize("length", [1024, 8190])
@pytest.mark.parametrize(
    ("unit", "takes_gzip"),
    [(",", False), (";", False), ("=", False), ("gzip;q=0.5,", True), ("gzip;q=0.", False), ("\\", False), ('"', False), ("a", False)],
)
def test_a_header_of_long_runs_is_read_to_its_end(unit, takes_gzip, length):
    # Gunicorn takes a header field of up to 8190 bytes.
    header = (unit * (length // len(unit) + 1))[:length]

    assert accept_encoding.gzip_accepted(header) is takes_gzip
