"""An API route reads its JSON body only when it is an object (``routes/json_body.py``).

Any other JSON -- a list, a string, a number, true -- is read as an object with
no members, so a route answers what it answers for a missing member, never a
failure of its own. A JSON body nested more than 64 deep is refused, 400 in
JSON, before it is parsed, by a scan linear in the body's length.
"""
from __future__ import annotations

import time
import tracemalloc

import pytest

from server.app.routes import json_body

# The routes that take no JSON: the metadata upload takes a form, the CSP reports their own type.
_NOT_JSON = {"/api/mds/metadata/upload", "/api/csp-report"}
_TOO_DEEP = {"error": "The request body is JSON nested more than 64 deep, deeper than this server reads."}
# A scan quadratic in the body's length takes seconds at 64 KiB, and hours at 8 MiB: each cost test asks it first.
_SECONDS_IF_QUADRATIC = 64 * 1024


def _unclosed_string(size, end=b""):
    """``size`` bytes: 65 arrays opened, then a string of escaped quotes that no quote closes, then ``end``."""

    pairs, odd = divmod(size - 66 - len(end), 2)
    body = b"[" * 65 + b'"' + b"x" * odd + b'\\"' * pairs + end
    assert len(body) == size
    return body


def _json_routes(app):
    """Every API route that takes a JSON body, by method and path."""

    return [
        (method, rule.build({name: "stored-1" for name in rule.arguments}, append_unknown=False)[1])
        for rule in app.url_map.iter_rules()
        if rule.rule.startswith("/api/") and rule.rule not in _NOT_JSON
        for method in sorted(rule.methods & {"POST", "PUT"})
    ]


def _answer(make_app, method, path, body):
    response = make_app().test_client().open(path, method=method, json=body)
    answer = response.get_json()
    # A begin's options hold a fresh challenge: its status and members are the answer.
    return response.status_code, answer.get("error") if isinstance(answer, dict) and "error" in answer else sorted(answer or {})


@pytest.mark.parametrize("body", [["publicKey"], "payload", 7, True])
def test_a_body_that_is_no_object_is_answered_as_one_without_members(app, make_app, body, monkeypatch, tmp_path):
    for name in ("CREDENTIAL", "CREDENTIAL_ARTIFACT", "SESSION_METADATA"):
        monkeypatch.setenv(f"FIDO_SERVER_{name}_DIR", str(tmp_path / name.lower()))
    routes = _json_routes(app)

    differing = [
        (method, path) for method, path in routes if _answer(make_app, method, path, body) != _answer(make_app, method, path, {})
    ]

    assert len(routes) > 10
    assert differing == []


@pytest.mark.parametrize(
    ("data", "too_deep"),
    [
        (b"[" * 64 + b"]" * 64, False),
        (b"[" * 65 + b"]" * 65, True),
        (b'{"a": ' * 65 + b"1" + b"}" * 65, True),
        (b"[" + b"[], " * 1000 + b"[]]", False),
        (b'["' + b"[" * 100 + b'"]', False),
        (b'["\\"' + b"[" * 100 + b'"]', False),
        (b'["\\\\", ' + b"[" * 64 + b"]" * 64 + b"]", True),
        (b"[" * 64 + b'"[[]]"' + b"]" * 64, False),
        (b"[" * 33 + b'"' + b"]" * 33 + b'"' + b"[" * 32 + b"]" * 65, True),
        (b'["' + b"[" * 100, False),
        (b'["' + b'\\"' * 10 + b"[" * 100, False),
        (b"[" * 65 + b'"' + b"]" * 65, True),
    ],
    ids=[
        "64 arrays",
        "65 arrays",
        "65 objects",
        "1000 side by side",
        "in a string",
        "after an escaped quote",
        "after a backslash",
        "64 arrays around a string",
        "past closing brackets in a string",
        "in a string never closed",
        "after escaped quotes in a string never closed",
        "65 arrays before a string never closed",
    ],
)
def test_json_is_too_deep_past_64_arrays_or_objects_its_strings_set_aside(data, too_deep):
    assert json_body.nested_too_deep(data) is too_deep


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"])
@pytest.mark.parametrize(
    ("text", "too_deep"),
    [
        ('["\\"", "x", ' + "[" * 63 + "]" * 63 + ', "y"]', False),
        ('["\\"", "x", ' + "[" * 64 + "]" * 64 + ', "y"]', True),
        ('["∀屜' + "[" * 100 + '"]', False),
    ],
    ids=["64 deep after an escaped quote", "65 deep after an escaped quote", "in a string of a quote's and a backslash's bytes"],
)
def test_json_in_any_encoding_the_reader_reads_is_scanned_as_it_decodes_it(text, too_deep, encoding):
    assert json_body.nested_too_deep(text.encode(encoding)) is too_deep


def test_bytes_the_reader_cannot_decode_are_not_too_deep():
    # The first bytes say UTF-16, and the body ends halfway through a character.
    assert json_body.nested_too_deep(("[" * 100).encode("utf-16-be") + b"\x00") is False


@pytest.mark.parametrize("end", [b"", b"\\"], ids=["escaped quotes", "then a lone backslash"])
def test_a_string_no_quote_closes_is_scanned_in_time_linear_in_the_body(end):
    for size in (_SECONDS_IF_QUADRATIC, 8 * 1024 * 1024):
        body = _unclosed_string(size, end)

        started = time.perf_counter()
        too_deep = json_body.nested_too_deep(body)
        elapsed = time.perf_counter() - started

        assert too_deep is True
        assert elapsed < 2, f"{size} bytes scanned in {elapsed:.1f} s"


def test_a_body_of_many_strings_is_scanned_in_memory_about_its_own_size():
    # 2.8 million strings in 8 MiB: a record held for each one set aside took 476 MB.
    body = b"[" * 65 + b'"",' * ((8 * 1024 * 1024 - 65) // 3)

    tracemalloc.start()
    try:
        too_deep = json_body.nested_too_deep(body)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert too_deep is True
    assert peak < 3 * len(body)


def test_a_body_that_does_not_say_it_is_json_is_not_read(app):
    with app.test_request_context("/api/codec", method="POST", data="[" * 100_000, content_type="text/plain"):
        assert json_body.json_object() == {}


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32-le"])
@pytest.mark.parametrize("depth", [65, 100_000])
def test_every_route_refuses_a_json_body_nested_too_deep_with_a_400_in_json(app, make_app, depth, encoding, monkeypatch, tmp_path):
    for name in ("CREDENTIAL", "CREDENTIAL_ARTIFACT", "SESSION_METADATA"):
        monkeypatch.setenv(f"FIDO_SERVER_{name}_DIR", str(tmp_path / name.lower()))
    client = make_app().test_client()
    # After an escaped quote, read byte by byte, UTF-16 and UTF-32 look like a string around the brackets.
    body = ('["\\"", "x", ' + "[" * depth + "]" * depth + ', "y"]').encode(encoding)

    # The Simple begins read the body once the username is one they take.
    answers = {
        (method, path): client.open(f"{path}?email=user@example.org", method=method, data=body, content_type="application/json")
        for method, path in _json_routes(app)
    }

    assert len(answers) > 10
    assert {route: (response.status_code, response.get_json()) for route, response in answers.items()} == {
        route: (400, _TOO_DEEP) for route in answers
    }


def test_a_route_refuses_a_string_no_quote_closes_at_its_size_limit_in_well_under_a_second(make_app, monkeypatch, tmp_path):
    for name in ("CREDENTIAL", "CREDENTIAL_ARTIFACT", "SESSION_METADATA"):
        monkeypatch.setenv(f"FIDO_SERVER_{name}_DIR", str(tmp_path / name.lower()))
    app = make_app()
    client = app.test_client()

    for size in (_SECONDS_IF_QUADRATIC, app.config["MAX_CONTENT_LENGTH"]):
        started = time.perf_counter()
        response = client.post("/api/register/begin?email=x", data=_unclosed_string(size), content_type="application/json")
        elapsed = time.perf_counter() - started

        assert (response.status_code, response.get_json()) == (400, _TOO_DEEP)
        assert elapsed < 2, f"{size} bytes answered in {elapsed:.1f} s"
