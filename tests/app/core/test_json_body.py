"""An API route reads its JSON body only when it is an object (``routes/json_body.py``).

Any other JSON -- a list, a string, a number, true -- is read as an object with
no members, so a route answers what it answers for a missing member, never a
failure of its own. A JSON body nested more than 64 deep, or holding more than
100,000 values, is refused, 400 in JSON, before it is parsed, by a scan linear in
the body's length. A body over 256 KiB is worked on two at a time: a third is told
to try again (503), and a place is given back however its request ends.
"""
from __future__ import annotations

import time
import tracemalloc

import pytest
from flask import abort

from server.app.config import request_limits
from server.app.routes import json_body

# The routes that take no JSON: the metadata upload takes a form, the CSP reports their own type.
_NOT_JSON = {"/api/mds/metadata/upload", "/api/csp-report"}
_TOO_DEEP = {"error": "The request body is JSON nested more than 64 deep, deeper than this server reads."}
_TOO_MANY = {"error": "The request body is JSON holding more than 100,000 values, more than this server reads."}
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


def _array(count):
    """JSON text of an array holding ``count`` values in all: itself and ``count - 1`` numbers."""

    return "[" + "0," * (count - 2) + "0]"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32-le"])
@pytest.mark.parametrize(
    ("text", "too_many"),
    [
        (_array(100_000), False),
        (_array(100_001), True),
        ('["' + "[{," * 100_000 + '", 1]', False),
        ('["\\"' + ", 0" * 100_000 + '"]', False),
        ('["\\\\"' + ", 0" * 100_000 + "]", True),
    ],
    ids=["100,000 values", "100,001 values", "in a string", "after an escaped quote", "after a backslash"],
)
def test_a_body_holding_more_than_100000_values_is_refused_its_strings_set_aside(app, text, too_many, encoding):
    with app.test_request_context("/api/codec", method="POST", data=text.encode(encoding), content_type="application/json"):
        if too_many:
            with pytest.raises(json_body.TooManyValues):
                json_body.json_object()
        else:
            assert json_body.json_object() == {}


@pytest.mark.parametrize("body", [_array(10), "[" + "[]," * 100 + "[]]"], ids=["few brackets", "past the depth's quick count"])
def test_a_reader_with_a_cap_of_its_own_is_given_the_count_it_was_held_to(body):
    counted = body.count("[") + body.count(",")

    assert json_body.check_limits(body.encode(), max_values=counted + 1) == counted
    with pytest.raises(json_body.TooManyValues):
        json_body.check_limits(body.encode(), max_values=counted)
    assert json_body.check_limits(("[" * 100).encode("utf-16-be") + b"\x00", max_values=1) == 0


@pytest.mark.parametrize(
    ("start", "unit", "end"),
    [(b'["', b'\\",', b""), (b'["', b",", b""), (b"[", b'"",', b"0]"), (b"[", b'"\\"",', b"0]")],
    ids=["escaped quotes and commas no quote closes", "commas no quote closes", "empty strings", "strings of an escaped quote"],
)
def test_a_body_of_commas_and_strings_is_counted_in_time_linear_in_the_body(start, unit, end):
    for size in (_SECONDS_IF_QUADRATIC, 8 * 1024 * 1024):
        body = start + unit * ((size - len(start) - len(end)) // len(unit)) + end

        started = time.perf_counter()
        try:
            json_body.check_limits(body)
        except json_body.TooManyValues:
            pass
        elapsed = time.perf_counter() - started

        # Room for a slow, loaded machine: a scan that is not linear takes hours at 8 MiB.
        assert elapsed < 20, f"{size} bytes scanned in {elapsed:.1f} s"


def test_every_route_refuses_a_json_body_holding_more_than_100000_values_with_a_400_in_json(app, make_app, monkeypatch, tmp_path):
    for name in ("CREDENTIAL", "CREDENTIAL_ARTIFACT", "SESSION_METADATA"):
        monkeypatch.setenv(f"FIDO_SERVER_{name}_DIR", str(tmp_path / name.lower()))
    client = make_app().test_client()
    body = ('{"publicKey": ' + _array(100_001) + "}").encode()

    # The Simple begins read the body once the username is one they take.
    answers = {
        (method, path): client.open(f"{path}?email=user@example.org", method=method, data=body, content_type="application/json")
        for method, path in _json_routes(app)
    }

    assert len(answers) > 10
    assert {route: (response.status_code, response.get_json()) for route, response in answers.items()} == {
        route: (400, _TOO_MANY) for route in answers
    }


def test_a_route_refuses_8_mib_of_empty_objects_in_memory_far_below_what_parsing_takes(make_app, monkeypatch, tmp_path):
    for name in ("CREDENTIAL", "CREDENTIAL_ARTIFACT", "SESSION_METADATA"):
        monkeypatch.setenv(f"FIDO_SERVER_{name}_DIR", str(tmp_path / name.lower()))
    client = make_app().test_client()
    # Parsed, these 8 MiB took 210 MiB.
    body = b"[" + b"{}," * ((8 * 1024 * 1024 - 3) // 3) + b"0]"

    tracemalloc.start()
    try:
        response = client.post("/api/advanced/credential-artifacts/bulk", data=body, content_type="application/json")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert (response.status_code, response.get_json()) == (400, _TOO_MANY)
    assert peak < 40 * 1024 * 1024


def test_a_body_that_does_not_say_it_is_json_is_not_read(app):
    with app.test_request_context("/api/codec", method="POST", data="[" * 100_000, content_type="text/plain"):
        assert json_body.json_object() == {}


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32-le"])
@pytest.mark.parametrize("depth", [65, 100_000])
def test_every_route_refuses_a_json_body_nested_too_deep_with_a_400_in_json(app, make_app, depth, encoding, monkeypatch, tmp_path):
    for name in ("CREDENTIAL", "CREDENTIAL_ARTIFACT", "SESSION_METADATA"):
        monkeypatch.setenv(f"FIDO_SERVER_{name}_DIR", str(tmp_path / name.lower()))
    # The Simple registration's complete reads at most 256 KiB, less than the deepest bodies here
    # in UTF-16 or UTF-32: given the general limit, every route reads them.
    client = make_app({request_limits.REGISTRATION_RESPONSE_LIMIT_KEY: request_limits.DEFAULT_MAX_REQUEST_BYTES}).test_client()
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


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_every_route_refuses_nan_and_infinity_with_a_400_in_json(app, make_app, constant, monkeypatch, tmp_path):
    for name in ("CREDENTIAL", "CREDENTIAL_ARTIFACT", "SESSION_METADATA"):
        monkeypatch.setenv(f"FIDO_SERVER_{name}_DIR", str(tmp_path / name.lower()))
    client = make_app().test_client()
    body = '{"publicKey": {"extensions": {"x": [1, %s]}}, "payload": "a"}' % constant

    # The Simple begins read the body once the username is one they take.
    answers = {
        (method, path): client.open(f"{path}?email=user@example.org", method=method, data=body, content_type="application/json")
        for method, path in _json_routes(app)
    }

    sentence = f"The request body holds {constant}, which is not JSON: RFC 8259 has no NaN or Infinity."
    assert len(answers) > 10
    assert {route: (response.status_code, response.get_json()) for route, response in answers.items()} == {
        route: (400, {"error": sentence}) for route in answers
    }


@pytest.mark.parametrize(
    ("data", "body"),
    [
        (b'{"a": "NaN", "b": "Infinity"}', {"a": "NaN", "b": "Infinity"}),
        (b'{"a": 1e308, "b": -1e-400}', {"a": 1e308, "b": -0.0}),
        (b"{not json", {}),
        (("[0," * 100_000).encode("utf-16-be") + b"\x00", {}),
    ],
    ids=["the words in strings", "numbers a double holds", "malformed", "undecodable"],
)
def test_strings_and_finite_numbers_are_read_and_malformed_json_as_no_members(app, data, body):
    with app.test_request_context("/api/codec", method="POST", data=data, content_type="application/json"):
        assert json_body.json_object() == body


@pytest.mark.parametrize("number", ["1e400", "-1.5e999"])
def test_a_number_too_large_for_a_double_is_refused_not_read_as_infinity(client, number):
    response = client.post("/api/codec", data='{"payload": %s}' % number, content_type="application/json")

    assert response.status_code == 400
    assert response.get_json() == {"error": f"The request body holds {number}, a number too large to read."}


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


_BUSY = {"error": "The server is reading other large requests: try again in a few seconds."}


def _object_of(size):
    """A JSON object of exactly ``size`` bytes."""

    body = b'{"pad":"' + b"x" * (size - 10) + b'"}'
    assert len(body) == size
    return body


def _free_places():
    """How many of the large bodies' places no request holds."""

    taken = 0
    while json_body._LARGE_BODIES.acquire(blocking=False):
        taken += 1
    for _ in range(taken):
        json_body._LARGE_BODIES.release()
    return taken


@pytest.fixture
def places_held(monkeypatch):
    """Both places held by the test, and a large body told at once that none is free."""

    monkeypatch.setattr(json_body, "_WAIT_SECONDS", 0)
    assert json_body._LARGE_BODIES.acquire(blocking=False)
    assert json_body._LARGE_BODIES.acquire(blocking=False)
    yield
    json_body._LARGE_BODIES.release()
    json_body._LARGE_BODIES.release()


def test_every_route_refuses_a_large_body_with_a_503_while_two_are_read(app, own_stores, places_held):
    client = app.test_client()
    body = _object_of(json_body.LARGE_BODY_BYTES + 1)

    # The Simple begins read the body once the username is one they take.
    answers = {
        (method, path): client.open(f"{path}?email=user@example.org", method=method, data=body, content_type="application/json")
        for method, path in _json_routes(app)
    }

    # A Simple registration's whole body is held to 256 KiB, so none is large (config/request_limits.py).
    too_large = answers.pop(("POST", "/api/register/complete"))
    assert ("POST", "/api/codec") in answers and ("POST", "/api/advanced/authenticate/begin") in answers
    assert {route: (response.status_code, response.headers.get("Retry-After"), response.get_json()) for route, response in answers.items()} == {
        route: (503, "5", _BUSY) for route in answers
    }
    assert too_large.status_code == 413


def test_a_body_up_to_the_threshold_is_answered_while_both_places_are_held(client, places_held):
    at_threshold = client.post("/api/codec", data=_object_of(json_body.LARGE_BODY_BYTES), content_type="application/json")
    one_byte_more = client.post("/api/codec", data=_object_of(json_body.LARGE_BODY_BYTES + 1), content_type="application/json")

    assert (at_threshold.status_code, at_threshold.get_json()) == (400, {"error": "Codec payload must be a non-empty string."})
    assert one_byte_more.status_code == 503


@pytest.mark.parametrize("reads", [1, 2])
def test_a_large_body_holds_one_place_until_its_request_ends_however_often_it_is_read(app, reads):
    body = _object_of(json_body.LARGE_BODY_BYTES + 1)

    with app.test_request_context("/api/codec", method="POST", data=body, content_type="application/json"):
        for _ in range(reads):
            assert json_body.json_object() == {"pad": "x" * (len(body) - 10)}
        held = _free_places()

    assert (held, _free_places()) == (1, 2)


def test_a_body_at_the_threshold_takes_no_place(app):
    with app.test_request_context("/api/codec", method="POST", data=_object_of(json_body.LARGE_BODY_BYTES), content_type="application/json"):
        json_body.json_object()
        assert _free_places() == 2


def _read_then(ending):
    def view():
        json_body.json_object()
        ending()

    return view


def _conflict():
    abort(409)


def _fail():
    raise RuntimeError("unexpected")


def test_the_place_is_given_back_after_an_answer(client):
    response = client.post("/api/codec", data=_object_of(json_body.LARGE_BODY_BYTES + 1), content_type="application/json")

    assert response.status_code == 400
    assert _free_places() == 2


def test_the_place_is_given_back_after_an_http_error_the_route_raises(make_app):
    app = make_app()
    app.add_url_rule("/api/read-then-conflict", view_func=_read_then(_conflict), methods=["POST"])

    response = app.test_client().post("/api/read-then-conflict", data=_object_of(json_body.LARGE_BODY_BYTES + 1), content_type="application/json")

    assert response.status_code == 409
    assert _free_places() == 2


@pytest.mark.parametrize("testing", [True, False])
def test_the_place_is_given_back_after_an_unhandled_exception(make_app, testing):
    app = make_app({"TESTING": testing})
    app.add_url_rule("/api/read-then-fail", view_func=_read_then(_fail), methods=["POST"])
    client = app.test_client()
    body = _object_of(json_body.LARGE_BODY_BYTES + 1)

    # Raised to the caller while testing; answered 500, as in production, otherwise.
    if testing:
        with pytest.raises(RuntimeError):
            client.post("/api/read-then-fail", data=body, content_type="application/json")
    else:
        assert client.post("/api/read-then-fail", data=body, content_type="application/json").status_code == 500
    assert _free_places() == 2
