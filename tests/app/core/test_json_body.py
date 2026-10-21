"""An API route reads its JSON body only when it is an object (``routes/json_body.py``).

Any other JSON -- a list, a string, a number, true -- is read as an object with
no members, so a route answers what it answers for a missing member, never a
failure of its own. A JSON body nested more than 64 deep is refused, 400 in
JSON, before it is parsed.
"""
from __future__ import annotations

import pytest

from server.app.routes import json_body

# The routes that take no JSON: the metadata upload takes a form, the CSP reports their own type.
_NOT_JSON = {"/api/mds/metadata/upload", "/api/csp-report"}
_TOO_DEEP = {"error": "The request body is JSON nested more than 64 deep, deeper than this server reads."}


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
    ],
    ids=["64 arrays", "65 arrays", "65 objects", "1000 side by side", "in a string", "after an escaped quote", "after a backslash"],
)
def test_json_is_too_deep_past_64_arrays_or_objects_its_strings_set_aside(data, too_deep):
    assert json_body.nested_too_deep(data) is too_deep


def test_a_body_that_does_not_say_it_is_json_is_not_read(app):
    with app.test_request_context("/api/codec", method="POST", data="[" * 100_000, content_type="text/plain"):
        assert json_body.json_object() == {}


@pytest.mark.parametrize("depth", [65, 100_000])
def test_every_route_refuses_a_json_body_nested_too_deep_with_a_400_in_json(app, make_app, depth, monkeypatch, tmp_path):
    for name in ("CREDENTIAL", "CREDENTIAL_ARTIFACT", "SESSION_METADATA"):
        monkeypatch.setenv(f"FIDO_SERVER_{name}_DIR", str(tmp_path / name.lower()))
    client = make_app().test_client()
    body = "[" * depth + "]" * depth

    # The Simple begins read the body once the username is one they take.
    answers = {
        (method, path): client.open(f"{path}?email=user@example.org", method=method, data=body, content_type="application/json")
        for method, path in _json_routes(app)
    }

    assert len(answers) > 10
    assert {route: (response.status_code, response.get_json()) for route, response in answers.items()} == {
        route: (400, _TOO_DEEP) for route in answers
    }
