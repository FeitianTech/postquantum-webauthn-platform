"""An API route reads its JSON body only when it is an object (``routes/json_body.py``).

Any other JSON -- a list, a string, a number, true -- is read as an object with
no members, so a route answers what it answers for a missing member, never a
failure of its own.
"""
from __future__ import annotations

import pytest

# The routes that take no JSON: the metadata upload takes a form, the CSP reports their own type.
_NOT_JSON = {"/api/mds/metadata/upload", "/api/csp-report"}


def _answer(make_app, method, path, body):
    response = make_app().test_client().open(path, method=method, json=body)
    answer = response.get_json()
    # A begin's options hold a fresh challenge: its status and members are the answer.
    return response.status_code, answer.get("error") if isinstance(answer, dict) and "error" in answer else sorted(answer or {})


@pytest.mark.parametrize("body", [["publicKey"], "payload", 7, True])
def test_a_body_that_is_no_object_is_answered_as_one_without_members(app, make_app, body, monkeypatch, tmp_path):
    for name in ("CREDENTIAL", "CREDENTIAL_ARTIFACT", "SESSION_METADATA"):
        monkeypatch.setenv(f"FIDO_SERVER_{name}_DIR", str(tmp_path / name.lower()))
    routes = [
        (method, rule.build({name: "stored-1" for name in rule.arguments}, append_unknown=False)[1])
        for rule in app.url_map.iter_rules()
        if rule.rule.startswith("/api/") and rule.rule not in _NOT_JSON
        for method in sorted(rule.methods & {"POST", "PUT"})
    ]

    differing = [
        (method, path) for method, path in routes if _answer(make_app, method, path, body) != _answer(make_app, method, path, {})
    ]

    assert len(routes) > 10
    assert differing == []
