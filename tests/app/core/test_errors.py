"""Tests for routes/errors.py: HTTP errors under /api/ answered in JSON, pages left as they are."""

from __future__ import annotations

import logging
from urllib.parse import quote

import pytest
from flask import abort

from server.app.routes import errors, json_body
from tests.app.log_lines import FORGED, one_line_naming


def _failing_view():
    raise RuntimeError("a route that fails")


@pytest.fixture
def api_client(make_app):
    app = make_app({"PROPAGATE_EXCEPTIONS": False})
    app.add_url_rule("/api/test-abort/<int:code>", "test_abort", lambda code: abort(code))
    app.add_url_rule("/api/test-failure", "test_failure", _failing_view)
    return app.test_client()


@pytest.mark.parametrize("method", ["get", "post", "put", "delete"])
@pytest.mark.parametrize("path", ["/api", "/api/", "/api/nothing-here", "/api/mds/nothing-here"])
def test_a_path_no_api_route_holds_answers_404_in_json_whatever_the_method(api_client, method, path):
    response = getattr(api_client, method)(path)

    assert response.status_code == 404
    assert response.get_json() == {"error": "There is nothing at this address."}


@pytest.mark.parametrize(
    ("method", "path", "allowed"),
    [
        ("post", "/api/mds/metadata/info", "GET, HEAD, OPTIONS"),
        ("get", "/api/codec", "OPTIONS, POST"),
        ("put", "/api/codec", "OPTIONS, POST"),
    ],
)
def test_a_method_an_api_route_does_not_take_answers_405_in_json_naming_those_it_does(api_client, method, path, allowed):
    response = getattr(api_client, method)(path)

    assert response.status_code == 405
    assert response.get_json() == {"error": "This address does not take this method."}
    assert response.headers["Allow"] == allowed


@pytest.mark.parametrize(
    ("code", "sentence"),
    [
        (400, "The server could not read this request."),
        (404, "There is nothing at this address."),
        (409, "The server refused this request (409 Conflict)."),
    ],
)
def test_an_abort_under_api_answers_its_status_in_json(api_client, code, sentence):
    response = api_client.get(f"/api/test-abort/{code}")

    assert response.status_code == code
    assert response.mimetype == "application/json"
    assert response.get_json() == {"error": sentence}


def test_an_api_routes_own_404_stays_a_404(api_client):
    response = api_client.get("/api/mds/metadata/custom/nothing.json/icon")

    assert response.status_code == 404
    assert response.get_json() == {"error": "There is nothing at this address."}


def test_an_unhandled_exception_under_api_answers_500_in_json(api_client):
    response = api_client.get("/api/test-failure")

    assert response.status_code == 500
    assert response.get_json() == {"error": "The server failed while handling this request."}


@pytest.mark.parametrize(("method", "path", "status"), [("get", "/assets/mds/icons/nothing.png", 404), ("post", "/", 405)])
def test_a_page_keeps_werkzeugs_html(api_client, method, path, status):
    response = getattr(api_client, method)(path)

    assert response.status_code == status
    assert response.mimetype == "text/html"


def test_the_nesting_refusal_keeps_its_own_sentence(api_client):
    nested = b"[" * (json_body.MAX_DEPTH + 1) + b"]" * (json_body.MAX_DEPTH + 1)

    response = api_client.post("/api/codec", data=nested, content_type="application/json")

    assert response.status_code == 400
    assert "nested more than 64 deep" in response.get_json()["error"]


def test_the_value_count_refusal_keeps_its_own_sentence(api_client):
    many = b"[" + b"0," * json_body.MAX_VALUES + b"0]"

    response = api_client.post("/api/codec", data=many, content_type="application/json")

    assert response.status_code == 400
    assert "more than 100,000 values" in response.get_json()["error"]


_ARTIFACT = "/api/advanced/credential-artifacts/"
# A body each refusal that logs its request's path is given, and how its line starts.
_REFUSED_BODIES = {
    "not-strict": (b"[NaN]", "Refused a JSON body holding NaN in PUT "),
    "nested": (b"[" * (json_body.MAX_DEPTH + 1), "Refused a JSON body nested too deep in PUT "),
    "too-many-values": (b"[" + b"0," * json_body.MAX_VALUES + b"0]", "Refused a JSON body holding too many values in PUT "),
    "oversized": (b"[" + b" " * (9 * 1024 * 1024) + b"]", "Refused an oversized body in PUT "),
}


@pytest.mark.parametrize("refusal", sorted(_REFUSED_BODIES))
def test_a_refused_request_s_path_is_logged_on_one_line_however_it_was_sent(api_client, caplog, refusal):
    body, start = _REFUSED_BODIES[refusal]

    with caplog.at_level(logging.WARNING, logger=errors.__name__):
        response = api_client.put(_ARTIFACT + quote(FORGED), data=body, content_type="application/json")

    assert response.status_code in (400, 413)
    assert one_line_naming(caplog, errors.__name__, _ARTIFACT + FORGED).startswith(f"{start}'{_ARTIFACT}x\\nERROR")


def test_a_refused_request_s_ordinary_path_is_logged_as_it_was(api_client, caplog):
    with caplog.at_level(logging.WARNING, logger=errors.__name__):
        api_client.put(_ARTIFACT + "abc_123", data=b"[NaN]", content_type="application/json")

    assert [record.getMessage() for record in caplog.records if record.name == errors.__name__] == [
        f"Refused a JSON body holding NaN in PUT {_ARTIFACT}abc_123"
    ]
