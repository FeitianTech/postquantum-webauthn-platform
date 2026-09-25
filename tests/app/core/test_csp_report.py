"""POST /api/csp-report: one bounded log line per violation, and nothing else kept."""
from __future__ import annotations

import io
import json
import logging

import pytest

from server.app import csp_reports
from server.app.routes import csp_report

REPORT_URI_BODY = {
    "csp-report": {
        "document-uri": "https://example.test/advanced?user=alice#settings",
        "referrer": "https://referrer.example/?from=mail",
        "violated-directive": "script-src-elem",
        "effective-directive": "script-src-elem",
        "original-policy": "default-src 'self'; script-src 'self'; report-uri /api/csp-report",
        "disposition": "enforce",
        "blocked-uri": "inline",
        "line-number": 12,
        "source-file": "https://example.test/advanced",
        "status-code": 200,
        "script-sample": "alert(document.cookie)",
    }
}

REPORT_TO_BODY = [
    {
        "type": "csp-violation",
        "age": 10,
        "url": "https://example.test/?q=secret",
        "user_agent": "Mozilla/5.0 (Secret-Agent)",
        "body": {
            "documentURL": "https://example.test/?q=secret",
            "blockedURL": "https://user:pw@evil.example/x.js?token=abc#frag",
            "effectiveDirective": "script-src-elem",
            "originalPolicy": "default-src 'self'",
            "disposition": "enforce",
            "sample": "",
            "statusCode": 200,
        },
    },
    {"type": "deprecation", "body": {"id": "Something", "message": "not a CSP report"}},
    {
        "type": "csp-violation",
        "body": {
            "documentURL": "https://example.test/",
            "blockedURL": "trusted-types-sink",
            "effectiveDirective": "require-trusted-types-for",
            "disposition": "report",
            "sample": "Element innerHTML|<img src=x onerror=alert(1)>",
        },
    },
]


@pytest.fixture
def lines(caplog):
    caplog.set_level(logging.WARNING, logger=csp_reports.__name__)

    def read():
        return [record.getMessage() for record in caplog.records if record.name == csp_reports.__name__]

    return read


def post(client, body, content_type="application/csp-report", **kwargs):
    data = body if isinstance(body, (bytes, str)) else json.dumps(body)
    return client.post("/api/csp-report", data=data, content_type=content_type, **kwargs)


def test_a_report_uri_report_is_one_line(client, lines):
    response = post(client, REPORT_URI_BODY)

    assert response.status_code == 204
    assert response.get_data() == b""
    assert lines() == ["CSP violation: directive=script-src-elem blocked=inline path=/advanced"]


def test_a_report_to_batch_logs_each_csp_violation_and_skips_other_reports(client, lines):
    response = post(client, REPORT_TO_BODY, content_type="application/reports+json")

    assert response.status_code == 204
    assert lines() == [
        "CSP violation: directive=script-src-elem blocked=https://evil.example/x.js path=/",
        "CSP violation: directive=require-trusted-types-for blocked=trusted-types-sink(Element.innerHTML) path=/",
    ]


def test_nothing_but_the_three_fields_reaches_the_log(client, lines, caplog):
    post(client, REPORT_URI_BODY)
    post(client, REPORT_TO_BODY, content_type="application/reports+json")

    logged = "\n".join(lines()) + caplog.text
    for kept_out in ("alice", "settings", "referrer", "Secret-Agent", "secret", "token", "user:pw",
                     "frag", "onerror", "alert", "cookie", "original", "line-number"):
        assert kept_out not in logged


def test_plain_json_is_read_too(client, lines):
    assert post(client, REPORT_URI_BODY, content_type="application/json").status_code == 204
    assert len(lines()) == 1


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("effective-directive", "script-src\nCSP violation: directive=forged", "directive=script-src "),
        ("effective-directive", "", "directive=- "),
        ("blocked-uri", "inl\x00ine", "blocked=inl?ine "),
        ("blocked-uri", "data:text/html,<script>alert(1)</script>", "blocked=data: "),
        ("blocked-uri", "chrome-extension://abcdef/inject.js", "blocked=chrome-extension: "),
        ("blocked-uri", "  ", "blocked=- "),
        ("document-uri", "about:blank", "path=about:blank"),
        ("document-uri", "https://example.test/" + "a" * 500, "path=/" + "a" * 199),
        ("document-uri", "https://example.test/paéth", "path=/pa?th"),
    ],
)
def test_each_field_is_cut_to_one_printable_token(client, lines, field, value, expected):
    body = {"csp-report": {**REPORT_URI_BODY["csp-report"], field: value}}
    if field == "effective-directive":
        body["csp-report"].pop("violated-directive")

    post(client, body)

    (line,) = lines()
    assert "\n" not in line
    assert expected in line + " "
    assert len(line) < 3 * csp_reports.FIELD_LIMIT + 60


def test_a_csp2_violated_directive_is_cut_to_its_name(client, lines):
    body = {"csp-report": {"violated-directive": "script-src 'self'", "blocked-uri": "eval",
                           "document-uri": "http://localhost:5000/"}}

    post(client, body)

    assert lines() == ["CSP violation: directive=script-src blocked=eval path=/"]


def test_a_report_over_the_limit_is_refused_unread(client, lines):
    big = b'{"csp-report": {"blocked-uri": "' + b"x" * csp_report.MAX_REPORT_BYTES + b'"}}'

    response = post(client, big)

    assert response.status_code == 413
    assert response.get_json() == {
        "error": f"The request is larger than the limit of {csp_report.MAX_REPORT_BYTES} bytes this server accepts."
    }
    assert lines() == [f"CSP report refused: larger than {csp_report.MAX_REPORT_BYTES} bytes"]


def test_a_chunked_report_over_the_limit_is_refused(client, lines):
    big = io.BytesIO(b"[" + b" " * (csp_report.MAX_REPORT_BYTES + 10) + b"]")

    # No Content-Length: gunicorn marks a chunked body terminated, as here.
    response = client.post(
        "/api/csp-report",
        input_stream=big,
        content_type="application/reports+json",
        headers={"Transfer-Encoding": "chunked"},
        environ_overrides={"wsgi.input_terminated": True},
    )

    assert response.status_code == 413
    assert lines() == [f"CSP report refused: larger than {csp_report.MAX_REPORT_BYTES} bytes"]


@pytest.mark.parametrize(
    ("body", "content_type", "status"),
    [
        (REPORT_URI_BODY, "text/plain", 415),
        (REPORT_URI_BODY, "application/x-www-form-urlencoded", 415),
        (b"{not json", "application/csp-report", 400),
        ({"not": "a report"}, "application/csp-report", 400),
        ("42", "application/json", 400),
    ],
)
def test_what_is_not_a_report_is_answered_and_not_logged(client, lines, body, content_type, status):
    response = post(client, body, content_type=content_type)

    assert response.status_code == status
    assert "error" in response.get_json()
    assert lines() == []


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_a_flood_logs_the_burst_then_says_how_many_it_dropped(app, lines):
    clock = _Clock()
    app.extensions[csp_report.LOG_EXTENSION] = csp_reports.ViolationLog(clock=clock)
    client = app.test_client()

    for _ in range(csp_reports.BURST + 12):
        assert post(client, REPORT_URI_BODY).status_code == 204

    assert len(lines()) == csp_reports.BURST
    assert set(lines()) == {"CSP violation: directive=script-src-elem blocked=inline path=/advanced"}

    clock.now += 2  # one line's worth at 30 a minute
    post(client, REPORT_URI_BODY)

    assert lines()[csp_reports.BURST:] == [
        "CSP violation reports dropped over the rate limit: 12",
        "CSP violation: directive=script-src-elem blocked=inline path=/advanced",
    ]


def test_a_large_batch_logs_its_first_hundred_and_counts_the_rest(app, lines):
    clock = _Clock()
    app.extensions[csp_report.LOG_EXTENSION] = csp_reports.ViolationLog(burst=500, per_minute=30, clock=clock)
    batch = [REPORT_TO_BODY[0]] * (csp_report.MAX_VIOLATIONS_PER_REQUEST + 5)

    response = post(app.test_client(), batch, content_type="application/reports+json")

    assert response.status_code == 204
    assert len(lines()) == csp_report.MAX_VIOLATIONS_PER_REQUEST
    post(app.test_client(), REPORT_URI_BODY)
    assert lines()[csp_report.MAX_VIOLATIONS_PER_REQUEST] == "CSP violation reports dropped over the rate limit: 5"


def test_each_app_keeps_its_own_limit(make_app):
    first, second = make_app(), make_app()

    assert isinstance(first.extensions[csp_report.LOG_EXTENSION], csp_reports.ViolationLog)
    assert first.extensions[csp_report.LOG_EXTENSION] is not second.extensions[csp_report.LOG_EXTENSION]


def test_a_chunked_report_within_the_limit_is_read(client, lines):
    response = client.post(
        "/api/csp-report",
        input_stream=io.BytesIO(json.dumps(REPORT_URI_BODY).encode()),
        content_type="application/csp-report",
        headers={"Transfer-Encoding": "chunked"},
        environ_overrides={"wsgi.input_terminated": True},
    )

    assert response.status_code == 204
    assert len(lines()) == 1


def test_a_report_needs_no_session_or_token(client):
    response = post(client, REPORT_URI_BODY)

    assert response.status_code == 204
    assert "Set-Cookie" not in response.headers
