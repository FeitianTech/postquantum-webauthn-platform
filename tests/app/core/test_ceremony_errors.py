"""Tests for routes/ceremony_errors.py: fido2's findings answered as written, anything else in a sentence."""

from __future__ import annotations

import re

import pytest
from fido2.webauthn import RegistrationResponse

from server.app.routes import ceremony_errors

SENTENCE = ceremony_errors.REGISTRATION_FAILED


@pytest.fixture
def request_context(app):
    with app.test_request_context("/api/register/complete", method="POST"):
        yield


@pytest.mark.parametrize("finding", sorted(ceremony_errors.FIDO2_FINDINGS))
def test_fido2s_findings_are_answered_as_fido2_wrote_them(request_context, finding):
    assert ceremony_errors.answer_text(ValueError(finding), SENTENCE) == finding


def test_a_key_fido2_cannot_verify_with_is_answered_as_fido2_wrote_it(request_context):
    exc = NotImplementedError("Signature verification not supported.")

    assert ceremony_errors.answer_text(exc, SENTENCE) == "Signature verification not supported."


def test_a_response_fido2_cannot_parse_is_answered_with_a_sentence_and_logged_as_its_type_and_place(
    request_context, caplog
):
    with pytest.raises(TypeError) as raised:
        RegistrationResponse.from_dict({})

    with caplog.at_level("INFO", logger=ceremony_errors.__name__):
        text = ceremony_errors.answer_text(raised.value, SENTENCE)

    assert text == "The registration could not be completed."
    assert "required keyword-only" in str(raised.value)
    [record] = caplog.records
    assert (record.levelname, record.exc_info) == ("WARNING", None)
    assert re.fullmatch(r"POST /api/register/complete refused: TypeError at fido2\.[\w.]+:\d+", record.getMessage())


def test_a_refusal_logs_no_text_its_exception_carries(request_context, caplog):
    with caplog.at_level("INFO", logger=ceremony_errors.__name__):
        ceremony_errors.answer_text(ValueError("written by a client: MARKER-7f3a"), SENTENCE)

    assert [record.getMessage() for record in caplog.records] == ["POST /api/register/complete refused: ValueError"]


def test_fido2s_finding_is_logged_as_the_refusals_cause(request_context, caplog):
    with caplog.at_level("INFO", logger=ceremony_errors.__name__):
        ceremony_errors.answer_text(ValueError("Wrong challenge in response."), SENTENCE)

    assert [(record.levelname, record.getMessage()) for record in caplog.records] == [
        ("WARNING", "POST /api/register/complete refused: Wrong challenge in response.")
    ]


@pytest.mark.parametrize(
    "exc",
    [RuntimeError("Wrong challenge in response."), ValueError("a store's own words"), KeyError("rawId")],
    ids=["another-type", "other-text", "key-error"],
)
def test_any_other_exception_is_answered_with_the_sentence(request_context, exc):
    assert ceremony_errors.answer_text(exc, SENTENCE) == SENTENCE
