"""``decoder.decode.attestation_object``: an attestation object's certificate, as the decoder reads it."""
from __future__ import annotations

import pytest

from server.app.decoder.decode import attestation_object as decode_attestation_object


def test_the_first_x5c_entry_is_serialised_even_when_it_is_not_a_certificate():
    certificate = decode_attestation_object.extract_certificate({"x5c": ["AQI="]})

    assert certificate["error"].startswith("Unable to parse attestation certificate: ")
    assert certificate["raw"] == "0102"


@pytest.mark.parametrize(
    "statement",
    ["not-a-map", {}, {"x5c": []}, {"x5c": ["A"]}, {"x5c": ["%%"]}, {"x5c": [{"not": "bytes"}]}],
)
def test_a_statement_without_a_readable_first_certificate_has_none(statement):
    assert decode_attestation_object.extract_certificate(statement) is None
