"""An x5c certificate in one line of facts (``decoder/decode/certificate_summary.py``)."""
from __future__ import annotations

import pytest

from server.app.decoder.decode import certificate_summary
from tests.app.characterization import material

CERTIFICATE = material.certificate(material.ec_key("certificate-summary").public_key(), common_name="Leaf", serial=0x5E)


def test_a_certificate_is_summarised_by_its_names_validity_and_digest():
    summary = certificate_summary.summarize(CERTIFICATE)

    assert summary["subject"] == "CN=Leaf,OU=Authenticator Attestation,O=Characterization Test,C=SE"
    assert summary["issuer"] == "CN=Characterization Test CA"
    assert len(summary["sha256"]) == 64


@pytest.mark.parametrize(
    ("der", "error"),
    [
        pytest.param(b"junk", "not an X.509 certificate: ", id="no-der"),
        # The subject's common name written as an INTEGER: the certificate loads,
        # and its subject is refused only when it is read.
        pytest.param(
            CERTIFICATE.replace(b"\x0c\x04Leaf", b"\x02\x04Leaf"),
            "not an X.509 certificate: error parsing asn1 value",
            id="malformed-subject",
        ),
        pytest.param("text", "a certificate in x5c is a byte string of DER; this is not", id="no-bytes"),
    ],
)
def test_what_is_no_readable_certificate_is_said_so(der, error):
    assert certificate_summary.summarize(der)["error"].startswith(error)
