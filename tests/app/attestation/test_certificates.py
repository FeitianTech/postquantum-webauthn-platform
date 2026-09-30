"""``webauthn.attestation.certificates``: an attestation certificate as the views show it,
and the attestation details a registration response gives."""
from __future__ import annotations

import base64
from types import SimpleNamespace

import pytest

from server.app.webauthn.attestation import certificates as attestation_certificates
from tests.app.characterization import material
from tests.app.security import ceremony_helpers

EC_PUBLIC_KEY_OID = bytes.fromhex("06072a8648ce3d0201")  # id-ecPublicKey
UNKNOWN_KEY_OID = bytes.fromhex("06072a8648ce3d0209")  # 1.2.840.10045.2.9, which nothing names
CERTIFICATE = material.certificate(material.ec_key("certificates-test").public_key(), common_name="Leaf", serial=0x5E)


def _registration_with_x5c(x5c):
    authenticator = ceremony_helpers.Authenticator()
    payload = ceremony_helpers.registration_payload(authenticator, challenge=b"challenge")
    attestation = ceremony_helpers.attestation_object(
        authenticator.authenticator_data(), fmt="packed", att_stmt={"x5c": x5c}
    )
    payload["response"]["attestationObject"] = ceremony_helpers.b64u(attestation)
    return payload


def test_a_certificate_whose_key_cryptography_cannot_load_is_described_from_its_key_info():
    certificate = CERTIFICATE.replace(EC_PUBLIC_KEY_OID, UNKNOWN_KEY_OID)

    serialized = attestation_certificates.serialize_attestation_certificate(certificate)

    assert serialized["publicKeyInfo"] == {"type": "Unknown", "algorithm": {"name": "Unknown", "oid": "1.2.840.10045.2.9"}}
    assert "    Type: Unknown\n    Algorithm OID: 1.2.840.10045.2.9" in serialized["summary"]


def test_each_x5c_entry_is_serialised_or_reported_as_what_went_wrong():
    details = attestation_certificates.extract_attestation_details(
        _registration_with_x5c(["%%%", b"", b"junk", CERTIFICATE])
    )
    fmt, _statement, _attestation, _client_data, _extensions, first, chain = details

    assert fmt == "packed"
    assert first == chain[0] == {"error": "Unable to decode attestation certificate bytes."}
    assert chain[1] == {"error": "Unable to parse attestation certificate."}
    assert chain[2]["error"].startswith("Unable to parse attestation certificate: ")
    assert chain[3]["subject"] == "CN=Leaf,OU=Authenticator Attestation,O=Characterization Test,C=SE"


@pytest.mark.parametrize("response", [["not-a-mapping"], {"not": "a registration"}])
def test_a_response_that_is_no_registration_has_no_attestation_details(response):
    assert attestation_certificates.extract_attestation_details(response) == ("none", {}, None, None, {}, None, [])


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (base64.b64encode(b"\xfb\xef\xbe").decode("ascii"), b"\xfb\xef\xbe"),
        # Standard base64 first, then base64url; each exact, so neither reads a shorter certificate.
        (base64.urlsafe_b64encode(b"\xfb\xef\xbe").decode("ascii").rstrip("="), b"\xfb\xef\xbe"),
        ("not a certificate!", None),
        ({"derBase64": "A"}, None),
        # A PEM body of "@@@" is nothing, not b"" from a decoder that dropped every character.
        ({"pem": "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"}, None),
    ],
)
def test_an_x5c_entry_is_read_from_base64_base64url_or_the_views_own_fields(entry, expected):
    assert attestation_certificates._coerce_attestation_certificate_bytes(entry) == expected


# What cryptography and fido2 never hand over only a direct call reaches.


def test_a_signature_hash_without_a_name_is_named_by_its_class():
    class Sha3Hash:
        pass

    certificate = SimpleNamespace(signature_hash_algorithm=Sha3Hash())

    assert attestation_certificates._signature_hash(certificate) == {"name": "Sha3Hash"}


def test_extension_outputs_that_are_not_a_mapping_are_kept_as_given():
    registration = SimpleNamespace(client_extension_results=["raw-extension"])

    assert attestation_certificates._client_extension_results(registration) == ["raw-extension"]
