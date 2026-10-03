"""Attestation statements are interpreted per format (WebAuthn L3 section 8), not verified.

Real device vectors: packed, tpm, android-safetynet, fido-u2f, apple and none
(python-fido2's tests/attestation/test_attestation.py), and the CTAP
makeCredential response from its tests/ctap2/test_ctap2.py. android-key and packed
self-attestation are WebAuthn L3 section 16's published vectors. compound is
assembled here from the real packed and tpm statements; the spec publishes no
compound vector.
"""
from __future__ import annotations

import base64
import json

import cbor2
import pytest
from cryptography import x509

from server.app.decoder.decode import attestation_statement
from server.app.decoder.decode.text import decode_payload_text
from tests.app.characterization import material
from tests.app.decoder.real_vectors import (
    ANDROID_SAFETYNET_ATT_STMT,
    ANDROID_SAFETYNET_AUTH_DATA,
    APPLE_ATT_STMT,
    APPLE_AUTH_DATA,
    FIDO_U2F_ATT_STMT,
    FIDO_U2F_AUTH_DATA,
    GET_ASSERTION_RESPONSE,
    MAKE_CREDENTIAL_RESPONSE,
    NONE_ATT_STMT,
    NONE_AUTH_DATA,
    PACKED_ATT_STMT,
    PACKED_AUTH_DATA,
    TPM_WINDOWS_HELLO_ATT_STMT,
    TPM_WINDOWS_HELLO_AUTH_DATA,
    WEBAUTHN_L3_ANDROID_KEY_ATTESTATION_OBJECT,
    WEBAUTHN_L3_ANDROID_KEY_CLIENT_DATA_JSON,
    WEBAUTHN_L3_PACKED_SELF_ATTESTATION_OBJECT,
    attestation_object,
)

_NOT_VERIFIED = attestation_statement.NOT_VERIFIED


def _statement(data: bytes) -> dict:
    result = decode_payload_text(data.hex())
    assert result["type"] == "Attestation object"
    return result["data"]["attestationStatementDecoded"]


def test_packed_with_a_certificate_chain():
    view = _statement(attestation_object("packed", PACKED_ATT_STMT, PACKED_AUTH_DATA))

    assert (view["fmt"], view["known"], view["spec"]) == ("packed", True, "WebAuthn L3 section 8.2")
    assert view["attestationTypesSupported"] == "Basic, Self, AttCA"
    assert view["verification"] == _NOT_VERIFIED
    assert "sig over authenticatorData || clientDataHash" in view["notChecked"]
    fields = view["fields"]
    assert fields["alg"] == {"value": -7, "name": "ES256 (ECDSA)"}
    assert fields["sig"]["length"] == 71
    assert fields["x5c"]["count"] == 1
    assert "CN=Yubico" in fields["x5c"]["certificates"][0]["subject"]
    assert fields["attestationType"].startswith("Basic or AttCA")
    assert "notInSyntax" not in view and "missing" not in view


def test_packed_self_attestation_shows_both_algorithms():
    view = _statement(WEBAUTHN_L3_PACKED_SELF_ATTESTATION_OBJECT)
    fields = view["fields"]

    assert fields["attestationType"] == "Self (no x5c): sig is made with the credential private key"
    assert fields["alg"] == fields["credentialPublicKeyAlg"] == {"value": -7, "name": "ES256 (ECDSA)"}
    assert fields["note"].endswith("shown, not compared")


def test_tpm_decodes_cert_info_and_pub_area():
    view = _statement(attestation_object("tpm", TPM_WINDOWS_HELLO_ATT_STMT, TPM_WINDOWS_HELLO_AUTH_DATA))
    fields = view["fields"]

    assert view["spec"] == "WebAuthn L3 section 8.3"
    # This capture carries no ver, which section 8.3's syntax requires ("2.0").
    assert view["missing"] == {"members": ["ver"], "note": "section 8.3's attStmt syntax requires them; absent here"}
    assert fields["alg"] == {"value": -65535, "name": "RS1 (RSA)"}
    assert fields["sig"]["length"] == 256
    assert fields["x5c"]["count"] == 2
    assert fields["certInfo"]["type"]["meaning"] == "TPM_ST_ATTEST_CERTIFY"
    assert fields["pubArea"]["parameters"]["keyBits"] == 2048
    assert "certInfo.attested.name = pubArea's Name" in view["notChecked"]


def test_a_truncated_cert_info_is_a_finding_located_in_the_input():
    statement = {**TPM_WINDOWS_HELLO_ATT_STMT, "certInfo": TPM_WINDOWS_HELLO_ATT_STMT["certInfo"][:50]}
    data = attestation_object("tpm", statement, TPM_WINDOWS_HELLO_AUTH_DATA)

    result = decode_payload_text(data.hex())
    (finding,) = [finding for finding in result["findings"] if finding["code"] == "tpm-structure"]

    assert finding["path"] == '${"attStmt"}{"certInfo"}'
    assert finding["offset"] == data.index(statement["certInfo"]) + 44
    assert finding["message"] == "certInfo.extraData needs 20 byte(s); 6 remain at offset 44"
    assert result["data"]["attestationStatementDecoded"]["fields"]["certInfo"]["error"]["offset"] == 44
    # A structure in the input that does not parse: malformed, as a PublicKeyCredential field's parse-error is.
    assert finding["category"] == "malformed"
    assert finding["message"] in result["malformed"]


def test_android_key_decodes_the_key_description():
    view = _statement(WEBAUTHN_L3_ANDROID_KEY_ATTESTATION_OBJECT)
    description = view["fields"]["keyDescription"]

    assert view["spec"] == "WebAuthn L3 section 8.4"
    assert description["attestationVersion"]["value"] == 300
    assert description["hardwareEnforced"]["purpose"]["meanings"] == ["SIGN"]
    assert "attestationChallenge = clientDataHash" in view["notChecked"]


def test_android_safetynet_is_marked_deprecated_and_not_verified():
    view = _statement(attestation_object("android-safetynet", ANDROID_SAFETYNET_ATT_STMT, ANDROID_SAFETYNET_AUTH_DATA))
    fields = view["fields"]

    assert fields["ver"]["value"] == "14574037"
    assert fields["response"]["verification"].startswith("NOT VERIFIED")
    assert fields["deprecated"].endswith("deprecated and expected to be removed")
    assert fields["response"]["header"]["json"]["alg"] == "RS256"


def test_fido_u2f_names_its_key_and_counts_its_certificates():
    view = _statement(attestation_object("fido-u2f", FIDO_U2F_ATT_STMT, FIDO_U2F_AUTH_DATA))

    assert view["fields"]["attestnCertKey"] == "EC secp256r1 (section 8.6 requires P-256; shown, not judged)"
    assert view["fields"]["x5c"]["count"] == 1

    two = {**FIDO_U2F_ATT_STMT, "x5c": FIDO_U2F_ATT_STMT["x5c"] * 2}
    noted = _statement(attestation_object("fido-u2f", two, FIDO_U2F_AUTH_DATA))
    assert noted["fields"]["x5c"]["note"] == "section 8.6: x5c holds exactly one certificate; this holds 2"


def test_fido_u2f_names_a_certificate_key_that_is_not_p256_or_cannot_be_read():
    ed25519_certificate = material.certificate(material.ed25519_key("u2f-ed25519").public_key(), common_name="U2F", serial=8)
    auth_data = bytes(32) + b"\x01" + bytes(4)

    other = _statement(attestation_object("fido-u2f", {"sig": b"\x00", "x5c": [ed25519_certificate]}, auth_data))
    unreadable = _statement(attestation_object("fido-u2f", {"sig": b"\x00", "x5c": [b"\x00"]}, auth_data))

    assert other["fields"]["attestnCertKey"] == "Ed25519PublicKey (section 8.6 requires an EC P-256 key; shown, not judged)"
    assert unreadable["fields"]["attestnCertKey"] == "unreadable"
    assert unreadable["fields"]["x5c"]["certificates"][0]["error"].startswith("not an X.509 certificate: ")


def test_a_tpm_statement_holding_only_its_version_names_what_it_lacks():
    statement = _statement(attestation_object("tpm", {"ver": "2.0"}, bytes(32) + b"\x01" + bytes(4)))

    assert statement["fields"] == {"ver": "2.0"}
    assert statement["missing"]["members"] == ["alg", "x5c", "sig", "certInfo", "pubArea"]


def test_an_android_key_description_of_the_wrong_shapes_shows_each_error_and_the_rest():
    # version as an OCTET STRING, softwareEnforced as an INTEGER, and in teeEnforced an
    # algorithm the schema does not name (99), an application id that is no DER (00),
    # and a brand that is no UTF-8 (ff).
    description = bytes.fromhex(
        "302c0401000a01010201030a010104040000000004000201003013a203020163bf854503040100bf8546030401ff"
    )
    key_description = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), description)
    leaf = material.certificate(
        material.ec_key("android-key-shapes").public_key(), common_name="Android", serial=9, extensions=[(key_description, False)]
    )

    statement = _statement(attestation_object("android-key", {"alg": -7, "sig": b"\x00", "x5c": [leaf]}, bytes(32) + b"\x01" + bytes(4)))
    read = statement["fields"]["keyDescription"]

    assert [error["field"] for error in read["errors"]] == [
        "attestationVersion",
        "softwareEnforced",
        "teeEnforced.attestationApplicationId",
    ]
    assert read["teeEnforced"] == {
        "algorithm": {"value": 99, "meaning": "not a value the schema names"},
        "attestationApplicationId": {"hex": "00"},
        "attestationIdBrand": {"hex": "ff"},
    }
    assert read["keymasterVersion"] == {"value": 3, "meaning": "Keymaster version 3.0"}


def test_apple_decodes_the_nonce_and_keeps_what_is_not_in_its_syntax():
    view = _statement(attestation_object("apple", APPLE_ATT_STMT, APPLE_AUTH_DATA))

    assert view["attestationTypesSupported"] == "Anonymization CA"
    assert view["fields"]["nonce"]["length"] == 32
    # The real statement carries alg, which section 8.8's syntax does not have.
    assert view["notInSyntax"] == {"members": {"alg": -7}, "note": "not in section 8.8's attStmt syntax; shown as sent"}


def test_none_is_an_empty_map_and_says_so_when_it_is_not():
    view = _statement(attestation_object("none", NONE_ATT_STMT, NONE_AUTH_DATA))
    assert (view["fields"], view["notChecked"]) == ({}, [])

    noted = _statement(attestation_object("none", {"x": 1}, NONE_AUTH_DATA))
    assert noted["fields"]["note"] == "section 8.7: attStmt is an empty map; this one has 1 member(s)"
    assert noted["notInSyntax"]["members"] == {"x": 1}


def test_compound_decodes_each_statement():
    statements = [
        {"fmt": "packed", "attStmt": PACKED_ATT_STMT},
        {"fmt": "tpm", "attStmt": TPM_WINDOWS_HELLO_ATT_STMT},
    ]

    view = _statement(attestation_object("compound", statements, PACKED_AUTH_DATA))

    assert view["spec"] == "WebAuthn L3 section 8.9"
    assert [statement["fmt"] for statement in view["statements"]] == ["packed", "tpm"]
    assert view["statements"][1]["fields"]["certInfo"]["magic"]["meaning"] == "TPM_GENERATED_VALUE"
    assert "note" not in view


def test_compound_shapes_the_syntax_does_not_allow_are_noted():
    one = _statement(attestation_object("compound", [{"fmt": "none", "attStmt": {}}], NONE_AUTH_DATA))
    assert one["note"] == "section 8.9: [2* nonCompoundAttStmt], at least two statements; this has 1"

    nested = _statement(
        attestation_object("compound", [{"fmt": "compound", "attStmt": []}, "not a map"], NONE_AUTH_DATA)
    )
    assert nested["statements"][0]["note"].startswith("section 8.9: a compound statement's statements are not compound")
    assert nested["statements"][1] == {"value": "not a map", "note": "each statement is a map with fmt and attStmt"}


def test_an_unknown_format_is_shown_as_sent():
    view = _statement(attestation_object("vendor-format", {"blob": b"\x01"}, NONE_AUTH_DATA))

    assert view == {
        "fmt": "vendor-format",
        "known": False,
        "meaning": "not an attestation statement format WebAuthn L3 section 8 defines; shown as sent",
        "attStmt": {"blob": "01"},
    }


def test_statement_members_of_the_wrong_shape_are_shown_as_sent():
    view = attestation_statement.interpret("packed", ["not", "a", "map"])
    assert view["note"] == "section 8.2 defines attStmt as a map; this is not"

    fields = attestation_statement.interpret("tpm", {"certInfo": "text", "x5c": "text", "alg": "RS1", "sig": 5})["fields"]
    assert fields["certInfo"] == {"value": "text", "note": "certInfo is a byte string; this is not"}
    assert fields["x5c"]["note"] == "x5c is an array of DER certificates; this is not"
    assert (fields["alg"], fields["sig"]) == ("RS1", 5)
    assert attestation_statement.interpret("compound", {"x": 1})["note"] == (
        "section 8.9 defines attStmt as an array of statements"
    )


def test_a_ctap_make_credential_response_carries_its_statement():
    result = decode_payload_text("00" + MAKE_CREDENTIAL_RESPONSE.hex())

    assert result["data"]["attestationStatementDecoded"]["fmt"] == "packed"
    assert result["data"]["attestationStatementDecoded"]["fields"]["x5c"]["count"] == 1


def test_a_compound_ctap_make_credential_response_is_read_as_one():
    statements = [{"fmt": "none", "attStmt": {}}, {"fmt": "packed", "attStmt": PACKED_ATT_STMT}]
    data = b"\x00" + cbor2.dumps({1: "compound", 2: PACKED_AUTH_DATA, 3: statements})

    result = decode_payload_text(data.hex())

    assert result["type"] == "CBOR (SUCCESS status; MakeCredential response)"
    assert [statement["fmt"] for statement in result["data"]["attestationStatementDecoded"]["statements"]] == [
        "none",
        "packed",
    ]


def test_an_assertion_has_no_statement():
    assert "attestationStatementDecoded" not in decode_payload_text("00" + GET_ASSERTION_RESPONSE.hex())["data"]


def _credential(attestation: bytes) -> str:
    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    return json.dumps(
        {
            "id": "AQID",
            "type": "public-key",
            "response": {
                "attestationObject": b64url(attestation),
                "clientDataJSON": b64url(WEBAUTHN_L3_ANDROID_KEY_CLIENT_DATA_JSON),
            },
        }
    )


def test_a_public_key_credential_carries_its_statement_and_locates_tpm_errors():
    result = decode_payload_text(_credential(WEBAUTHN_L3_ANDROID_KEY_ATTESTATION_OBJECT))
    assert result["data"]["attestationStatementDecoded"]["fmt"] == "android-key"

    statement = {**TPM_WINDOWS_HELLO_ATT_STMT, "pubArea": TPM_WINDOWS_HELLO_ATT_STMT["pubArea"][:5]}
    attestation = attestation_object("tpm", statement, TPM_WINDOWS_HELLO_AUTH_DATA)
    (finding,) = decode_payload_text(_credential(attestation))["findings"]

    assert (finding["code"], finding["source"]) == ("tpm-structure", "response.attestationObject")
    assert finding["offset"] == attestation.index(statement["pubArea"]) + 4
    assert finding["path"] == '${"attStmt"}{"pubArea"}'


@pytest.mark.parametrize("fmt", ["packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "none", "apple", "compound"])
def test_every_format_names_its_section(fmt):
    view = attestation_statement.interpret(fmt, [] if fmt == "compound" else {})

    assert view["spec"].startswith("WebAuthn L3 section 8.")
    assert view["verification"] == _NOT_VERIFIED


@pytest.mark.parametrize("lenient", [False, True])
def test_a_certificate_malformed_past_its_load_is_shown_as_unreadable(client, lenient):
    leaf = material.certificate(material.ec_key("malformed-subject").public_key(), common_name="Leaf", serial=0x5E)
    # The subject's common name written as an INTEGER: the certificate loads, and
    # cryptography refuses its subject only when it is read.
    malformed = leaf.replace(b"\x0c\x04Leaf", b"\x02\x04Leaf")
    auth_data = bytes(32) + b"\x41" + (7).to_bytes(4, "big")
    statement = {"alg": -7, "sig": b"\x30\x00", "x5c": [malformed]}
    payload = cbor2.dumps({"fmt": "packed", "attStmt": statement, "authData": auth_data})

    response = client.post("/api/codec", json={"payload": payload.hex(), "mode": "decode", "lenient": lenient})

    assert response.status_code == 200
    (certificate,) = response.get_json()["data"]["attestationStatementDecoded"]["fields"]["x5c"]["certificates"]
    assert certificate["error"].startswith("not an X.509 certificate: error parsing asn1 value")
