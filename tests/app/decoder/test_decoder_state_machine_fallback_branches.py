from __future__ import annotations

from server.app.decoder.decode import answer as decode_answer


def test_build_decoder_payload_names_the_kind_ctap_decoded_names_only():
    payload = decode_answer._build_decoder_payload(
        {
            "format": "CBOR",
            "decoded": {
                "ctap": {"meaning": "Status meaning"},
                "ctapDecoded": {"makeCredentialRequest": {"rp": "example.com"}},
                "expandedJson": {"attStmt": {"sig": "aa"}, "signature": "bb"},
            },
        }
    )

    assert payload["success"] is True
    assert "MakeCredential request" in payload["type"]
    # Text keys named "attStmt" or "signature" do not make a response of it.
    assert "MakeCredential response" not in payload["type"]
    assert "GetAssertion response" not in payload["type"]
