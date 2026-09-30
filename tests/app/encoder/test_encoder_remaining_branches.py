
import pytest


def test_a_ctap_view_names_one_message_the_encoder_builds():
    from server.app.decoder.encode import ctap_view_reader

    with pytest.raises(ValueError, match="ctapDecoded names no CTAP message"):
        ctap_view_reader.one_message({})
    with pytest.raises(ValueError, match="ctapDecoded.makeCredentialRequest must be an object"):
        ctap_view_reader.one_message({"makeCredentialRequest": "not-a-map"})
    with pytest.raises(ValueError, match="ctapDecoded holds 2 messages"):
        ctap_view_reader.one_message({"makeCredentialRequest": "not-a-map", "getAssertionRequest": "still-not-a-map"})
