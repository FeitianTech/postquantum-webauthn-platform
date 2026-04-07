import base64

import pytest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_extract_requested_assertion_algorithm_prefers_top_level_alg_over_allow_credentials():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    result = advanced_module._extract_requested_assertion_algorithm(
        {
            "alg": "ES256",
            "allowCredentials": [
                {"type": "public-key", "id": b"cred-1", "alg": -257},
            ],
        },
        credential_id=b"cred-1",
    )

    assert result == -7


def test_extract_requested_assertion_algorithm_returns_none_when_inputs_do_not_provide_algorithm():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    assert advanced_module._extract_requested_assertion_algorithm({"challenge": "AQID"}, None) is None
    assert (
        advanced_module._extract_requested_assertion_algorithm(
            {"allowCredentials": "not-a-list"},
            None,
        )
        is None
    )


def test_extract_requested_assertion_algorithm_matches_bytes_id():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    credential_id = b"credential-bytes"

    result = advanced_module._extract_requested_assertion_algorithm(
        {
            "allowCredentials": [
                {"type": "public-key", "id": credential_id, "alg": -8},
            ]
        },
        credential_id=credential_id,
    )

    assert result == -8


@pytest.mark.parametrize(
    "encoded_id",
    [
        b"credential-encoded".hex(),
        _b64url(b"credential-encoded"),
    ],
)
def test_extract_requested_assertion_algorithm_matches_string_encoded_ids(encoded_id):
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    credential_id = b"credential-encoded"

    result = advanced_module._extract_requested_assertion_algorithm(
        {
            "allowCredentials": [
                {"type": "public-key", "id": encoded_id, "alg": "-257"},
            ]
        },
        credential_id=credential_id,
    )

    assert result == -257


@pytest.mark.parametrize(
    "wrapped_id",
    [
        {"$hex": b"wrapped-credential".hex()},
        {"$base64": base64.b64encode(b"wrapped-credential").decode("ascii")},
        {"$base64url": _b64url(b"wrapped-credential")},
    ],
)
def test_extract_requested_assertion_algorithm_matches_wrapped_binary_identifiers(wrapped_id):
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    credential_id = b"wrapped-credential"

    result = advanced_module._extract_requested_assertion_algorithm(
        {
            "allowCredentials": [
                {"type": "public-key", "id": wrapped_id, "alg": "PS256"},
            ]
        },
        credential_id=credential_id,
    )

    assert result == -37


def test_extract_requested_assertion_algorithm_prefers_exact_match_over_later_entries():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    credential_id = b"target-credential"

    result = advanced_module._extract_requested_assertion_algorithm(
        {
            "allowCredentials": [
                {"type": "public-key", "id": b"first", "alg": -8},
                {"type": "public-key", "id": credential_id, "alg": -7},
                {"type": "public-key", "id": b"third", "alg": -257},
            ]
        },
        credential_id=credential_id,
    )

    assert result == -7


def test_extract_requested_assertion_algorithm_uses_last_valid_fallback_when_no_id_matches():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    result = advanced_module._extract_requested_assertion_algorithm(
        {
            "allowCredentials": [
                "not-a-mapping",
                {"type": "public-key", "id": "not*valid", "alg": -99999},
                {"type": "public-key", "id": b"first", "alg": -8},
                {"type": "public-key", "id": b"second", "alg": "-257"},
                {"type": "public-key", "id": b"third", "alg": "unsupported"},
            ]
        },
        credential_id=b"missing",
    )

    assert result == -257


def test_extract_requested_assertion_algorithm_uses_fallback_when_credential_id_is_none():
    advanced_module = pytest.importorskip("server.app.routes.advanced")

    result = advanced_module._extract_requested_assertion_algorithm(
        {
            "allowCredentials": [
                {"type": "public-key", "id": b"one", "alg": -8},
                {"type": "public-key", "id": b"two", "alg": -257},
            ]
        },
        credential_id=None,
    )

    assert result == -257
