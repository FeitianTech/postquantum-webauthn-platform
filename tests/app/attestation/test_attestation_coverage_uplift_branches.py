from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

from cryptography import x509
from fido2.attestation import Attestation
from fido2.webauthn import AuthenticatorData, RegistrationResponse

from server.app.webauthn import attestation as attestation_module


class _CredentialData:
    def __init__(self, public_key=None):
        self.credential_id = b"credential-id"
        self.public_key = public_key if public_key is not None else {3: -7}
        self.aaguid = bytes.fromhex("00112233445566778899aabbccddeeff")


class _AuthData:
    def __init__(self, *, rp_id: str, flags: int, credential_data: _CredentialData | None = None):
        self.rp_id_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
        self.flags = flags
        self.counter = 1
        self.credential_data = credential_data or _CredentialData()

    def __bytes__(self):
        return b"auth-data"


class _ClientData:
    def __init__(self, *, challenge: bytes, origin: str):
        self.type = "webauthn.create"
        self.challenge = challenge
        self.origin = origin
        self.cross_origin = False
        self.hash = hashlib.sha256(b"client-data").digest()


def _registration(attestation_object, client_data):
    return SimpleNamespace(
        response=SimpleNamespace(
            attestation_object=attestation_object,
            client_data=client_data,
        ),
        client_extension_results={},
    )


def test_coerce_certificate_bytes_falls_back_to_hex_parsing_when_base64_decode_fails(monkeypatch, attestation_module):
    monkeypatch.setattr(
        base64,
        "b64decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad-base64")),
    )

    assert attestation_module._coerce_certificate_bytes("0a0b") == b"\x0a\x0b"
    assert attestation_module._coerce_certificate_bytes("zz") is None


def test_extract_certificate_aaguid_handles_non_hex_string_extension_values(monkeypatch, attestation_module):
    class _ExtensionValue:
        value = "Z" * 16

    class _Extension:
        value = _ExtensionValue()

    class _Extensions:
        def get_extension_for_oid(self, _oid):
            return _Extension()

    class _Certificate:
        extensions = _Extensions()

    monkeypatch.setattr(
        x509,
        "load_der_x509_certificate",
        lambda _data: _Certificate(),
    )

    extracted = attestation_module._extract_certificate_aaguid(b"cert")
    assert extracted == b"Z" * 16


def test_coerce_attestation_certificate_bytes_string_path_falls_back_to_base64url():
    raw = b"\xfb\xef\xbe"
    standard = base64.b64encode(raw).decode("ascii")
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    assert "+" in standard or "/" in standard
    assert "-" in urlsafe or "_" in urlsafe

    # Standard base64 first, then base64url -- and each reading is exact, so
    # the fallback recovers the same certificate rather than a shorter one.
    assert attestation_module._coerce_attestation_certificate_bytes(standard) == raw
    assert attestation_module._coerce_attestation_certificate_bytes(urlsafe) == raw

    assert attestation_module._coerce_attestation_certificate_bytes("not a certificate!") is None


def test_normalise_signature_algorithm_name_covers_ed448_and_dsa_paths(attestation_module):
    assert attestation_module._normalise_signature_algorithm_name("ed448 with shake") == "ED448"
    assert attestation_module._normalise_signature_algorithm_name("dsa-with-sha1") == "DSA"


def test_perform_attestation_checks_coerces_string_challenge_via_utf8_fallback_and_records_attestation_error(monkeypatch, metadata_module, certificates, attestation_module):
    flags = int(AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT)
    auth_data = _AuthData(rp_id="example.com", flags=flags)
    challenge = b"raw:text:challenge"
    client_data = _ClientData(challenge=challenge, origin="https://example.com")
    attestation_object = SimpleNamespace(fmt="packed", att_stmt={}, auth_data=auth_data)

    monkeypatch.setattr(
        RegistrationResponse,
        "from_dict",
        lambda _response: _registration(attestation_object, client_data),
    )
    # "raw:text:challenge" is not base64, base64url or hex, so the challenge
    # coercion reaches its UTF-8 fallback without any decoder being stubbed.

    class _AttestationVerifier:
        def verify(self, _att_stmt, _auth_data, _client_hash):
            raise RuntimeError("boom")

    monkeypatch.setattr(
        Attestation,
        "for_type",
        lambda _fmt: _AttestationVerifier,
    )
    monkeypatch.setattr(metadata_module, "get_mds_verifier", lambda: None)

    result = attestation_module.perform_attestation_checks(
        response={"dummy": True},
        state={"challenge": challenge.decode("utf-8")},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["client_data"]["challenge_matches"] is True
    assert result["signature_valid"] is False
    assert any(err.startswith("attestation_error:") for err in result["errors"])


def test_perform_attestation_checks_falls_back_to_public_key_options_when_state_hex_wrapper_is_invalid(monkeypatch, metadata_module, attestation_module):
    flags = int(AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT)
    auth_data = _AuthData(rp_id="example.com", flags=flags)
    challenge = b"fallback-challenge"
    client_data = _ClientData(challenge=challenge, origin="https://example.com")
    attestation_object = SimpleNamespace(fmt="none", att_stmt={}, auth_data=auth_data)

    monkeypatch.setattr(
        RegistrationResponse,
        "from_dict",
        lambda _response: _registration(attestation_object, client_data),
    )
    monkeypatch.setattr(metadata_module, "get_mds_verifier", lambda: None)

    result = attestation_module.perform_attestation_checks(
        response={"dummy": True},
        state={"challenge": {"$hex": "zz"}},
        public_key_options={
            "challenge": challenge,
            "pubKeyCredParams": [{"alg": -7}],
        },
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["client_data"]["challenge_matches"] is True
    assert "challenge_mismatch" not in result["errors"]
