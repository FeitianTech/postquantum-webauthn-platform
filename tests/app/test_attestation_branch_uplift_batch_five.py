from __future__ import annotations

import hashlib
from types import MappingProxyType, SimpleNamespace

import pytest
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier


class _ClientData:
    def __init__(self, challenge: bytes):
        self.type = "webauthn.create"
        self.challenge = challenge
        self.origin = "https://example.com"
        self.cross_origin = False
        self.hash = hashlib.sha256(b"client-data").digest()
        self.b64 = None

    def __bytes__(self):
        return b"client-data-json"


class _AttestationObject:
    def __init__(self, *, fmt: str, att_stmt, auth_data):
        self.fmt = fmt
        self.att_stmt = att_stmt
        self.auth_data = auth_data

    def __bytes__(self):
        return b"attestation-object"


class _AuthData:
    def __init__(self, *, rp_id_hash: bytes, flags, counter: int, credential_data):
        self.rp_id_hash = rp_id_hash
        self.flags = flags
        self.counter = counter
        self.credential_data = credential_data

    def __bytes__(self):
        return b"auth-data"


def _registration(attestation_object, client_data, extension_results):
    return SimpleNamespace(
        response=SimpleNamespace(
            attestation_object=attestation_object,
            client_data=client_data,
        ),
        client_extension_results=extension_results,
    )


def test_extract_attestation_details_handles_non_dict_and_certificate_edge_cases(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    defaults = attestation_module.extract_attestation_details(["not-a-dict"])
    assert defaults[0] == "none"
    assert defaults[1] == {}

    attestation_object = _AttestationObject(
        fmt="packed",
        att_stmt={"x5c": ["bad", "good"]},
        auth_data=SimpleNamespace(),
    )
    registration = _registration(
        attestation_object,
        _ClientData(b"challenge"),
        MappingProxyType({"ext": True}),
    )

    monkeypatch.setattr(
        attestation_module.RegistrationResponse,
        "from_dict",
        lambda _response: registration,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "_coerce_attestation_certificate_bytes",
        lambda entry: None if entry == "bad" else b"cert-bytes",
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module,
        "serialize_attestation_certificate",
        lambda _cert: None,
        raising=False,
    )

    extracted = attestation_module.extract_attestation_details({"ok": True})
    assert extracted[0] == "packed"
    assert extracted[5]["error"] == "Unable to decode attestation certificate bytes."
    assert extracted[6][1]["error"] == "Unable to parse attestation certificate."
    assert extracted[4] == {"ext": True}


def test_extract_attestation_details_keeps_non_mapping_extension_outputs(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    attestation_object = _AttestationObject(fmt="none", att_stmt={}, auth_data=SimpleNamespace())
    registration = _registration(attestation_object, _ClientData(b"challenge"), ["raw-extension"])

    monkeypatch.setattr(
        attestation_module.RegistrationResponse,
        "from_dict",
        lambda _response: registration,
        raising=False,
    )

    extracted = attestation_module.extract_attestation_details({"ok": True})
    assert extracted[4] == ["raw-extension"]


def test_serialize_extension_value_unrecognized_oid_fallback_paths(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    firmware_oid = ObjectIdentifier("1.3.6.1.4.1.41482.13.1")
    security_key_oid = ObjectIdentifier("1.3.6.1.4.1.41482.1.1")
    aaguid_oid = ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4")

    def _decode_stub(raw_value: bytes) -> bytes:
        if raw_value == b"firmware":
            return b""
        if raw_value == b"security":
            return b"\xff\xfe"
        return b"short"

    monkeypatch.setattr(attestation_module, "decode_asn1_octet_string", _decode_stub, raising=False)

    firmware_ext = SimpleNamespace(
        oid=firmware_oid,
        value=x509.UnrecognizedExtension(firmware_oid, b"firmware"),
    )
    security_ext = SimpleNamespace(
        oid=security_key_oid,
        value=x509.UnrecognizedExtension(security_key_oid, b"security"),
    )
    aaguid_ext = SimpleNamespace(
        oid=aaguid_oid,
        value=x509.UnrecognizedExtension(aaguid_oid, b"aaguid"),
    )

    assert "Hex value" in attestation_module._serialize_extension_value(firmware_ext)
    assert "Hex value" in attestation_module._serialize_extension_value(security_ext)
    assert "Hex value" in attestation_module._serialize_extension_value(aaguid_ext)


def test_perform_attestation_checks_challenge_coercion_and_uv_requirement_paths(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    auth_data_override = attestation_module.AuthenticatorData.create(
        hashlib.sha256(b"example.com").digest(),
        attestation_module.AuthenticatorData.FLAG.UP,
        1,
    )

    registration = _registration(
        SimpleNamespace(fmt="none", att_stmt={}, auth_data=auth_data_override),
        _ClientData(b"challenge"),
        {},
    )

    monkeypatch.setattr(
        attestation_module.RegistrationResponse,
        "from_dict",
        lambda _response: registration,
        raising=False,
    )

    result = attestation_module.perform_attestation_checks(
        response={"ok": True},
        state={"challenge": {"$base64": "%%%"}},
        public_key_options={
            "challenge": {"unexpected": True},
            "authenticatorSelection": {"userVerification": "required"},
            "pubKeyCredParams": [{"alg": -7}],
        },
        auth_data=auth_data_override,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["signature_valid"] is None
    assert result["client_data"]["expected_challenge"] is None
    assert result["authenticator_data"]["user_verification_required"] is True


def test_perform_attestation_checks_classical_lookup_and_aaguid_parse_failure_paths(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    class _SparsePublicKey(dict):
        def __iter__(self):
            return iter(())

        def get(self, key, default=None):
            if key == 3:
                return -7
            return default

    credential_data = SimpleNamespace(
        credential_id=b"cred-id",
        public_key=_SparsePublicKey(),
        aaguid=b"\x01" * 16,
    )
    auth_data = _AuthData(
        rp_id_hash=hashlib.sha256(b"example.com").digest(),
        flags=attestation_module.AuthenticatorData.FLAG.UP
        | attestation_module.AuthenticatorData.FLAG.AT,
        counter=3,
        credential_data=credential_data,
    )

    registration = _registration(
        _AttestationObject(fmt="packed", att_stmt={}, auth_data=auth_data),
        _ClientData(b"challenge"),
        {},
    )

    monkeypatch.setattr(
        attestation_module.RegistrationResponse,
        "from_dict",
        lambda _response: registration,
        raising=False,
    )
    monkeypatch.setattr(
        attestation_module.Attestation,
        "for_type",
        lambda _fmt: type("_Verifier", (), {"verify": lambda self, *_args: SimpleNamespace(trust_path=[])})
        ,
        raising=False,
    )
    monkeypatch.setattr(attestation_module, "get_mds_verifier", lambda: object(), raising=False)
    monkeypatch.setattr(
        attestation_module,
        "_evaluate_classical_attestation_root",
        lambda *_args, **_kwargs: {
            "root_valid": None,
            "metadata_entry": None,
            "metadata_lookup_source": "classical-source",
            "checks": None,
            "errors": [],
            "warnings": [],
        },
        raising=False,
    )
    monkeypatch.setattr(attestation_module.CoseKey, "parse", lambda _value: object(), raising=False)
    monkeypatch.setattr(
        attestation_module.Aaguid,
        "fromhex",
        lambda _hex: (_ for _ in ()).throw(ValueError("bad-aaguid")),
        raising=False,
    )

    result = attestation_module.perform_attestation_checks(
        response={"ok": True},
        state={"challenge": b"challenge"},
        public_key_options={"pubKeyCredParams": [{"alg": -7}]},
        auth_data=None,
        expected_origin="https://example.com",
        rp_id="example.com",
    )

    assert result["metadata"]["source"] == "classical-source"
    assert result["authenticator_data"]["algorithm"] == -7


def test_coerce_attestation_certificate_bytes_and_aaguid_field_cleanup_edges():
    attestation_module = pytest.importorskip("server.app.attestation")

    assert attestation_module._coerce_attestation_certificate_bytes({"raw": "zz"}) is None
    assert attestation_module._coerce_attestation_certificate_bytes({"derBase64": "A"}) is None
    assert attestation_module._coerce_attestation_certificate_bytes(
        {"pem": "-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"}
    ) == b""

    container = {
        "aaguid": {"raw": "not-aaguid"},
        "aaguidHex": "existing",
        "aaguidGuid": "existing",
        "aaguidRaw": "existing",
    }
    attestation_module.augment_aaguid_fields(container)
    assert "aaguidHex" not in container
    assert "aaguidGuid" not in container
    assert "aaguidRaw" not in container