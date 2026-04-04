from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.x509.oid import ObjectIdentifier


def test_attestation_helper_residual_branches(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    assert attestation_module._normalise_pqc_algorithm_identifier("   ") is None
    assert (
        attestation_module._normalise_pqc_algorithm_identifier("prefix ml-dsa-65 suffix")
        == -49
    )
    huge_numeric = f"value {'9' * 5000}"
    assert attestation_module._normalise_pqc_algorithm_identifier(huge_numeric) is None

    assert attestation_module.coerce_aaguid_hex("invalid") is None
    assert attestation_module.coerce_aaguid_hex({"aaguid": "still-invalid"}) is None
    assert attestation_module.coerce_aaguid_hex([1, 2, 3]) is None

    attestation_module.augment_aaguid_fields(("not", "mutable"))

    monkeypatch.setattr(
        attestation_module.uuid,
        "UUID",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("bad-uuid")),
        raising=False,
    )
    container = {"aaguid": b"\x01" * 16}
    attestation_module.augment_aaguid_fields(container)
    assert container["aaguidHex"] == (b"\x01" * 16).hex()
    assert "aaguidGuid" not in container

    assert attestation_module._normalise_signature_algorithm_name("") == ""
    assert (
        attestation_module._normalise_signature_algorithm_name("RSASSA-PSS with SHA-256")
        == "RSASSA-PSS"
    )
    assert (
        attestation_module._normalise_signature_algorithm_name("custom algo")
        == "CUSTOMALGO"
    )

    assert attestation_module._derive_certificate_algorithm_info("not-a-mapping") == ""
    assert (
        attestation_module._derive_certificate_algorithm_info(
            {"algorithm": "ecdsa", "hash": "sha-256"}
        )
        == "ECDSA_SHA256"
    )
    assert (
        attestation_module._derive_certificate_algorithm_info({"algorithm": "ed25519"})
        == "ED25519_SHA512"
    )
    assert (
        attestation_module._derive_certificate_algorithm_info({"algorithm": "ed448"})
        == "ED448_SHAKE256"
    )

    monkeypatch.setattr(
        attestation_module,
        "_build_unknown_public_key_info",
        lambda _cert, _err: (
            {"type": "Unknown", "algorithm": {"name": "Unknown"}},
            [
                ("SkipNone", None),
                ("Nested", ["line-a", "line-b"]),
            ],
        ),
        raising=False,
    )
    fallback = attestation_module._serialize_attestation_certificate_fallback(
        b"\x30\x82\x01\x00",
        ValueError("parse-error"),
    )
    assert "Best-effort public key details" in fallback["summary"]
    assert "Nested:" in fallback["summary"]


def test_serialize_attestation_certificate_mocked_certificate_residual_paths(monkeypatch):
    attestation_module = pytest.importorskip("server.app.attestation")

    class _Extensions(list):
        def get_extension_for_oid(self, oid):
            raise x509.ExtensionNotFound("missing", oid)

    ext_one_oid = SimpleNamespace(dotted_string="1.2.3", _name="unknown oid")
    ext_two_oid = SimpleNamespace(dotted_string="9.9.9", _name="9.9.9")
    ext_one = SimpleNamespace(oid=ext_one_oid, critical=False)
    ext_two = SimpleNamespace(oid=ext_two_oid, critical=False)

    class _Name:
        def __init__(self, text: str):
            self._text = text

        def rfc4514_string(self):
            return self._text

        def get_attributes_for_oid(self, _oid):
            return []

    class _SignatureHash:
        pass

    class _Certificate:
        version = SimpleNamespace(value=2)
        signature_algorithm_oid = SimpleNamespace(dotted_string="1.2.840.10045.4.3.2", _name="unknown oid")
        issuer = _Name("CN=Issuer")
        subject = _Name("CN=Subject")
        extensions = _Extensions([ext_one, ext_two])
        signature = b"\xAA\xBB"
        serial_number = 12345

        not_valid_before = datetime(2020, 1, 1)
        not_valid_after = datetime(2030, 1, 1)

        @property
        def signature_hash_algorithm(self):
            return _SignatureHash()

        def public_key(self):
            raise UnsupportedAlgorithm("unsupported")

        def fingerprint(self, algorithm):
            algo_name = algorithm.name.lower()
            if algo_name == "md5":
                return b""
            if algo_name == "sha1":
                return b"\x01"
            return b"\x02"

        def public_bytes(self, _encoding):
            return b"\x30\x82\x01\x00"

    monkeypatch.setattr(
        attestation_module.x509,
        "load_der_x509_certificate",
        lambda _der: _Certificate(),
        raising=False,
    )
    monkeypatch.setattr(attestation_module, "describe_mldsa_oid_name", lambda _oid: "FriendlySig", raising=False)
    monkeypatch.setattr(attestation_module, "describe_mldsa_oid", lambda _oid: {}, raising=False)
    monkeypatch.setattr(
        attestation_module,
        "_build_unknown_public_key_info",
        lambda _cert, _err: (
            {"type": "Unknown", "algorithm": {"name": "Unknown"}},
            [
                ("Type", "Unknown"),
                ("SkipEmpty", []),
                ("Structured", [None, {"inner": "value"}]),
            ],
        ),
        raising=False,
    )
    monkeypatch.setitem(
        attestation_module.EXTENSION_DISPLAY_METADATA,
        "1.2.3",
        {"friendly_name": "FriendlyOne", "include_oid_in_header": False},
    )
    monkeypatch.setitem(
        attestation_module.EXTENSION_DISPLAY_METADATA,
        "9.9.9",
        {"include_oid_in_header": False},
    )
    monkeypatch.setattr(
        attestation_module,
        "_serialize_extension_value",
        lambda _ext: {"skip": "", "nested": [None, {"k": "v"}]},
        raising=False,
    )

    serialized = attestation_module.serialize_attestation_certificate(b"\x30\x82\x01\x00")
    assert serialized["signatureAlgorithm"] == "FriendlySig"
    assert "FriendlyOne" in serialized["summary"]
    assert "9.9.9" in serialized["summary"]
    assert "FINGERPRINT" in serialized["summary"].upper()
    assert serialized["algorithmInfo"]