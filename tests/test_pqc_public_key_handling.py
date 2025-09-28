import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

for _module_name in [name for name in list(sys.modules) if name == "fido2" or name.startswith("fido2.")]:
    del sys.modules[_module_name]

import base64  # noqa: E402
import hashlib  # noqa: E402
import fido2.cose as cose_module  # noqa: E402
import fido2.attestation.packed as packed_module  # noqa: E402
import examples.server.server.attestation as attestation_module  # noqa: E402
import pytest  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.exceptions import UnsupportedAlgorithm  # noqa: E402
from fido2.cose import MLDSA44, MLDSA65, MLDSA87  # noqa: E402
from fido2.utils import ByteBuffer  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from examples.server.server import storage  # noqa: E402


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _encode_oid(oid: str) -> bytes:
    components = [int(part) for part in oid.split(".")]
    if len(components) < 2:
        raise ValueError("OID must have at least two components")
    first = components[0] * 40 + components[1]
    encoded = [first]
    for value in components[2:]:
        if value == 0:
            encoded.append(0)
            continue
        base128 = []
        while value:
            base128.append(0x80 | (value & 0x7F))
            value >>= 7
        base128[0] &= 0x7F
        encoded.extend(reversed(base128))
    body = bytes(encoded)
    return b"\x06" + _encode_length(len(body)) + body


def _encode_sequence(*elements: bytes) -> bytes:
    body = b"".join(elements)
    return b"\x30" + _encode_length(len(body)) + body


def _encode_set(*elements: bytes) -> bytes:
    body = b"".join(elements)
    return b"\x31" + _encode_length(len(body)) + body


def _encode_integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big", signed=False)
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + _encode_length(len(encoded)) + encoded


def _encode_utf8_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return b"\x0c" + _encode_length(len(encoded)) + encoded


def _encode_utctime(value: str) -> bytes:
    return b"\x17" + _encode_length(len(value)) + value.encode("ascii")


def _encode_octet_string(payload: bytes) -> bytes:
    return b"\x04" + _encode_length(len(payload)) + payload


def _build_name(common_name: str) -> bytes:
    cn = _encode_sequence(_encode_oid("2.5.4.3"), _encode_utf8_string(common_name))
    return _encode_sequence(_encode_set(cn))


def _build_spki(raw_key: bytes, algorithm_oid: str = "1.2.3") -> bytes:
    """Construct a minimal SubjectPublicKeyInfo wrapper for a raw key."""

    oid = _encode_oid(algorithm_oid)
    null_params = b"\x05\x00"
    algorithm = _encode_sequence(oid, null_params)
    bit_string = b"\x03" + _encode_length(len(raw_key) + 1) + b"\x00" + raw_key
    return _encode_sequence(algorithm, bit_string)


def _build_certificate(spki: bytes, signature_algorithm_oid: str = "1.2.840.10045.4.3.2") -> bytes:
    version = b"\xa0" + _encode_length(len(_encode_integer(2))) + _encode_integer(2)
    serial = _encode_integer(1)
    signature_algo = _encode_sequence(_encode_oid(signature_algorithm_oid), b"\x05\x00")
    name = _build_name("Test")
    validity = _encode_sequence(
        _encode_utctime("240101000000Z"),
        _encode_utctime("260101000000Z"),
    )
    tbs = _encode_sequence(version, serial, signature_algo, name, validity, name, spki)
    signature_value = b"\x03\x02\x00\x00"
    return _encode_sequence(tbs, signature_algo, signature_value)

def test_mldsa_from_cryptography_key_accepts_raw_public_bytes():
    raw_key = b"\x01\x02\x03"

    class DummyKey:
        def public_bytes(self, encoding, fmt):
            if encoding is serialization.Encoding.Raw and fmt is serialization.PublicFormat.Raw:
                return raw_key
            raise ValueError("unexpected encoding")

    cose_key = MLDSA87.from_cryptography_key(DummyKey())
    assert cose_key[-1] == raw_key


def test_mldsa_from_cryptography_key_extracts_from_spki():
    raw_key = b"raw-public-key"
    spki = _build_spki(raw_key)

    class DummyKey:
        def public_bytes(self, encoding, fmt):
            if encoding is serialization.Encoding.DER and fmt is serialization.PublicFormat.SubjectPublicKeyInfo:
                return spki
            raise ValueError("unsupported encoding")

    cose_key = MLDSA65.from_cryptography_key(DummyKey())
    assert cose_key[-1] == raw_key


def test_mldsa_verify_coerces_dynamic_public_key_bytes(monkeypatch):
    raw_key = b"coerced-public-key"
    spki = _build_spki(raw_key)

    class DummyKey:
        def public_bytes(self, encoding, fmt):
            if encoding is serialization.Encoding.DER and fmt is serialization.PublicFormat.SubjectPublicKeyInfo:
                return spki
            raise ValueError("unsupported encoding")

    verify_calls: list[tuple[bytes, bytes, bytes]] = []

    class FakeSignature:
        def __init__(self, algorithm: str):
            assert algorithm == "ML-DSA-44"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
            verify_calls.append((message, signature, public_key))
            return True

    class FakeOQS:
        Signature = FakeSignature

    monkeypatch.setattr(cose_module, "oqs", FakeOQS)
    monkeypatch.setattr(cose_module, "_oqs_import_error", None)

    cose_key = MLDSA44({1: 7, 3: -48, -1: DummyKey()})
    cose_key.verify(b"msg", b"sig")

    assert verify_calls == [(b"msg", b"sig", raw_key)]


def test_coerce_mldsa_public_key_bytes_unwraps_der_subject_public_key():
    raw_key = b"wrapped-public-key"
    spki = _build_spki(raw_key, algorithm_oid="2.16.840.1.101.3.4.3.17")

    result = cose_module._coerce_mldsa_public_key_bytes(spki, "ML-DSA-44")

    assert result == raw_key


def test_coerce_mldsa_public_key_bytes_handles_bytebuffer():
    raw_key = b"bytebuffer-public-key"
    buffer = ByteBuffer(raw_key)

    result = cose_module._coerce_mldsa_public_key_bytes(buffer, "ML-DSA-65")

    assert result == raw_key


def test_extract_certificate_public_key_info_parses_mldsa_certificate():
    raw_key = b"ml-dsa-public-key"
    spki = _build_spki(raw_key, algorithm_oid="2.16.840.1.101.3.4.3.17")
    cert = _build_certificate(spki)

    info = cose_module.extract_certificate_public_key_info(cert)

    assert info["algorithm_oid"] == "2.16.840.1.101.3.4.3.17"
    assert info["ml_dsa_parameter_set"] == "ML-DSA-44"
    assert info["subject_public_key"] == raw_key
    details = info.get("ml_dsa_parameter_details")
    assert isinstance(details, dict)
    length = details.get("public_key_length")
    if length is not None:
        assert isinstance(length, int)
        assert length > 0


def test_extract_certificate_public_key_info_unwraps_octet_string_public_key():
    raw_key = b"wrapped-ml-dsa-key"
    wrapped = _encode_octet_string(raw_key)
    spki = _build_spki(wrapped, algorithm_oid="2.16.840.1.101.3.4.3.18")
    cert = _build_certificate(spki)

    info = cose_module.extract_certificate_public_key_info(cert)

    assert info["subject_public_key"] == raw_key
    assert info["wrapped_subject_public_key"] == wrapped


def test_extract_certificate_public_key_info_scans_when_tbs_parse_fails(monkeypatch):
    raw_key = b"fallback-ml-dsa-key"
    spki = _build_spki(raw_key, algorithm_oid="2.16.840.1.101.3.4.3.19")
    cert = _build_certificate(spki)

    def fail_parse(view):
        raise ValueError("unable to parse")

    monkeypatch.setattr(
        cose_module, "_locate_subject_public_key_info_from_tbs", fail_parse
    )

    info = cose_module.extract_certificate_public_key_info(cert)

    assert info["algorithm_oid"] == "2.16.840.1.101.3.4.3.19"
    assert info["subject_public_key"] == raw_key


@pytest.mark.parametrize("exception_cls", [UnsupportedAlgorithm, ValueError])
def test_packed_attestation_falls_back_to_parsed_certificate_bytes(monkeypatch, exception_cls):
    raw_key = b"certificate-public-key"
    spki = _build_spki(raw_key, algorithm_oid="2.16.840.1.101.3.4.3.17")
    cert_der = _build_certificate(spki)

    class FakeCert:
        def __init__(self):
            self.extensions = []
            self.subject = SimpleNamespace(
                get_attributes_for_oid=lambda oid: [SimpleNamespace(value="Test")]
            )

        def public_key(self):
            raise exception_cls("Unknown key type: 2.16.840.1.101.3.4.3.17")

    monkeypatch.setattr(
        packed_module,
        "_validate_packed_cert",
        lambda cert, aaguid, **kwargs: None,
    )
    monkeypatch.setattr(
        packed_module.x509,
        "load_der_x509_certificate",
        lambda data, backend=None: FakeCert(),
    )

    def fake_extract(data):
        assert data == cert_der
        return {
            "subject_public_key": raw_key,
            "algorithm_oid": "2.16.840.1.101.3.4.3.17",
            "ml_dsa_parameter_set": "ML-DSA-44",
        }

    monkeypatch.setattr(packed_module, "extract_certificate_public_key_info", fake_extract)

    verify_calls: list[tuple[bytes, bytes, bytes]] = []

    def fake_verify(self, message, signature):
        verify_calls.append((self.get(-1), message, signature))

    monkeypatch.setattr(cose_module.MLDSA44, "verify", fake_verify, raising=False)

    class DummyCredentialData:
        aaguid = b"\x00" * 16

    class DummyAuthData:
        credential_data = DummyCredentialData()

        def __bytes__(self):
            return b"auth-data"

        def __add__(self, other):
            return bytes(self) + other

    attestation = packed_module.PackedAttestation()
    statement = {"alg": -48, "sig": b"sig", "x5c": [cert_der]}

    result = attestation.verify(statement, DummyAuthData(), b"hash")

    assert verify_calls == [(raw_key, b"auth-data" + b"hash", b"sig")]
    assert result.attestation_type == packed_module.AttestationType.BASIC


def test_validate_packed_cert_allows_missing_basic_constraints_for_mldsa():
    raw_key = b"certificate-public-key"
    cert_der = _build_certificate(
        _build_spki(raw_key, algorithm_oid="2.16.840.1.101.3.4.3.17")
    )
    cert = x509.load_der_x509_certificate(cert_der)

    class DummyExtensions:
        def get_extension_for_class(self, cls):
            raise x509.ExtensionNotFound("missing", cls)

        def get_extension_for_oid(self, oid):
            raise x509.ExtensionNotFound("missing", oid)

    class DummyName:
        def get_attributes_for_oid(self, oid):
            mapping = {
                x509.NameOID.COUNTRY_NAME: [SimpleNamespace(value="US")],
                x509.NameOID.ORGANIZATION_NAME: [SimpleNamespace(value="Example Corp")],
                x509.NameOID.ORGANIZATIONAL_UNIT_NAME: [
                    SimpleNamespace(value="Authenticator Attestation")
                ],
                x509.NameOID.COMMON_NAME: [SimpleNamespace(value="Test Device")],
            }
            return mapping.get(oid, [])

    dummy_cert = SimpleNamespace(
        version=x509.Version.v3,
        extensions=DummyExtensions(),
        subject=DummyName(),
        issuer=DummyName(),
    )

    packed_module._validate_packed_cert(
        dummy_cert,
        b"\x00" * 16,
        cert_bytes=cert_der,
    )


def test_validate_packed_cert_requires_basic_constraints_for_non_pqc():
    raw_key = b"certificate-public-key"
    cert_der = _build_certificate(_build_spki(raw_key, algorithm_oid="1.2.3"))
    cert = x509.load_der_x509_certificate(cert_der)

    class DummyExtensions:
        def get_extension_for_class(self, cls):
            raise x509.ExtensionNotFound("missing", cls)

        def get_extension_for_oid(self, oid):
            raise x509.ExtensionNotFound("missing", oid)

    class DummyName:
        def get_attributes_for_oid(self, oid):
            mapping = {
                x509.NameOID.COUNTRY_NAME: [SimpleNamespace(value="US")],
                x509.NameOID.ORGANIZATION_NAME: [SimpleNamespace(value="Example Corp")],
                x509.NameOID.ORGANIZATIONAL_UNIT_NAME: [
                    SimpleNamespace(value="Authenticator Attestation")
                ],
                x509.NameOID.COMMON_NAME: [SimpleNamespace(value="Test Device")],
            }
            return mapping.get(oid, [])

    dummy_cert = SimpleNamespace(
        version=x509.Version.v3,
        extensions=DummyExtensions(),
        subject=DummyName(),
        issuer=DummyName(),
    )

    with pytest.raises(packed_module.InvalidData):
        packed_module._validate_packed_cert(
            dummy_cert,
            b"\x00" * 16,
            cert_bytes=cert_der,
        )


def test_unknown_public_key_info_formats_mldsa_details(monkeypatch):
    raw_key = b"certificate-public-key"
    wrapped = _encode_octet_string(raw_key)
    cert_der = _build_certificate(
        _build_spki(wrapped, algorithm_oid="2.16.840.1.101.3.4.3.17")
    )

    monkeypatch.setattr(
        attestation_module,
        "_load_oqs_signature_details",
        lambda mechanism: {
            "length-public-key": len(raw_key),
            "length-signature": 10,
            "claimed-nist-level": 2,
        },
    )

    info, summary = attestation_module._build_unknown_public_key_info(
        cert_der, UnsupportedAlgorithm("unsupported")
    )

    assert "error" not in info
    assert info["type"] == "ML-DSA"
    assert info["algorithm"]["mlDsaParameterSet"] == "ML-DSA-44"
    assert info["keySize"] == len(raw_key) * 8

    summary_dict = dict(summary)
    assert summary_dict["ML-DSA parameter set"] == "ML-DSA-44"
    assert summary_dict["Claimed NIST level"] == 2


def test_serialize_attestation_certificate_handles_value_error(monkeypatch):
    raw_key = b"certificate-public-key"
    cert_der = _build_certificate(
        _build_spki(raw_key, algorithm_oid="2.16.840.1.101.3.4.3.17"),
        signature_algorithm_oid="2.16.840.1.101.3.4.3.17",
    )

    certificate = x509.load_der_x509_certificate(cert_der)
    cert_type = type(certificate)

    def fail_public_key(self):
        raise ValueError("Unknown key type: 2.16.840.1.101.3.4.3.17")

    monkeypatch.setattr(cert_type, "public_key", fail_public_key, raising=False)

    details = attestation_module.serialize_attestation_certificate(cert_der)

    public_key_info = details["publicKeyInfo"]
    assert public_key_info["type"] == "ML-DSA"
    assert public_key_info["algorithm"]["mlDsaParameterSet"] == "ML-DSA-44"
    assert public_key_info["publicKeyHex"].replace(":", "").lower() == raw_key.hex()
    assert details["signatureAlgorithm"] == "ML-DSA-44"
    assert details["signatureAlgorithmOid"] == "2.16.840.1.101.3.4.3.17"
    assert details["signatureAlgorithmDetails"]["mlDsaParameterSet"] == "ML-DSA-44"
    signature_info = details["signature"]
    assert signature_info["algorithm"] == "ML-DSA-44"
    assert signature_info["oid"] == "2.16.840.1.101.3.4.3.17"

    summary_lines = details["summary"].splitlines()
    assert any("ML-DSA parameter set" in line for line in summary_lines)


def test_serialize_attestation_certificate_fallback_on_parse_error(monkeypatch):
    cert_der = b"invalid-der"

    def fail_loader(*_args, **_kwargs):
        raise ValueError("short data")

    monkeypatch.setattr(
        attestation_module.x509, "load_der_x509_certificate", fail_loader
    )

    details = attestation_module.serialize_attestation_certificate(cert_der)

    assert details["error"].startswith("Unable to parse attestation certificate")
    assert details["derBase64"] == base64.b64encode(cert_der).decode("ascii")
    assert details["fingerprints"]["sha256"] == hashlib.sha256(cert_der).hexdigest()
    assert "Fingerprints:" in details["summary"]
    assert isinstance(details["publicKeyInfo"], dict)

def test_pqc_attestation_fallback_verifies_signature(monkeypatch):
    class FakeCredentialData:
        def __init__(self):
            self.public_key = {"kty": 7}

    class FakeAuthData:
        def __init__(self):
            self.credential_data = FakeCredentialData()

        def __bytes__(self) -> bytes:  # pragma: no cover - simple helper
            return b"auth-data"

    attestation_object = SimpleNamespace(
        fmt="packed",
        att_stmt={"alg": -48, "sig": b"\x01\x02"},
        auth_data=FakeAuthData(),
    )

    class FakeCoseKey(dict):
        ALGORITHM = -48
        verify_calls = []

        def __init__(self, data=None):
            super().__init__(data or {})

        def verify(self, message: bytes, signature: bytes) -> None:
            self.verify_calls.append((message, signature))

    FakeCoseKey.verify_calls = []

    def fake_for_alg(alg: int):
        assert alg == -48
        return FakeCoseKey

    def fake_parse(_cose_data):
        return FakeCoseKey({1: 7, 3: -48, -1: b"fake-public"})

    monkeypatch.setattr(
        attestation_module.CoseKey, "for_alg", staticmethod(fake_for_alg)
    )
    monkeypatch.setattr(
        attestation_module.CoseKey, "parse", staticmethod(fake_parse)
    )

    outcome = attestation_module._attempt_pqc_attestation_signature_validation(
        attestation_object, b"hash"
    )

    assert outcome["attempted"] is True
    assert outcome["success"] is True
    assert isinstance(outcome["attestation_result"], attestation_module.AttestationResult)
    assert (
        outcome["attestation_result"].attestation_type
        == attestation_module.AttestationType.SELF
    )
    assert FakeCoseKey.verify_calls == [(b"auth-datahash", b"\x01\x02")]


def test_pqc_attestation_fallback_ignored_for_non_pqc_algorithm():
    attestation_object = SimpleNamespace(
        fmt="packed", att_stmt={"alg": -7, "sig": b"\x00"}, auth_data=SimpleNamespace()
    )

    outcome = attestation_module._attempt_pqc_attestation_signature_validation(
        attestation_object, b"hash"
    )

    assert outcome["attempted"] is False
    assert outcome["success"] is False
    assert outcome["attestation_result"] is None


def test_add_public_key_material_serialises_credential_key_bytes():
    credential_key = {1: 2, 3: -48, -1: b"credential-public-key"}
    container: dict[str, object] = {}

    storage.add_public_key_material(container, credential_key)

    assert container["publicKeyCose"][3] == -48  # type: ignore[index]
    assert container["publicKeyType"] == 2
    expected = base64.b64encode(b"credential-public-key").decode("utf-8")
    assert container["publicKeyBytes"] == expected


def test_add_public_key_material_supports_prefixed_fields():
    credential_key = {1: 2, 3: -48, -1: b"prefixed-key"}
    container: dict[str, object] = {}

    storage.add_public_key_material(
        container,
        credential_key,
        field_prefix="credential",
    )

    assert container["credentialPublicKeyCose"][3] == -48  # type: ignore[index]
    assert container["credentialPublicKeyType"] == 2
    expected = base64.b64encode(b"prefixed-key").decode("utf-8")
    assert container["credentialPublicKeyBytes"] == expected
