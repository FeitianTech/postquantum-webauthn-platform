import hashlib
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from fido2.server import Fido2Server
from fido2.utils import websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestedCredentialData,
    AuthenticationResponse,
    AuthenticatorAssertionResponse,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    UserVerificationRequirement,
)
from fido2.attestation import AttestationResult, AttestationType, UntrustedAttestation

from unittest import mock

from .test_ctap2 import _ATT_CRED_DATA, _CRED_ID

from server.server.attestation import perform_attestation_checks


class TestPublicKeyCredentialRpEntity(unittest.TestCase):
    def test_id_hash(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        rp_id_hash = (
            b"\xa3y\xa6\xf6\xee\xaf\xb9\xa5^7\x8c\x11\x804\xe2u\x1eh/"
            b"\xab\x9f-0\xab\x13\xd2\x12U\x86\xce\x19G"
        )
        self.assertEqual(rp.id_hash, rp_id_hash)


USER = {"id": b"user_id", "name": "A. User"}


class TestFido2Server(unittest.TestCase):
    def test_register_begin_rp(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        request, state = server.register_begin(USER)

        self.assertEqual(
            request["publicKey"]["rp"], {"id": "example.com", "name": "Example"}
        )

    def test_register_begin_custom_challenge(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        challenge = b"1234567890123456"
        request, state = server.register_begin(USER, challenge=challenge)

        self.assertEqual(request["publicKey"]["challenge"], websafe_encode(challenge))

    def test_register_begin_custom_challenge_too_short(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        challenge = b"123456789012345"
        with self.assertRaises(ValueError):
            request, state = server.register_begin(USER, challenge=challenge)

    def test_authenticate_complete_invalid_signature(self):
        rp = PublicKeyCredentialRpEntity(name="Example", id="example.com")
        server = Fido2Server(rp)

        state = {
            "challenge": "GAZPACHO!",
            "user_verification": UserVerificationRequirement.PREFERRED,
        }
        client_data = CollectedClientData.create(
            CollectedClientData.TYPE.GET,
            "GAZPACHO!",
            "https://example.com",
        )
        _AUTH_DATA = bytes.fromhex(
            "A379A6F6EEAFB9A55E378C118034E2751E682FAB9F2D30AB13D2125586CE1947010000001D"
        )
        response = AuthenticationResponse(
            id=_CRED_ID,
            response=AuthenticatorAssertionResponse(
                client_data=client_data,
                authenticator_data=AuthenticatorData(_AUTH_DATA),
                signature=b"INVALID",
            ),
        )

        with self.assertRaisesRegex(ValueError, "Invalid signature."):
            server.authenticate_complete(
                state,
                [AttestedCredentialData(_ATT_CRED_DATA)],
                response,
            )


class TestPerformAttestationChecks(unittest.TestCase):
    def test_pqc_metadata_failure_marks_root_invalid(self):
        trust_path = [b"leaf-cert", b"root-cert"]

        client_data = SimpleNamespace(
            type=CollectedClientData.TYPE.CREATE.value,
            challenge=b"challenge",
            origin="https://example.com",
            cross_origin=False,
            hash=b"\x00" * 32,
        )

        credential_data = SimpleNamespace(
            credential_id=b"id",
            public_key={3: -999},
            aaguid=Aaguid.fromhex("0" * 32),
        )

        class DummyAuthData:
            def __init__(self, cred):
                self.rp_id_hash = hashlib.sha256("example.com".encode("utf-8")).digest()
                self.flags = (
                    AuthenticatorData.FLAG.UP
                    | AuthenticatorData.FLAG.AT
                )
                self.counter = 1
                self.credential_data = cred

            def __bytes__(self):
                return b"auth-data"

        attestation_object = SimpleNamespace(
            fmt="dummy-pqc",
            auth_data=DummyAuthData(credential_data),
            att_stmt={"x5c": trust_path},
        )

        registration = SimpleNamespace(
            response=SimpleNamespace(
                client_data=client_data,
                attestation_object=attestation_object,
            )
        )

        class DummyAttestation:
            def __call__(self):
                return self

            def verify(self, statement, auth_data, client_data_hash):
                return AttestationResult(AttestationType.BASIC, trust_path)

        class DummyVerifier:
            def find_entry(self, attestation_obj, client_hash):
                raise UntrustedAttestation("metadata missing")

        class DummyName:
            def rfc4514_string(self):
                return "CN=Dummy"

        class DummyCertificate:
            signature_algorithm_oid = SimpleNamespace(dotted_string="1.2.3.4")
            subject = DummyName()
            issuer = DummyName()
            not_valid_before = datetime(2020, 1, 1, tzinfo=timezone.utc)
            not_valid_after = datetime(2030, 1, 1, tzinfo=timezone.utc)

        with mock.patch(
            "server.server.attestation.RegistrationResponse.from_dict",
            return_value=registration,
        ), mock.patch(
            "server.server.attestation.Attestation.for_type",
            return_value=DummyAttestation,
        ), mock.patch(
            "server.server.attestation.CoseKey.parse",
            return_value=None,
        ), mock.patch(
            "server.server.attestation.get_mds_verifier",
            return_value=DummyVerifier(),
        ), mock.patch(
            "server.server.attestation.is_pqc_algorithm",
            side_effect=lambda alg: alg == -999,
        ), mock.patch(
            "server.server.attestation.describe_mldsa_oid",
            return_value={"ml_dsa_parameter_set": "ML-DSA-65"},
        ), mock.patch(
            "server.server.attestation.x509.load_der_x509_certificate",
            return_value=DummyCertificate(),
        ):
            results = perform_attestation_checks(
                {},
                None,
                None,
                None,
                "https://example.com",
                "example.com",
            )

        self.assertFalse(results.get("root_valid"))
        self.assertIn("pqc_metadata_verification_failed", results.get("warnings", []))
        self.assertTrue(
            any(
                msg.startswith("pqc_attestation_trust_verification_failed")
                for msg in results.get("errors", [])
            )
        )

    def test_pqc_metadata_absent_reports_not_applicable(self):
        trust_path = [b"leaf-cert", b"root-cert"]

        client_data = SimpleNamespace(
            type=CollectedClientData.TYPE.CREATE.value,
            challenge=b"challenge",
            origin="https://example.com",
            cross_origin=False,
            hash=b"\x00" * 32,
        )

        credential_data = SimpleNamespace(
            credential_id=b"id",
            public_key={3: -999},
            aaguid=Aaguid.fromhex("0" * 32),
        )

        class DummyAuthData:
            def __init__(self, cred):
                self.rp_id_hash = hashlib.sha256("example.com".encode("utf-8")).digest()
                self.flags = (
                    AuthenticatorData.FLAG.UP
                    | AuthenticatorData.FLAG.AT
                )
                self.counter = 1
                self.credential_data = cred

            def __bytes__(self):
                return b"auth-data"

        attestation_object = SimpleNamespace(
            fmt="dummy-pqc",
            auth_data=DummyAuthData(credential_data),
            att_stmt={"x5c": trust_path},
        )

        registration = SimpleNamespace(
            response=SimpleNamespace(
                client_data=client_data,
                attestation_object=attestation_object,
            )
        )

        class DummyAttestation:
            def __call__(self):
                return self

            def verify(self, statement, auth_data, client_data_hash):
                return AttestationResult(AttestationType.BASIC, trust_path)

        class DummyVerifier:
            def find_entry(self, attestation_obj, client_hash):
                return None

            def last_verification_error(self):
                return None

        class DummyName:
            def rfc4514_string(self):
                return "CN=Dummy"

        class DummyCertificate:
            signature_algorithm_oid = SimpleNamespace(dotted_string="1.2.3.4")
            subject = DummyName()
            issuer = DummyName()
            not_valid_before = datetime(2020, 1, 1, tzinfo=timezone.utc)
            not_valid_after = datetime(2030, 1, 1, tzinfo=timezone.utc)

        with mock.patch(
            "server.server.attestation.RegistrationResponse.from_dict",
            return_value=registration,
        ), mock.patch(
            "server.server.attestation.Attestation.for_type",
            return_value=DummyAttestation,
        ), mock.patch(
            "server.server.attestation.CoseKey.parse",
            return_value=None,
        ), mock.patch(
            "server.server.attestation.get_mds_verifier",
            return_value=DummyVerifier(),
        ), mock.patch(
            "server.server.attestation.is_pqc_algorithm",
            side_effect=lambda alg: alg == -999,
        ), mock.patch(
            "server.server.attestation.describe_mldsa_oid",
            return_value={"ml_dsa_parameter_set": "ML-DSA-65"},
        ), mock.patch(
            "server.server.attestation.x509.load_der_x509_certificate",
            return_value=DummyCertificate(),
        ):
            results = perform_attestation_checks(
                {},
                None,
                None,
                None,
                "https://example.com",
                "example.com",
            )

        self.assertIsNone(results.get("root_valid"))
        self.assertIn("pqc_metadata_entry_not_found", results.get("warnings", []))
        self.assertFalse(
            any(
                msg.startswith("pqc_attestation_trust_verification_failed")
                for msg in results.get("errors", [])
            )
        )

    def test_pqc_trust_verification_failure_detected_via_last_error(self):
        trust_path = [b"leaf-cert", b"root-cert"]

        client_data = SimpleNamespace(
            type=CollectedClientData.TYPE.CREATE.value,
            challenge=b"challenge",
            origin="https://example.com",
            cross_origin=False,
            hash=b"\x00" * 32,
        )

        credential_data = SimpleNamespace(
            credential_id=b"id",
            public_key={3: -999},
            aaguid=Aaguid.fromhex("0" * 32),
        )

        class DummyAuthData:
            def __init__(self, cred):
                self.rp_id_hash = hashlib.sha256("example.com".encode("utf-8")).digest()
                self.flags = (
                    AuthenticatorData.FLAG.UP
                    | AuthenticatorData.FLAG.AT
                )
                self.counter = 1
                self.credential_data = cred

            def __bytes__(self):
                return b"auth-data"

        attestation_object = SimpleNamespace(
            fmt="dummy-pqc",
            auth_data=DummyAuthData(credential_data),
            att_stmt={"x5c": trust_path},
        )

        registration = SimpleNamespace(
            response=SimpleNamespace(
                client_data=client_data,
                attestation_object=attestation_object,
            )
        )

        class DummyAttestation:
            def __call__(self):
                return self

            def verify(self, statement, auth_data, client_data_hash):
                return AttestationResult(AttestationType.BASIC, trust_path)

        class DummyVerifier:
            def find_entry(self, attestation_obj, client_hash):
                return None

            def last_verification_error(self):
                return UntrustedAttestation("signature invalid")

        class DummyName:
            def rfc4514_string(self):
                return "CN=Dummy"

        class DummyCertificate:
            signature_algorithm_oid = SimpleNamespace(dotted_string="1.2.3.4")
            subject = DummyName()
            issuer = DummyName()
            not_valid_before = datetime(2020, 1, 1, tzinfo=timezone.utc)
            not_valid_after = datetime(2030, 1, 1, tzinfo=timezone.utc)

        with mock.patch(
            "server.server.attestation.RegistrationResponse.from_dict",
            return_value=registration,
        ), mock.patch(
            "server.server.attestation.Attestation.for_type",
            return_value=DummyAttestation,
        ), mock.patch(
            "server.server.attestation.CoseKey.parse",
            return_value=None,
        ), mock.patch(
            "server.server.attestation.get_mds_verifier",
            return_value=DummyVerifier(),
        ), mock.patch(
            "server.server.attestation.is_pqc_algorithm",
            side_effect=lambda alg: alg == -999,
        ), mock.patch(
            "server.server.attestation.describe_mldsa_oid",
            return_value={"ml_dsa_parameter_set": "ML-DSA-65"},
        ), mock.patch(
            "server.server.attestation.x509.load_der_x509_certificate",
            return_value=DummyCertificate(),
        ):
            results = perform_attestation_checks(
                {},
                None,
                None,
                None,
                "https://example.com",
                "example.com",
            )

        self.assertFalse(results.get("root_valid"))
        self.assertTrue(
            any(
                msg.startswith("pqc_attestation_trust_verification_failed")
                for msg in results.get("errors", [])
            )
        )
        self.assertNotIn(
            "pqc_metadata_entry_not_found", results.get("warnings", [])
        )
