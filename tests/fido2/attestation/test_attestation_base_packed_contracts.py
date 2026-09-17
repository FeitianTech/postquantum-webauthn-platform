from __future__ import annotations

import datetime
import types

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature as CryptoInvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import fido2.attestation.base as base
import fido2.attestation.packed as packed
from tests.pqc import mldsa_helpers


def test_catch_builtins_wraps_common_exceptions():
    @base.catch_builtins
    def _boom():
        raise KeyError('missing')

    with pytest.raises(base.InvalidData):
        _boom()


def _ec_certificate_der() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'classical')])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_verify_mldsa_certificate_signature_rejects_malformed_input():
    with pytest.raises(base.InvalidSignature, match='Unable to parse ML-DSA certificate'):
        base._verify_mldsa_certificate_signature(b'not a certificate', b'issuer')

    mldsa_der = mldsa_helpers.certificate('ML-DSA-44')
    with pytest.raises(base.InvalidSignature, match='Unable to parse issuer public key'):
        base._verify_mldsa_certificate_signature(mldsa_der, b'not a certificate')

    with pytest.raises(base.InvalidSignature, match='Unsupported signature algorithm OID'):
        base._verify_mldsa_certificate_signature(_ec_certificate_der(), mldsa_der)

    with pytest.raises(base.InvalidSignature, match='not an ML-DSA key'):
        base._verify_mldsa_certificate_signature(mldsa_der, _ec_certificate_der())

    # Issuer holds an ML-DSA key of a different parameter set than the one the
    # certificate says signed it.
    with pytest.raises(base.InvalidSignature, match='does not match the certificate'):
        base._verify_mldsa_certificate_signature(
            mldsa_der, mldsa_helpers.certificate('ML-DSA-65')
        )


@pytest.mark.parametrize('parameter_set', mldsa_helpers.PARAMETER_SETS)
def test_verify_mldsa_certificate_signature_accepts_only_the_real_issuer(parameter_set):
    issued = mldsa_helpers.certificate(
        parameter_set,
        label='leaf',
        issuer_label='ca',
        common_name=f'{parameter_set} leaf',
    )
    real_issuer = mldsa_helpers.certificate(parameter_set, label='ca', ca=True)
    other_issuer = mldsa_helpers.certificate(parameter_set, label='impostor', ca=True)

    base._verify_mldsa_certificate_signature(issued, real_issuer)
    base.verify_x509_chain([issued, real_issuer])

    with pytest.raises(base.InvalidSignature, match='verification failed'):
        base._verify_mldsa_certificate_signature(issued, other_issuer)
    with pytest.raises(base.InvalidSignature):
        base.verify_x509_chain([issued, other_issuer])

    # A single flipped bit anywhere in the signed certificate is rejected.
    tampered = bytearray(issued)
    tampered[-1] ^= 0x01
    with pytest.raises(base.InvalidSignature, match='verification failed'):
        base._verify_mldsa_certificate_signature(bytes(tampered), real_issuer)


class _FakeVerifier(base.AttestationVerifier):
    def __init__(self, attestation_types=None, ca=b'root'):
        super().__init__(attestation_types)
        self._ca = ca

    def ca_lookup(self, attestation_result, auth_data):
        if self._ca == b'raise':
            raise RuntimeError('lookup failed')
        return self._ca


class _FakeAttestation(base.Attestation):
    FORMAT = 'fake'

    def __init__(self, result=None, to_raise=None):
        self.result = result
        self.to_raise = to_raise

    def verify(self, statement, auth_data, client_data_hash):
        if self.to_raise:
            raise self.to_raise
        return self.result


def _att_obj(fmt='fake', att_stmt=None, auth_data=None):
    return types.SimpleNamespace(fmt=fmt, att_stmt=att_stmt or {}, auth_data=auth_data or b'auth')


def test_validate_cert_common_and_attestation_verifier_paths(monkeypatch):
    cert_v2 = types.SimpleNamespace(version=x509.Version.v1)
    with pytest.raises(base.InvalidData, match='version 3'):
        base._validate_cert_common(cert_v2)

    cert_ca_true = types.SimpleNamespace(
        version=x509.Version.v3,
        extensions=types.SimpleNamespace(
            get_extension_for_class=lambda _cls: types.SimpleNamespace(value=types.SimpleNamespace(ca=True))
        ),
    )
    with pytest.raises(base.InvalidData, match='CA=false'):
        base._validate_cert_common(cert_ca_true)

    cert_no_bc = types.SimpleNamespace(
        version=x509.Version.v3,
        extensions=types.SimpleNamespace(
            get_extension_for_class=lambda _cls: (_ for _ in ()).throw(x509.ExtensionNotFound('missing', None))
        ),
    )
    with pytest.raises(base.InvalidData, match='Basic Constraints'):
        base._validate_cert_common(cert_no_bc)

    result = base.AttestationResult(base.AttestationType.BASIC, [b'leaf'])

    # InvalidData from verifier
    verifier = _FakeVerifier(attestation_types=[_FakeAttestation(to_raise=base.InvalidData('bad'))])
    details = verifier.collect_trust_path_details(_att_obj(), b'hash')
    assert details.attestation_result is None
    assert details.chain_valid is False

    # unexpected verifier error
    verifier = _FakeVerifier(attestation_types=[_FakeAttestation(to_raise=RuntimeError('boom'))])
    details = verifier.collect_trust_path_details(_att_obj(), b'hash')
    assert details.attestation_result is None

    # ca lookup error
    verifier = _FakeVerifier(attestation_types=[_FakeAttestation(result=result)], ca=b'raise')
    details = verifier.collect_trust_path_details(_att_obj(), b'hash')
    assert details.attestation_result == result
    assert details.ca_certificate is None

    # no CA
    verifier = _FakeVerifier(attestation_types=[_FakeAttestation(result=result)], ca=None)
    details = verifier.collect_trust_path_details(_att_obj(), b'hash')
    assert details.attestation_result == result
    assert details.chain_valid is False

    # invalid trust chain
    verifier = _FakeVerifier(attestation_types=[_FakeAttestation(result=result)], ca=b'root')
    monkeypatch.setattr(base, 'verify_x509_chain', lambda _chain: (_ for _ in ()).throw(base.InvalidSignature('bad sig')))
    details = verifier.collect_trust_path_details(_att_obj(), b'hash')
    assert details.chain_valid is False
    assert details.errors

    # generic trust chain error
    monkeypatch.setattr(base, 'verify_x509_chain', lambda _chain: (_ for _ in ()).throw(RuntimeError('chain boom')))
    details = verifier.collect_trust_path_details(_att_obj(), b'hash')
    assert details.chain_valid is False

    # success
    monkeypatch.setattr(base, 'verify_x509_chain', lambda _chain: None)
    details = verifier.collect_trust_path_details(_att_obj(), b'hash')
    assert details.chain_valid is True

    # verify_attestation unhappy paths
    v = _FakeVerifier(attestation_types=[_FakeAttestation(result=result)], ca=b'root')
    monkeypatch.setattr(v, 'collect_trust_path_details', lambda *_args: base.TrustPathEvaluation(None, None, False, ['x']))
    with pytest.raises(base.UntrustedAttestation, match='x'):
        v.verify_attestation(_att_obj(), b'h')

    monkeypatch.setattr(v, 'collect_trust_path_details', lambda *_args: base.TrustPathEvaluation(None, None, False, []))
    with pytest.raises(base.UntrustedAttestation, match='Untrusted attestation'):
        v.verify_attestation(_att_obj(), b'h')

    monkeypatch.setattr(v, 'collect_trust_path_details', lambda *_args: base.TrustPathEvaluation(result, None, False, []))
    with pytest.raises(base.UntrustedAttestation, match='No root found'):
        v.verify_attestation(_att_obj(), b'h')

    monkeypatch.setattr(v, 'collect_trust_path_details', lambda *_args: base.TrustPathEvaluation(result, b'ca', False, ['bad chain']))
    with pytest.raises(base.UntrustedAttestation, match='bad chain'):
        v.verify_attestation(_att_obj(), b'h')

    monkeypatch.setattr(v, 'collect_trust_path_details', lambda *_args: base.TrustPathEvaluation(result, b'ca', False, []))
    with pytest.raises(base.UntrustedAttestation, match='Invalid attestation trust path'):
        v.verify_attestation(_att_obj(), b'h')

    # __call__ delegates
    called = []
    monkeypatch.setattr(v, 'verify_attestation', lambda *args: called.append(args))
    v(_att_obj(), b'h')
    assert called


def test_base_verify_x509_chain_and_dispatch_edge_paths(monkeypatch):
    child = types.SimpleNamespace(
        signature=b'sig',
        tbs_certificate_bytes=b'tbs',
        signature_hash_algorithm=object(),
    )

    # public_key() ValueError -> pub=None -> unsupported signature key type
    issuer_value_error = types.SimpleNamespace(public_key=lambda: (_ for _ in ()).throw(ValueError('bad pub')))
    certs = [child, issuer_value_error]
    monkeypatch.setattr(base.x509, 'load_der_x509_certificate', lambda *_args, **_kwargs: certs.pop(0))

    with pytest.raises(ValueError, match='Unsupported signature key type'):
        base.verify_x509_chain([b'child', b'issuer'])

    # RSA verify raises cryptography InvalidSignature -> mapped to base.InvalidSignature
    class _FakeRSA:
        def verify(self, *_args, **_kwargs):
            raise CryptoInvalidSignature()

    monkeypatch.setattr(base.rsa, 'RSAPublicKey', _FakeRSA)
    issuer_bad_sig = types.SimpleNamespace(public_key=lambda: _FakeRSA())
    certs = [child, issuer_bad_sig]
    monkeypatch.setattr(base.x509, 'load_der_x509_certificate', lambda *_args, **_kwargs: certs.pop(0))

    with pytest.raises(base.InvalidSignature):
        base.verify_x509_chain([b'child', b'issuer'])

    # _default_attestations helper should produce concrete instances.
    defaults = base._default_attestations()
    assert isinstance(defaults, list)

    # collect_trust_path_details should re-raise UnsupportedType for unsupported format.
    verifier = _FakeVerifier(attestation_types=[])
    with pytest.raises(base.UnsupportedType):
        verifier.collect_trust_path_details(_att_obj(fmt='unknown'), b'h')

    # Loop should continue past non-matching FORMAT and use the matching verifier.
    matched = _FakeAttestation(result=base.AttestationResult(base.AttestationType.BASIC, []))
    matched.FORMAT = 'target'
    non_match = _FakeAttestation(result=base.AttestationResult(base.AttestationType.BASIC, []))
    non_match.FORMAT = 'other'
    verifier = _FakeVerifier(attestation_types=[non_match, matched], ca=b'root')
    monkeypatch.setattr(base, 'verify_x509_chain', lambda _chain: None)
    details = verifier.collect_trust_path_details(_att_obj(fmt='target'), b'h')
    assert details.attestation_result is not None

    # verify_attestation should succeed silently when chain_valid is True.
    good_eval = base.TrustPathEvaluation(
        base.AttestationResult(base.AttestationType.BASIC, []),
        b'root',
        True,
        [],
    )
    verifier = _FakeVerifier(attestation_types=[matched], ca=b'root')
    monkeypatch.setattr(verifier, 'collect_trust_path_details', lambda *_args: good_eval)
    verifier.verify_attestation(_att_obj(fmt='target'), b'h')


def _fake_cert(*, with_bc=True, bc_ca=False, with_c=True, with_o=True, with_ou=True, ou_value='Authenticator Attestation', with_cn=True, ext=None, public_key=None):
    attrs = {
        x509.NameOID.COUNTRY_NAME: [types.SimpleNamespace(value='SE')] if with_c else [],
        x509.NameOID.ORGANIZATION_NAME: [types.SimpleNamespace(value='Org')] if with_o else [],
        x509.NameOID.ORGANIZATIONAL_UNIT_NAME: [types.SimpleNamespace(value=ou_value)] if with_ou else [],
        x509.NameOID.COMMON_NAME: [types.SimpleNamespace(value='CN')] if with_cn else [],
    }

    def _get_attr(oid):
        return attrs.get(oid, [])

    if with_bc:
        ext_obj = types.SimpleNamespace(
            get_extension_for_class=lambda _cls: types.SimpleNamespace(value=types.SimpleNamespace(ca=bc_ca)),
            get_extension_for_oid=lambda _oid: ext if ext is not None else (_ for _ in ()).throw(x509.ExtensionNotFound('missing', None)),
        )
    else:
        ext_obj = types.SimpleNamespace(
            get_extension_for_class=lambda _cls: (_ for _ in ()).throw(x509.ExtensionNotFound('missing', None)),
            get_extension_for_oid=lambda _oid: ext if ext is not None else (_ for _ in ()).throw(x509.ExtensionNotFound('missing', None)),
        )

    cert = types.SimpleNamespace(
        version=x509.Version.v3,
        subject=types.SimpleNamespace(get_attributes_for_oid=_get_attr),
        extensions=ext_obj,
        public_key=(public_key or (lambda: object())),
    )
    return cert


class _AuthData(bytes):
    def __new__(cls, value=b'auth', *, aaguid=b'\x01' * 16, public_key=b'pk'):
        obj = super().__new__(cls, value)
        obj.credential_data = types.SimpleNamespace(aaguid=aaguid, public_key=public_key)
        return obj


def test_packed_helpers_and_verify_paths(monkeypatch):
    # _validate_packed_cert basic subject checks
    with pytest.raises(packed.InvalidData, match='C set'):
        packed._validate_packed_cert(_fake_cert(with_c=False), b'\x01' * 16)
    with pytest.raises(packed.InvalidData, match='O set'):
        packed._validate_packed_cert(_fake_cert(with_o=False), b'\x01' * 16)
    with pytest.raises(packed.InvalidData, match='OU ='):
        packed._validate_packed_cert(_fake_cert(with_ou=False), b'\x01' * 16)
    with pytest.raises(packed.InvalidData, match='OU ='):
        packed._validate_packed_cert(_fake_cert(ou_value='Wrong OU'), b'\x01' * 16)
    with pytest.raises(packed.InvalidData, match='CN set'):
        packed._validate_packed_cert(_fake_cert(with_cn=False), b'\x01' * 16)

    # AAGUID extension checks
    critical_ext = types.SimpleNamespace(critical=True, value=types.SimpleNamespace(value=b'\x04\x10' + b'\x01' * 16))
    with pytest.raises(packed.InvalidData, match='must not be marked as critical'):
        packed._validate_packed_cert(_fake_cert(ext=critical_ext), b'\x01' * 16)

    mismatch_ext = types.SimpleNamespace(critical=False, value=types.SimpleNamespace(value=b'\x04\x10' + b'\x02' * 16))
    with pytest.raises(packed.InvalidData, match='does not match'):
        packed._validate_packed_cert(_fake_cert(ext=mismatch_ext), b'\x01' * 16)

    # Basic Constraints are required for every packed attestation certificate,
    # ML-DSA included: the old exemption was a workaround for the hand-rolled
    # DER parser, not for any real authenticator.
    with pytest.raises(packed.InvalidData, match='Basic Constraints'):
        packed._validate_packed_cert(_fake_cert(with_bc=False), b'\x01' * 16, cert_bytes=b'mldsa')
    with pytest.raises(packed.InvalidData, match='Basic Constraints'):
        packed._validate_packed_cert(_fake_cert(with_bc=False), b'\x01' * 16, cert_bytes=b'normal')

    att = packed.PackedAttestation()
    auth_data = _AuthData()

    # ecdaa unsupported
    with pytest.raises(NotImplementedError):
        att.verify({'ecdaaKeyId': b'x', 'alg': -7, 'sig': b'sig'}, auth_data, b'h')

    class _PubKey:
        def __init__(self, fail=False):
            self.fail = fail

        def verify(self, _data, _sig):
            if self.fail:
                raise CryptoInvalidSignature()

    class _CoseCls:
        ALGORITHM = -48

        def __init__(self, _params=None):
            self._k = _PubKey()

        def verify(self, data, sig):
            return self._k.verify(data, sig)

        @classmethod
        def from_cryptography_key(cls, _key):
            return _PubKey()

    monkeypatch.setattr(packed, '_validate_packed_cert', lambda *args, **kwargs: None)
    monkeypatch.setattr(packed.x509, 'load_der_x509_certificate', lambda *_args, **_kwargs: _fake_cert(public_key=lambda: object()))
    monkeypatch.setattr(packed.CoseKey, 'for_alg', lambda _alg: _CoseCls)

    res = att.verify({'alg': -48, 'sig': b'sig', 'x5c': [b'cert']}, auth_data, b'h')
    assert res.attestation_type == base.AttestationType.BASIC

    # fallback pubkey extraction path
    def _unsupported_pk():
        raise packed.UnsupportedAlgorithm('x')

    monkeypatch.setattr(packed.x509, 'load_der_x509_certificate', lambda *_args, **_kwargs: _fake_cert(public_key=_unsupported_pk))
    monkeypatch.setattr(packed, 'extract_certificate_public_key_info', lambda _cert: {'subject_public_key': b'pk'})
    res = att.verify({'alg': -48, 'sig': b'sig', 'x5c': [b'cert']}, auth_data, b'h')
    assert res.attestation_type == base.AttestationType.BASIC

    # fallback re-raise path (missing subject_public_key)
    monkeypatch.setattr(packed, 'extract_certificate_public_key_info', lambda _cert: {'subject_public_key': None})
    with pytest.raises(packed.UnsupportedAlgorithm):
        att.verify({'alg': -48, 'sig': b'sig', 'x5c': [b'cert']}, auth_data, b'h')

    # self-attestation path with algorithm mismatch
    monkeypatch.setattr(packed.CoseKey, 'parse', lambda _pk: types.SimpleNamespace(ALGORITHM=-7, verify=lambda _d, _s: None))
    with pytest.raises(packed.InvalidData, match='Wrong algorithm'):
        att.verify({'alg': -8, 'sig': b'sig'}, auth_data, b'h')

    # self-attestation success
    monkeypatch.setattr(packed.CoseKey, 'parse', lambda _pk: types.SimpleNamespace(ALGORITHM=-7, verify=lambda _d, _s: None))
    res = att.verify({'alg': -7, 'sig': b'sig'}, auth_data, b'h')
    assert res.attestation_type == base.AttestationType.SELF

    # signature failure mapping
    monkeypatch.setattr(packed.CoseKey, 'parse', lambda _pk: types.SimpleNamespace(ALGORITHM=-7, verify=lambda _d, _s: (_ for _ in ()).throw(CryptoInvalidSignature())))
    with pytest.raises(packed.InvalidSignature):
        att.verify({'alg': -7, 'sig': b'sig'}, auth_data, b'h')
