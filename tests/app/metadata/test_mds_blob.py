"""``mds.blob``: the MDS BLOB's chain to the pinned root, its signature, and its payload.

The chains are real certificates in the shape the FIDO BLOB has: a signing
certificate, its CA, and a cross-certificate from the pinned root's older
sibling (R3 to R46), which the path to the pinned root does not need.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature as CryptographyInvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID
from fido2.attestation import InvalidSignature, verify_x509_chain
from fido2.utils import websafe_encode

from server.app.mds import blob as mds_blob

_NOW = datetime.now(timezone.utc)


def _certificate(
    *, subject: str, issuer: str, public_key, issuer_key, ca: bool = True, expired: bool = False
) -> bytes:
    """A certificate; a CA's carries Basic Constraints, as the real chain's do."""

    not_after = _NOW - timedelta(hours=1) if expired else _NOW + timedelta(days=30)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - timedelta(days=1))
        .not_valid_after(not_after)
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _transition():
    """A signing chain whose x5c ends in the R3-to-R46 cross-certificate."""

    legacy, current, intermediate, leaf = _rsa(), _rsa(), _rsa(), ec.generate_private_key(ec.SECP256R1())
    unrelated = _rsa()
    return SimpleNamespace(
        leaf=_certificate(
            subject="mds.example.org", issuer="Intermediate CA", public_key=leaf.public_key(), issuer_key=intermediate, ca=False
        ),
        intermediate=_certificate(subject="Intermediate CA", issuer="Root R46", public_key=intermediate.public_key(), issuer_key=current),
        cross=_certificate(subject="Root R46", issuer="Root R3", public_key=current.public_key(), issuer_key=legacy),
        current_root=_certificate(subject="Root R46", issuer="Root R46", public_key=current.public_key(), issuer_key=current),
        legacy_root=_certificate(subject="Root R3", issuer="Root R3", public_key=legacy.public_key(), issuer_key=legacy),
        unrelated=_certificate(subject="Unrelated", issuer="Unrelated", public_key=unrelated.public_key(), issuer_key=unrelated),
        leaf_key=leaf,
        intermediate_key=intermediate,
        current_key=current,
    )


def _segment(value: dict) -> bytes:
    return websafe_encode(json.dumps(value).encode()).encode("ascii")


def _payload() -> dict:
    return {
        "legalHeader": "demo",
        "no": 1,
        "nextUpdate": "2099-01-01",
        "entries": [{"statusReports": [{"status": "FIDO_CERTIFIED"}], "timeOfLastStatusChange": "2020-01-01"}],
    }


def _blob(header: dict, payload: dict, key) -> bytes:
    message = _segment(header) + b"." + _segment(payload)
    return message + b"." + websafe_encode(key.sign(message, ec.ECDSA(hashes.SHA256()))).encode("ascii")


def _x5c(*certificates: bytes) -> list[str]:
    return [base64.b64encode(certificate).decode("ascii") for certificate in certificates]


def test_a_chain_ending_in_a_cross_certificate_reaches_either_root():
    certs = _transition()
    chain = [certs.leaf, certs.intermediate, certs.cross]

    # As one straight chain (fido2's parse_blob) the pinned root is refused.
    with pytest.raises(InvalidSignature):
        verify_x509_chain(chain + [certs.current_root])

    mds_blob.verify_chain_to_root(chain, certs.current_root)
    mds_blob.verify_chain_to_root(chain, certs.legacy_root)
    mds_blob.verify_chain_to_root([certs.leaf, certs.intermediate], certs.current_root)
    with pytest.raises(InvalidSignature):
        mds_blob.verify_chain_to_root(chain, certs.unrelated)


def test_a_path_through_an_expired_or_unconstrained_ca_is_refused():
    certs = _transition()
    expired = _certificate(
        subject="Intermediate CA", issuer="Root R46", public_key=certs.intermediate_key.public_key(),
        issuer_key=certs.current_key, expired=True,
    )
    unconstrained = _certificate(
        subject="Intermediate CA", issuer="Root R46", public_key=certs.intermediate_key.public_key(),
        issuer_key=certs.current_key, ca=False,
    )

    for intermediate in (expired, unconstrained):
        with pytest.raises(InvalidSignature, match="No path to the pinned root"):
            mds_blob.verify_chain_to_root([certs.leaf, intermediate], certs.current_root)
    # Checked at the time given: a day ago the expired one was still valid.
    mds_blob.verify_chain_to_root([certs.leaf, expired], certs.current_root, now=_NOW - timedelta(hours=2))


def test_no_x5c_means_the_root_signed_the_blob():
    key = ec.generate_private_key(ec.SECP256R1())
    root = _certificate(subject="Signer", issuer="Signer", public_key=key.public_key(), issuer_key=key)

    assert mds_blob.verify_blob(_blob({"alg": "ES256"}, _payload(), key), root) == _payload()


def test_a_blob_with_the_cross_certificate_in_x5c_verifies_and_keeps_its_json():
    certs = _transition()
    payload = {**_payload(), "notModelled": {"kept": True}}
    header = {"alg": "ES256", "x5c": _x5c(certs.leaf, certs.intermediate, certs.cross)}

    assert mds_blob.verify_blob(_blob(header, payload, certs.leaf_key), certs.current_root) == payload


def test_a_blob_signed_by_another_key_is_refused():
    certs = _transition()
    header = {"alg": "ES256", "x5c": _x5c(certs.leaf, certs.intermediate)}

    with pytest.raises(CryptographyInvalidSignature):
        mds_blob.verify_blob(_blob(header, _payload(), ec.generate_private_key(ec.SECP256R1())), certs.current_root)


def test_a_payload_that_is_not_a_json_object_is_refused():
    certs = _transition()
    header = {"alg": "ES256", "x5c": _x5c(certs.leaf, certs.intermediate)}

    with pytest.raises(ValueError, match="not a JSON object"):
        mds_blob.verify_blob(_blob(header, ["not", "an", "object"], certs.leaf_key), certs.current_root)


def test_the_payload_is_given_as_json_unparsed_into_fido2s_dataclasses():
    certs = _transition()
    header = {"alg": "ES256", "x5c": _x5c(certs.leaf, certs.intermediate)}
    unparseable = {"entries": "not a list"}

    assert mds_blob.verify_blob(_blob(header, unparseable, certs.leaf_key), certs.current_root) == unparseable


def test_a_blob_is_checked_at_the_time_given():
    certs = _transition()
    expired = _certificate(
        subject="Intermediate CA", issuer="Root R46", public_key=certs.intermediate_key.public_key(),
        issuer_key=certs.current_key, expired=True,
    )
    blob = _blob({"alg": "ES256", "x5c": _x5c(certs.leaf, expired)}, _payload(), certs.leaf_key)

    with pytest.raises(InvalidSignature, match="No path to the pinned root"):
        mds_blob.verify_blob(blob, certs.current_root)
    assert mds_blob.verify_blob(blob, certs.current_root, now=_NOW - timedelta(hours=2)) == _payload()


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _resigned(der: bytes, issuer_key, old: bytes, new: bytes) -> bytes:
    """``der`` with ``old`` replaced by ``new`` in its body, signed again by ``issuer_key``."""

    tbs = x509.load_der_x509_certificate(der.replace(old, new)).tbs_certificate_bytes
    algorithm = bytes.fromhex("300d06092a864886f70d01010b0500")  # sha256WithRSAEncryption
    assert algorithm in der
    signature = b"\x00" + issuer_key.sign(tbs, padding.PKCS1v15(), hashes.SHA256())
    body = tbs + algorithm + b"\x03" + _der_length(len(signature)) + signature
    return b"\x30" + _der_length(len(body)) + body


def test_a_signing_certificate_whose_key_does_not_load_is_refused():
    certs = _transition()
    point = certs.leaf_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    # A point off the curve, in a certificate its issuer signed.
    leaf = _resigned(certs.leaf, certs.intermediate_key, point, point[:-1] + bytes([point[-1] ^ 1]))
    blob = _blob({"alg": "ES256", "x5c": _x5c(leaf, certs.intermediate)}, _payload(), certs.leaf_key)

    with pytest.raises(ValueError, match="does not expose a supported public key"):
        mds_blob.verify_blob(blob, certs.current_root)


@pytest.mark.parametrize(
    ("segment", "spelling"),
    [(0, "padded"), (1, "padded"), (2, "padded"), (1, "standard"), (1, "spaced"), (2, "spaced")],
)
def test_a_segment_not_written_as_unpadded_base64url_is_refused_even_when_signed(segment, spelling):
    key = ec.generate_private_key(ec.SECP256R1())
    root = _certificate(subject="Signer", issuer="Signer", public_key=key.public_key(), issuer_key=key)
    parts = _blob({"alg": "ES256"}, {**_payload(), "legalHeader": "~~~?"}, key).split(b".")
    if spelling == "padded":
        parts[segment] += b"=" * (-len(parts[segment]) % 4 or 4)
    elif spelling == "standard":
        parts[segment] = parts[segment].replace(b"-", b"+").replace(b"_", b"/")
        assert b"+" in parts[segment] or b"/" in parts[segment]
    else:
        parts[segment] = parts[segment][:8] + b" " + parts[segment][8:]
    message = parts[0] + b"." + parts[1]
    if segment < 2:
        parts[2] = websafe_encode(key.sign(message, ec.ECDSA(hashes.SHA256()))).encode("ascii")

    with pytest.raises(ValueError):
        mds_blob.verify_blob(message + b"." + parts[2], root)


def test_an_x5c_certificate_in_base64url_is_refused():
    certs = _transition()
    leaf = base64.urlsafe_b64encode(certs.leaf).decode("ascii")
    assert "-" in leaf or "_" in leaf
    header = {"alg": "ES256", "x5c": [leaf, *_x5c(certs.intermediate)]}

    with pytest.raises(ValueError):
        mds_blob.verify_blob(_blob(header, _payload(), certs.leaf_key), certs.current_root)
