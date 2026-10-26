"""``mds.revocation``: the MDS BLOB's signing chain against its issuers' CRLs.

The chain is the fixture's (``mds_fixture.chain_certificate``): a signing certificate,
the CA that issued it and the root, each certificate below the root naming the CRL its
issuer publishes, which ``mds_fixture.crl`` signs. ``mds_fixture.CrlServer`` serves
them by URL; nothing goes to the network.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

from server.app.mds import revocation
from tests.app.metadata import mds_fixture

NOW = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
CA_URL = mds_fixture.CA_CRL_URL
ROOT_URL = mds_fixture.ROOT_CRL_URL
MIRROR_URL = "http://mirror.fixture.example/ca.crl"
LEAF_UNKNOWN = "No current CRL says whether mds.fixture.example (serial 1b5b) is revoked"
UNREADABLE_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1")


def _certificate(name: str, extensions: list | None = None) -> x509.Certificate:
    return x509.load_der_x509_certificate(mds_fixture.chain_certificate(name, extensions))


def _path(leaf: x509.Certificate | None = None, ca: x509.Certificate | None = None) -> list[x509.Certificate]:
    """The path from the signing certificate to the root, as ``mds.blob`` finds it."""

    return [leaf or _certificate("leaf"), ca or _certificate("ca"), _certificate("root")]


def _unknown(served: mds_fixture.CrlServer, path: list[x509.Certificate] | None = None) -> str:
    with pytest.raises(revocation.RevocationUnknown) as raised:
        revocation.check_path(path or _path(), served, now=NOW)
    return str(raised.value)


def _scope(**fields) -> x509.IssuingDistributionPoint:
    """An issuing distribution point with ``fields`` set and the rest unset."""

    unset = {
        "full_name": None,
        "relative_name": None,
        "only_contains_user_certs": False,
        "only_contains_ca_certs": False,
        "only_some_reasons": None,
        "indirect_crl": False,
        "only_contains_attribute_certs": False,
    }
    return x509.IssuingDistributionPoint(**{**unset, **fields})


def test_a_chain_no_current_crl_lists_passes_with_each_crl_from_its_point():
    served = mds_fixture.CrlServer()
    # Other certificates listed, a CRL number and an extension nobody reads, not critical.
    served[CA_URL] = mds_fixture.crl(
        "ca",
        revoked=[0x1234, 0x5678],
        reason=x509.ReasonFlags.key_compromise,
        extensions=[(x509.CRLNumber(42), False), (x509.UnrecognizedExtension(UNREADABLE_OID, b"\x05\x00"), False)],
    )

    revocation.check_path(_path(), served, now=NOW)

    # The leaf's CRL is its CA's, and the CA's the root's; the root is the pin.
    assert served.fetched == [CA_URL, ROOT_URL]


@pytest.mark.parametrize(
    ("url", "issuer", "serial", "reason", "said"),
    [
        (
            CA_URL,
            "ca",
            mds_fixture.chain_serial("leaf"),
            x509.ReasonFlags.key_compromise,
            "mds.fixture.example (serial 1b5b) is revoked (keyCompromise) since 2026-10-01T00:00:00+00:00, "
            f"by the CRL at {CA_URL}",
        ),
        (
            ROOT_URL,
            "root",
            mds_fixture.chain_serial("ca"),
            None,
            f"Fixture MDS CA (serial 1b5a) is revoked since 2026-10-01T00:00:00+00:00, by the CRL at {ROOT_URL}",
        ),
    ],
)
def test_a_certificate_its_issuers_current_crl_lists_is_revoked(url, issuer, serial, reason, said):
    served = mds_fixture.CrlServer()
    served[url] = mds_fixture.crl(issuer, revoked=[serial], reason=reason)

    with pytest.raises(revocation.CertificateRevoked) as raised:
        revocation.check_path(_path(), served, now=NOW)

    assert str(raised.value) == said


def test_the_root_is_the_pin_and_never_looked_up():
    served = mds_fixture.CrlServer()
    served[ROOT_URL] = mds_fixture.crl("root", revoked=[mds_fixture.chain_serial("root")])

    revocation.check_path(_path(), served, now=NOW)
    revocation.check_path([_certificate("root")], served, now=NOW)

    assert served.fetched == [CA_URL, ROOT_URL]


@pytest.mark.parametrize(
    ("times", "said"),
    [
        ({"next_update": NOW - timedelta(days=1)}, "out of date since its nextUpdate, 2026-10-24T12:00:00+00:00"),
        ({"this_update": NOW + timedelta(hours=1)}, "not current before its thisUpdate, 2026-10-25T13:00:00+00:00"),
    ],
)
def test_a_crl_that_is_not_current_says_nothing(times, said):
    served = mds_fixture.CrlServer()
    # Even of a certificate it lists: a CRL out of date says nothing either way.
    served[CA_URL] = mds_fixture.crl("ca", revoked=[mds_fixture.chain_serial("leaf")], **times)

    assert _unknown(served) == f"{LEAF_UNKNOWN}: {CA_URL}: {said}"


def _sequence(body: bytes) -> bytes:
    """A DER SEQUENCE of ``body``, its length in the short form or the long."""

    size = len(body)
    octets = (size.bit_length() + 7) // 8
    length = bytes([size]) if size < 0x80 else bytes([0x80 | octets]) + size.to_bytes(octets, "big")
    return b"\x30" + length + body


def _without_next_update(der: bytes) -> bytes:
    """The CA's CRL ``der`` without the nextUpdate cryptography always writes, signed again."""

    crl = x509.load_der_x509_crl(der)
    tbs = crl.tbs_certlist_bytes
    # A GeneralizedTime (the date is past 2049), right after thisUpdate.
    next_update = b"\x18\x0f" + crl.next_update_utc.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    assert tbs.count(next_update) == 1
    header = 2 + (tbs[1] & 0x7F if tbs[1] & 0x80 else 0)
    tbs = _sequence(tbs[header:].replace(next_update, b""))
    signature = mds_fixture.chain_key("ca").sign(tbs, ec.ECDSA(hashes.SHA256()))
    ecdsa_with_sha256 = bytes.fromhex("300a06082a8648ce3d040302")
    return _sequence(tbs + ecdsa_with_sha256 + b"\x03" + bytes([len(signature) + 1, 0]) + signature)


def test_a_crl_without_a_next_update_is_never_current():
    served = mds_fixture.CrlServer()
    served[CA_URL] = _without_next_update(served[CA_URL])
    assert x509.load_der_x509_crl(served[CA_URL]).next_update_utc is None

    assert _unknown(served) == f"{LEAF_UNKNOWN}: {CA_URL}: no nextUpdate, so never current"


@pytest.mark.parametrize(
    ("served_as", "said"),
    [("nothing", f"{CA_URL} is unreachable"), ("garbage", "not a CRL in DER"), ("PEM", "not a CRL in DER")],
)
def test_a_crl_that_cannot_be_fetched_or_read_says_nothing(served_as, said):
    served = mds_fixture.CrlServer()
    if served_as == "nothing":
        del served[CA_URL]
    elif served_as == "garbage":
        served[CA_URL] = b"<html>Not Found</html>"
    else:
        served[CA_URL] = x509.load_der_x509_crl(served[CA_URL]).public_bytes(serialization.Encoding.PEM)

    assert _unknown(served) == f"{LEAF_UNKNOWN}: {CA_URL}: {said}"


def test_another_issuers_crl_says_nothing():
    served = mds_fixture.CrlServer()
    served[CA_URL] = mds_fixture.crl("root")
    root, ca = (_certificate(name).subject.rfc4514_string() for name in ("root", "ca"))

    assert _unknown(served) == f"{LEAF_UNKNOWN}: {CA_URL}: a CRL of {root}, not of {ca}"


def test_a_crl_its_issuer_did_not_sign_says_nothing():
    served = mds_fixture.CrlServer()
    served[CA_URL] = mds_fixture.crl("ca", signing_key=mds_fixture.chain_key("leaf"))

    assert _unknown(served) == (
        f"{LEAF_UNKNOWN}: {CA_URL}: its signature does not verify with the key of Fixture MDS CA (serial 1b5a)"
    )


def test_an_issuer_that_may_not_sign_crls_says_nothing():
    ca = _certificate(
        "ca",
        [
            (x509.BasicConstraints(ca=True, path_length=0), True),
            (mds_fixture.ca_key_usage(crl_sign=False), True),
            (mds_fixture.crl_distribution_points(ROOT_URL), False),
        ],
    )
    served = mds_fixture.CrlServer()

    assert _unknown(served, _path(ca=ca)) == (
        "Fixture MDS CA (serial 1b5a), which issued mds.fixture.example (serial 1b5b), may not sign CRLs"
    )
    assert served.fetched == []


@pytest.mark.parametrize(
    "points",
    [
        None,
        [x509.DistributionPoint([x509.UniformResourceIdentifier("ldap://ldap.fixture.example/cn=CA")], None, None, None)],
        [
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier(CA_URL)],
                None,
                None,
                [x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Another CRL Issuer")]))],
            )
        ],
        [
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier(CA_URL)], None, frozenset({x509.ReasonFlags.key_compromise}), None
            )
        ],
        [
            x509.DistributionPoint(
                None, x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "CRL1")]), None, None
            )
        ],
    ],
    ids=["no points", "an LDAP URL", "another CRL issuer", "some reasons only", "a name relative to the issuer"],
)
def test_a_certificate_with_no_point_to_fetch_a_complete_crl_from_says_nothing(points):
    leaf = _certificate("leaf", [(x509.CRLDistributionPoints(points), False)] if points else [])
    served = mds_fixture.CrlServer()

    assert _unknown(served, _path(leaf)) == "mds.fixture.example (serial 1b5b) names no CRL distribution point to fetch"
    assert served.fetched == []


def test_a_certificate_without_a_common_name_is_named_by_its_subject():
    ca = _certificate("ca")
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fixture Signer")]))
        .issuer_name(ca.subject)
        .public_key(mds_fixture.chain_key("leaf").public_key())
        .serial_number(0x1B5C)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2099, 1, 1, tzinfo=timezone.utc))
        .sign(mds_fixture.chain_key("ca"), hashes.SHA256())
    )

    assert _unknown(mds_fixture.CrlServer(), _path(leaf, ca)) == (
        "O=Fixture Signer (serial 1b5c) names no CRL distribution point to fetch"
    )


def test_the_points_are_tried_in_order_until_one_gives_a_crl_it_can_use():
    leaf = _certificate("leaf", [(mds_fixture.crl_distribution_points(MIRROR_URL, CA_URL), False)])
    served = mds_fixture.CrlServer()

    revocation.check_path(_path(leaf), served, now=NOW)
    assert served.fetched == [MIRROR_URL, CA_URL, ROOT_URL]

    # With neither usable, each says why.
    served[CA_URL] = mds_fixture.crl("ca", next_update=NOW - timedelta(days=1))
    assert _unknown(served, _path(leaf)) == (
        f"{LEAF_UNKNOWN}: {MIRROR_URL}: {MIRROR_URL} is unreachable; "
        f"{CA_URL}: out of date since its nextUpdate, 2026-10-24T12:00:00+00:00"
    )


@pytest.mark.parametrize(
    ("extension", "oid"),
    [
        (x509.DeltaCRLIndicator(41), "2.5.29.27"),
        (x509.UnrecognizedExtension(UNREADABLE_OID, b"\x05\x00"), UNREADABLE_OID.dotted_string),
    ],
    ids=["a delta CRL", "an extension nobody reads"],
)
def test_a_crl_with_a_critical_extension_it_does_not_read_says_nothing(extension, oid):
    served = mds_fixture.CrlServer()
    served[CA_URL] = mds_fixture.crl("ca", extensions=[(extension, True)])

    assert _unknown(served) == f"{LEAF_UNKNOWN}: {CA_URL}: a critical extension this does not read ({oid})"


@pytest.mark.parametrize(
    ("url", "issuer", "scope"),
    [
        (CA_URL, "ca", _scope(full_name=[x509.UniformResourceIdentifier(CA_URL)])),
        (CA_URL, "ca", _scope(only_contains_user_certs=True)),
        (ROOT_URL, "root", _scope(only_contains_ca_certs=True)),
    ],
    ids=["its own point", "end-entity certificates for the leaf", "CA certificates for the CA"],
)
def test_a_crl_whose_issuing_distribution_point_takes_the_certificate_in_is_used(url, issuer, scope):
    served = mds_fixture.CrlServer()
    served[url] = mds_fixture.crl(issuer, extensions=[(scope, True)])

    revocation.check_path(_path(), served, now=NOW)


@pytest.mark.parametrize(
    ("url", "issuer", "scope", "said"),
    [
        (
            CA_URL,
            "ca",
            _scope(full_name=[x509.UniformResourceIdentifier("http://crl.fixture.example/other.crl")]),
            "a CRL of another distribution point",
        ),
        (
            CA_URL,
            "ca",
            _scope(relative_name=x509.RelativeDistinguishedName([x509.NameAttribute(NameOID.COMMON_NAME, "CRL1")])),
            "a CRL of another distribution point",
        ),
        (CA_URL, "ca", _scope(only_contains_ca_certs=True), "a CRL of CA certificates only"),
        (ROOT_URL, "root", _scope(only_contains_user_certs=True), "a CRL of end-entity certificates only"),
        (CA_URL, "ca", _scope(indirect_crl=True), "an indirect CRL"),
        (
            CA_URL,
            "ca",
            _scope(only_some_reasons=frozenset({x509.ReasonFlags.key_compromise})),
            "a CRL of some revocation reasons only",
        ),
        (CA_URL, "ca", _scope(only_contains_attribute_certs=True), "a CRL of attribute certificates only"),
    ],
    ids=[
        "another point",
        "a point relative to the issuer",
        "CA certificates for the leaf",
        "end-entity certificates for the CA",
        "indirect",
        "some reasons",
        "attribute certificates",
    ],
)
def test_a_crl_whose_issuing_distribution_point_leaves_the_certificate_out_says_nothing(url, issuer, scope, said):
    served = mds_fixture.CrlServer()
    served[url] = mds_fixture.crl(issuer, extensions=[(scope, True)])

    assert _unknown(served).endswith(f" is revoked: {url}: {said}")
