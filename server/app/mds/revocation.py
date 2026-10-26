"""The MDS BLOB's signing chain checked against its issuers' CRLs, as MDS3 asks.

MDS3 has a relying party ignore a BLOB when a certificate on its signing chain is
revoked. Each certificate on the path ``mds.blob`` found, the root aside (it is the
pin), names where its issuer publishes the CRL that covers it: its CRL distribution
points. The updater fetches the CRL (``tools/update_mds_snapshot.py``) and this
reads it. The CRL must be the issuer's (its name, signed with the key of the next
certificate on the path, which may sign CRLs), current at the time of the check (its
thisUpdate passed, its nextUpdate not), and complete for the certificate: a point
that names another CRL issuer or some reasons only is not fetched, and a delta CRL,
or one whose issuing distribution point leaves the certificate out, is not used. It
must not list the certificate's serial; entries are found by serial alone, since a
direct CRL lists only its issuer's certificates.

A certificate a CRL lists raises ``CertificateRevoked``. One whose status no CRL from
its points establishes (none could be fetched, read or used) raises
``RevocationUnknown``: a CRL that is not there is no evidence that nothing was
revoked. A Flask-free leaf like ``mds.blob``, which runs this for the updater.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID

__all__ = ["CertificateRevoked", "RevocationUnknown", "check_path"]


class CertificateRevoked(Exception):
    """A current CRL of the certificate's issuer lists it."""


class RevocationUnknown(Exception):
    """No CRL from the certificate's distribution points says whether it is revoked."""


def check_path(path: Sequence[x509.Certificate], fetch: Callable[[str], bytes], *, now: datetime) -> None:
    """Raise unless no current CRL lists a certificate on ``path``, the root aside.

    ``path`` runs from the signing certificate to the root, each certificate followed
    by its issuer (``mds.blob.verify_chain_to_root``'s path); ``fetch`` gives the bytes
    at a CRL's URL, and raises when it cannot. A certificate's points are tried in
    order until one gives a CRL that can be used.
    """

    for certificate, issuer in zip(path, path[1:]):
        _check_certificate(certificate, issuer, fetch, now)


def _check_certificate(
    certificate: x509.Certificate, issuer: x509.Certificate, fetch: Callable[[str], bytes], now: datetime
) -> None:
    named = _named(certificate)
    points = _distribution_points(certificate)
    urls = _urls(points)
    if not urls:
        raise RevocationUnknown(f"{named} names no CRL distribution point to fetch")
    if not _may_sign_crls(issuer):
        raise RevocationUnknown(f"{_named(issuer)}, which issued {named}, may not sign CRLs")
    problems = []
    for url in urls:
        try:
            crl = _current_crl(fetch(url), certificate, issuer, points, now)
        except Exception as exc:
            problems.append(f"{url}: {exc}")
            continue
        entry = crl.get_revoked_certificate_by_serial_number(certificate.serial_number)
        if entry is not None:
            raise CertificateRevoked(
                f"{named} is revoked{_reason(entry)} since {entry.revocation_date_utc.isoformat()}, "
                f"by the CRL at {url}"
            )
        return
    raise RevocationUnknown(f"No current CRL says whether {named} is revoked: {'; '.join(problems)}")


def _current_crl(
    data: bytes,
    certificate: x509.Certificate,
    issuer: x509.Certificate,
    points: list[x509.DistributionPoint],
    now: datetime,
) -> x509.CertificateRevocationList:
    """The CRL in ``data``, once it is ``issuer``'s, current at ``now`` and complete for
    ``certificate``; raises ValueError saying why it is not."""

    try:
        crl = x509.load_der_x509_crl(data)
    except ValueError:
        raise ValueError("not a CRL in DER") from None
    if crl.issuer != certificate.issuer:
        raise ValueError(f"a CRL of {crl.issuer.rfc4514_string()}, not of {certificate.issuer.rfc4514_string()}")
    if not crl.is_signature_valid(issuer.public_key()):
        raise ValueError(f"its signature does not verify with the key of {_named(issuer)}")
    if crl.last_update_utc > now:
        raise ValueError(f"not current before its thisUpdate, {crl.last_update_utc.isoformat()}")
    if crl.next_update_utc is None:
        raise ValueError("no nextUpdate, so never current")
    if crl.next_update_utc < now:
        raise ValueError(f"out of date since its nextUpdate, {crl.next_update_utc.isoformat()}")
    for extension in crl.extensions:
        if isinstance(extension.value, x509.IssuingDistributionPoint):
            _check_scope(extension.value, certificate, points)
        elif extension.critical:
            raise ValueError(f"a critical extension this does not read ({extension.oid.dotted_string})")
    return crl


def _check_scope(
    scope: x509.IssuingDistributionPoint, certificate: x509.Certificate, points: list[x509.DistributionPoint]
) -> None:
    """A CRL's issuing distribution point must leave ``certificate`` in: a CRL of
    another issuer's certificates too, of some reasons or kinds of certificate only, or
    of another distribution point is not this certificate's complete CRL."""

    if scope.indirect_crl:
        raise ValueError("an indirect CRL")
    if scope.only_some_reasons:
        raise ValueError("a CRL of some revocation reasons only")
    if scope.only_contains_attribute_certs:
        raise ValueError("a CRL of attribute certificates only")
    if scope.only_contains_user_certs and _is_ca(certificate):
        raise ValueError("a CRL of end-entity certificates only")
    if scope.only_contains_ca_certs and not _is_ca(certificate):
        raise ValueError("a CRL of CA certificates only")
    names = [name for point in points for name in point.full_name or ()]
    if scope.relative_name is not None or (scope.full_name and not any(name in names for name in scope.full_name)):
        raise ValueError("a CRL of another distribution point")


def _distribution_points(certificate: x509.Certificate) -> list[x509.DistributionPoint]:
    try:
        return list(certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value)
    except x509.ExtensionNotFound:
        return []


def _urls(points: list[x509.DistributionPoint]) -> list[str]:
    """The http and https URLs of the points that give the issuer's complete CRL: a
    point that names another CRL issuer (an indirect CRL) or some reasons only does not."""

    return [
        name.value
        for point in points
        if not point.crl_issuer and not point.reasons
        for name in point.full_name or ()
        if isinstance(name, x509.UniformResourceIdentifier) and name.value.lower().startswith(("http://", "https://"))
    ]


def _may_sign_crls(issuer: x509.Certificate) -> bool:
    try:
        return issuer.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign
    except x509.ExtensionNotFound:
        return True


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        return certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _named(certificate: x509.Certificate) -> str:
    """A certificate as a message names it: its common name (else its subject) and serial."""

    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    subject = common_names[0].value if common_names else certificate.subject.rfc4514_string()
    return f"{subject} (serial {certificate.serial_number:x})"


def _reason(entry: x509.RevokedCertificate) -> str:
    """`` (keyCompromise)``: the reason a CRL entry gives, when it gives one."""

    try:
        return f" ({entry.extensions.get_extension_for_class(x509.CRLReason).value.reason.value})"
    except x509.ExtensionNotFound:
        return ""
