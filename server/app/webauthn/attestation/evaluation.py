"""How an attestation's trust path fares against the FIDO metadata: the statement, the entry, the root, the chain.

``MdsAttestationVerifier.verify_attestation`` answers trusted or not. The
registration views say more: which step failed and why, the root the chain was
checked against, the metadata entry and whether it was found by AAGUID or by the
attestation certificate's key identifier. This walks the verifier's steps with
its public lookups and reports each, and checks the chain with
``chain.verify_certificate_chain``, so an ML-DSA chain verifies too.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from cryptography import x509

from fido2.attestation import Attestation, AttestationResult, UnsupportedType
from fido2.mds3 import MdsAttestationVerifier, filter_attestation_key_compromised

from .chain import verify_certificate_chain

__all__ = ["MdsEvaluation", "TrustPathEvaluation", "evaluate_attestation"]


@dataclass
class TrustPathEvaluation:
    """The attestation statement's result, the root found for it, and whether its chain verified."""

    attestation_result: AttestationResult | None
    ca_certificate: bytes | None
    chain_valid: bool | None
    errors: list[str]


@dataclass
class MdsEvaluation:
    """A trust path evaluation, the metadata entry whose root it used, and how the entry was found."""

    trust_path: TrustPathEvaluation
    metadata_entry: Any | None
    metadata_lookup_source: str | None


@dataclass
class _Lookup:
    entry: Any | None = None
    source: str | None = None
    root: bytes | None = None


def _issuer_name(trust_path: Sequence[bytes]) -> x509.Name | None:
    try:
        return x509.load_der_x509_certificate(trust_path[-1]).issuer
    except Exception:
        return None


def _matching_root(roots: Sequence[bytes], issuer: x509.Name) -> bytes | None:
    for root in roots:
        try:
            subject = x509.load_der_x509_certificate(root).subject
        except Exception:
            continue
        if subject == issuer:
            return root
    return None


def _find_root(verifier: MdsAttestationVerifier, result: AttestationResult, auth_data: Any, lookup: _Lookup) -> None:
    """Fill ``lookup`` with the authenticator's metadata entry and the root of it the trust path ends in.

    The entry is looked up by AAGUID, or by the trust path's key identifiers when
    the authenticator has none. It is kept only once a root is chosen; the source
    is recorded as soon as an entry is found.
    """

    trust_path = list(result.trust_path or [])
    aaguid = auth_data.credential_data.aaguid
    if aaguid:
        entry = verifier.find_entry_by_aaguid(aaguid)
        lookup.source = "aaguid" if entry is not None else None
    else:
        entry = verifier.find_entry_by_chain(trust_path)
        lookup.source = "chain" if entry is not None else None

    if not entry or not filter_attestation_key_compromised(entry, trust_path) or not entry.metadata_statement:
        return
    # Only a certificate names its issuer. Without one (a self attestation, or a
    # trust path that does not parse) no root can vouch for the key, so there is none.
    issuer = _issuer_name(trust_path)
    if issuer is not None:
        lookup.root = _matching_root(entry.metadata_statement.attestation_root_certificates, issuer)
    if lookup.root is not None:
        lookup.entry = entry


def _statement_result(attestation_object: Any, client_data_hash: bytes) -> AttestationResult:
    fmt = attestation_object.fmt
    if fmt == "none":
        # The verifier's formats leave "none" out: nothing in it can be trusted.
        raise UnsupportedType(attestation_object.auth_data, fmt)
    return Attestation.for_type(fmt)().verify(attestation_object.att_stmt, attestation_object.auth_data, client_data_hash)


def evaluate_attestation(
    verifier: MdsAttestationVerifier, attestation_object: Any, client_data_hash: bytes
) -> MdsEvaluation:
    """Each step of verifying ``attestation_object`` against ``verifier``'s metadata.

    An unsupported format raises ``UnsupportedType``; every other failure is
    reported in the trust path's ``errors``.
    """

    errors: list[str] = []
    try:
        result = _statement_result(attestation_object, client_data_hash)
    except UnsupportedType:
        raise
    except Exception as exc:
        errors.append(str(exc))
        return MdsEvaluation(TrustPathEvaluation(None, None, False, errors), None, None)

    lookup = _Lookup()
    try:
        _find_root(verifier, result, attestation_object.auth_data, lookup)
    except Exception as exc:
        errors.append(str(exc))
        return MdsEvaluation(TrustPathEvaluation(result, None, False, errors), None, lookup.source)

    if not lookup.root:
        errors.append("No root found for Authenticator")
        return MdsEvaluation(TrustPathEvaluation(result, None, False, errors), None, lookup.source)

    try:
        verify_certificate_chain(list(result.trust_path or []) + [lookup.root])
    except Exception as exc:
        errors.append(str(exc))
        chain_valid = False
    else:
        chain_valid = True
    return MdsEvaluation(TrustPathEvaluation(result, lookup.root, chain_valid, errors), lookup.entry, lookup.source)
