from fido2.attestation import base


def _clear_certificate_caches() -> None:
    base._PARSED_CERTIFICATE_CACHE.clear()
    base._PARSED_CERTIFICATE_IDENTITIES.clear()
    base._PARSED_CERTIFICATE_DER_IDENTITIES.clear()


def _make_parsed_certificate(
    *,
    identity: tuple[bytes, bytes, bytes],
    signature_oid: str,
    spki_oid: str,
) -> base._ParsedCertificate:
    return base._ParsedCertificate(
        tbs_certificate=b"tbs",
        signature_algorithm_oid=signature_oid,
        signature_value=b"sig",
        subject_public_key_algorithm_oid=spki_oid,
        subject_public_key=b"spki",
        issuer_name=identity[0],
        subject_name=identity[1],
        serial_number=identity[2],
        authority_key_identifier=None,
        subject_key_identifier=None,
        is_ca=True,
        has_aaguid_extension=False,
    )


def test_register_parsed_certificate_prefers_mldsa_over_rsa():
    _clear_certificate_caches()

    identity = (b"issuer", b"subject", b"\x01")

    rsa_cert = _make_parsed_certificate(
        identity=identity,
        signature_oid="1.2.840.113549.1.1.11",
        spki_oid="1.2.840.113549.1.1.1",
    )

    chosen = base._register_parsed_certificate(b"rsa-der", identity, rsa_cert)
    base._PARSED_CERTIFICATE_CACHE[b"rsa-der"] = chosen

    assert base._PARSED_CERTIFICATE_IDENTITIES[identity].signature_algorithm_oid == (
        "1.2.840.113549.1.1.11"
    )

    mldsa_cert = _make_parsed_certificate(
        identity=identity,
        signature_oid="2.16.840.1.101.3.4.3.17",
        spki_oid="2.16.840.1.101.3.4.3.17",
    )

    chosen = base._register_parsed_certificate(b"mldsa-der", identity, mldsa_cert)
    base._PARSED_CERTIFICATE_CACHE[b"mldsa-der"] = chosen

    assert chosen.signature_algorithm_oid == "2.16.840.1.101.3.4.3.17"
    assert (
        base._PARSED_CERTIFICATE_IDENTITIES[identity].signature_algorithm_oid
        == "2.16.840.1.101.3.4.3.17"
    )
    assert (
        base._PARSED_CERTIFICATE_CACHE[b"rsa-der"].signature_algorithm_oid
        == "2.16.840.1.101.3.4.3.17"
    )


def test_register_parsed_certificate_keeps_existing_mldsa_metadata():
    _clear_certificate_caches()

    identity = (b"issuer", b"subject", b"\x02")

    mldsa_cert = _make_parsed_certificate(
        identity=identity,
        signature_oid="2.16.840.1.101.3.4.3.17",
        spki_oid="2.16.840.1.101.3.4.3.17",
    )

    chosen = base._register_parsed_certificate(b"mldsa-der", identity, mldsa_cert)
    base._PARSED_CERTIFICATE_CACHE[b"mldsa-der"] = chosen

    rsa_cert = _make_parsed_certificate(
        identity=identity,
        signature_oid="1.2.840.113549.1.1.11",
        spki_oid="1.2.840.113549.1.1.1",
    )

    chosen = base._register_parsed_certificate(b"rsa-der", identity, rsa_cert)
    base._PARSED_CERTIFICATE_CACHE[b"rsa-der"] = chosen

    assert chosen.signature_algorithm_oid == "2.16.840.1.101.3.4.3.17"
    assert (
        base._PARSED_CERTIFICATE_CACHE[b"rsa-der"].signature_algorithm_oid
        == "2.16.840.1.101.3.4.3.17"
    )
