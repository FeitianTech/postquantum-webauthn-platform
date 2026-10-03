"""The small FIDO MDS snapshot the tests and the browser tests serve.

It is built the way the updater builds a real one (``snapshot_files`` in
``server/app/mds/snapshot.py``), from a synthetic MDS3 BLOB this module signs
itself: every entry, name, key and certificate is made up here, nothing is copied
from the FIDO Alliance's service. It holds what the explorer must show well: each
protocol (FIDO2, U2F, UAF: the three kinds of entry id), each certification level,
a revocation, a status report with every MDS3 field (and one unknown), the longest values (a CN list of about 970 characters, 11 user
verification methods, a 135-character name), an entry without an icon, one without
status reports, and enough short entries for the list to scroll.

``tests/fixtures/mds/snapshot/`` holds the seven files and
``tests/fixtures/mds/custom-metadata.json`` a statement to upload.
``tests/app/metadata/test_mds_fixture.py`` fails when they differ from what this
module builds; ``MDS_FIXTURE_WRITE=1`` rewrites them (or run this module).
Everything is deterministic: fixed times, keys derived from labels
(``tests/app/characterization/material.py``), PKCS#1 v1.5 and RFC 6979 signatures,
and icons kept as literal PNGs (a zlib build could compress them differently).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fido2.utils import websafe_encode

from server.app.mds import snapshot as mds_snapshot
from tests.app.characterization import material
from tools import update_mds_snapshot as updater

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "mds"
SNAPSHOT_DIR = FIXTURE_DIR / "snapshot"
CUSTOM_METADATA_PATH = FIXTURE_DIR / "custom-metadata.json"
WRITE_ENV = "MDS_FIXTURE_WRITE"

GENERATED_AT = "2026-09-20T08:00:00+00:00"
LAST_MODIFIED = "Sun, 20 Sep 2026 08:00:00 GMT"
ETAG = '"fixture-7"'
SNAPSHOT_NO = 7
NEXT_UPDATE = "2026-10-20"
LEGAL_HEADER = "Fixture metadata for the tests of this repository; not published by the FIDO Alliance."

ICONS = {
    "blue": (
        "iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAIAAABvFaqvAAAATklEQVR42mP4TyXAQA+DGAofoyGSDcI0gqBx"
        "DCQZgcc4BvJMwTSLBgaRagqaWdQ2iDxTkM0aNYj+Bg2+dDQo8xo1ixFqFmxULmoHshYBAJ+2rOFZWpOBAAAAAElFTkSuQmCC"
    ),
    "green": (
        "iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAIAAABvFaqvAAAATklEQVR42mP4TyXAQA+DTI5HoiGSDcI0gqBx"
        "DCQZgcc4BvJMwTSLBgaRagqaWdQ2iDxTkM0aNYj+Bg2+dDQo8xo1ixFqFmxULmoHshYBAIpNrOG1ZQeZAAAAAElFTkSuQmCC"
    ),
    "orange": (
        "iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAIAAABvFaqvAAAATUlEQVR42mP4TyXAQBeDpjKgI5INwjSCkHEM"
        "pBmB2zgGMk3BMIsWBpFqCqpZVDeIPFOQzBo1aAAMGnzpaFDmNWoWI9Qs2Khc1A5gLQIAVq374ZzxQkQAAAAASUVORK5CYII="
    ),
}

LONG_NAME = (
    "Fixture Authenticator With A Deliberately Long Description, Written To Show How The"
    " Explorer Truncates A Name While Keeping It Visible."
)

USER_VERIFICATION_METHODS = (
    "presence_internal",
    "fingerprint_internal",
    "passcode_internal",
    "voiceprint_internal",
    "faceprint_internal",
    "location_internal",
    "eyeprint_internal",
    "pattern_internal",
    "handprint_internal",
    "passcode_external",
    "none",
)

# Every method above, in combinations: a passcode with a fingerprint, a pattern
# alone, the rest alone; each descriptor the detail page shows, with every
# property it has.
USER_VERIFICATION_COMBINATIONS = [
    [
        {
            "userVerificationMethod": "passcode_internal",
            "caDesc": {"base": 10, "minLength": 6, "maxRetries": 8, "blockSlowdown": 30},
        },
        {
            "userVerificationMethod": "fingerprint_internal",
            "baDesc": {
                "selfAttestedFRR": 0.01,
                "selfAttestedFAR": 0.00002,
                "maxTemplates": 5,
                "maxRetries": 5,
                "blockSlowdown": 30,
            },
        },
    ],
    [{"userVerificationMethod": "pattern_internal", "paDesc": {"minComplexity": 9, "maxRetries": 5, "blockSlowdown": 60}}],
    *(
        [{"userVerificationMethod": method}]
        for method in USER_VERIFICATION_METHODS
        if method not in {"passcode_internal", "fingerprint_internal", "pattern_internal"}
    ),
]

# Every getInfo field the detail page names, for one FIDO2 entry.
FULL_GET_INFO = {
    "options": {"rk": True, "up": True, "uv": False, "plat": False, "clientPin": True, "credMgmt": True},
    "maxCredentialCountInList": 8,
    "maxCredentialIdLength": 128,
    "maxSerializedLargeBlobArray": 1024,
    "minPINLength": 6,
    "firmwareVersion": 327941,
    "maxCredBlobLength": 32,
    "maxRPIDsForSetMinPINLength": 1,
    "remainingDiscoverableCredentials": 25,
    "algorithms": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -8}],
}


def _b64(der: bytes) -> str:
    return base64.b64encode(der).decode("ascii")


def _icon(colour: str) -> str:
    return f"data:image/png;base64,{ICONS[colour]}"


def _aaguid(number: int) -> str:
    return f"f1d0f1d0-0000-4000-8000-{number:012d}"


def _ec_root(label: str, common_name: str, serial: int) -> str:
    key = material.ec_key(f"mds-fixture:{label}")
    return _b64(
        material.certificate(
            key.public_key(),
            common_name=common_name,
            serial=serial,
            signing_key=key,
            issuer=material._name(common_name),
            algorithm=hashes.SHA256(),
            ecdsa_deterministic=True,
        )
    )


def _rsa_root(label: str, common_name: str, serial: int) -> str:
    key = material.rsa_key(f"mds-fixture:{label}")
    return _b64(
        material.certificate(
            key.public_key(),
            common_name=common_name,
            serial=serial,
            signing_key=key,
            issuer=material._name(common_name),
            algorithm=hashes.SHA256(),
            rsa_padding=padding.PKCS1v15(),
        )
    )


def _ed25519_root(label: str, common_name: str, serial: int) -> str:
    key = material.ed25519_key(f"mds-fixture:{label}")
    return _b64(material.certificate(key.public_key(), common_name=common_name, serial=serial))


def _status(
    status: str,
    date: str,
    descriptor: str | None = None,
    number: str | None = None,
    *,
    url: str | None = None,
    version: int | None = None,
    **fields: Any,
) -> dict[str, Any]:
    report: dict[str, Any] = {"status": status, "effectiveDate": date}
    if version is not None:
        report["authenticatorVersion"] = version
    if descriptor:
        report["certificationDescriptor"] = descriptor
    if number:
        report["certificateNumber"] = number
        report["certificationPolicyVersion"] = "1.4.0"
        report["certificationRequirementsVersion"] = "1.3"
    if url:
        report["url"] = url
    report.update(fields)
    return report


def _statement(
    description: str,
    *,
    protocol: str = "fido2",
    roots: list[str],
    icon: str | None = "blue",
    methods: tuple[str, ...] = ("presence_internal", "passcode_external"),
    key_protection: tuple[str, ...] = ("hardware", "secure_element"),
    attachment: tuple[str, ...] = ("external", "wired", "nfc"),
    algorithms: tuple[str, ...] = ("secp256r1_ecdsa_sha256_raw", "ed25519_eddsa_sha512_raw"),
    transports: tuple[str, ...] = ("usb", "nfc"),
    verification: list[list[dict[str, Any]]] | None = None,
    get_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "legalHeader": LEGAL_HEADER,
        "description": description,
        "authenticatorVersion": 2,
        "protocolFamily": protocol,
        "schema": 3,
        "upv": [{"major": 1, "minor": 1}],
        "authenticationAlgorithms": list(algorithms),
        "publicKeyAlgAndEncodings": ["cose"],
        "attestationTypes": ["basic_full"],
        "userVerificationDetails": verification or [[{"userVerificationMethod": method}] for method in methods],
        "keyProtection": list(key_protection),
        "matcherProtection": ["on_chip"],
        "cryptoStrength": 128,
        "attachmentHint": list(attachment),
        "tcDisplay": [],
        "attestationRootCertificates": roots,
    }
    if icon:
        statement["icon"] = _icon(icon)
    if protocol == "fido2":
        statement["authenticatorGetInfo"] = {
            "versions": ["FIDO_2_0", "FIDO_2_1"],
            "extensions": ["credProtect", "hmac-secret"],
            "options": {"rk": True, "up": True, "plat": False, "clientPin": True},
            "maxMsgSize": 1200,
            "pinUvAuthProtocols": [1, 2],
            "transports": list(transports),
            **(get_info or {}),
        }
    return statement


def _fido2(number: int, description: str, date: str, reports: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
    aaguid = _aaguid(number)
    statement = _statement(description, **kwargs)
    statement["aaguid"] = aaguid
    if "authenticatorGetInfo" in statement:
        statement["authenticatorGetInfo"]["aaguid"] = aaguid.replace("-", "")
    return {
        "aaguid": aaguid,
        "metadataStatement": statement,
        "statusReports": reports,
        "timeOfLastStatusChange": date,
    }


def _entries() -> list[dict[str, Any]]:
    ec_root = _ec_root("fido2-root", "Fixture FIDO2 Attestation Root", 1001)
    rsa_root = _rsa_root("rsa-root", "Fixture RSA Attestation Root", 1002)
    ed_root = _ed25519_root("ed-root", "Fixture Ed25519 Attestation Root", 1003)
    many_roots = [
        _ed25519_root(f"many-{index}", f"Fixture Authenticator Attestation Root Certificate Authority {index:02d}", 1100 + index)
        for index in range(1, 16)
    ]

    entries = [
        _fido2(
            1,
            "Fixture Security Key L1",
            "2026-09-01",
            [
                _status("NOT_FIDO_CERTIFIED", "2025-11-03", version=1),
                _status(
                    "FIDO_CERTIFIED_L1",
                    "2026-03-16",
                    "Fixture Security Key",
                    "FIDO20020260316001",
                    url="https://fixture.example/certificates/FIDO20020260316001",
                    version=1,
                ),
                _status(
                    "FIDO_CERTIFIED_L1",
                    "2026-09-01",
                    "Fixture Security Key",
                    "FIDO20020260901001",
                    url="https://fixture.example/certificates/FIDO20020260901001",
                    version=2,
                    # Every other field an MDS3 status report has, and one no
                    # version defines yet: the entry page shows them all.
                    certificate=_ec_root("certification", "Fixture Certification Certificate", 1004),
                    certificationProfiles=["consumer", "enterprise"],
                    sunsetDate="2029-09-01",
                    fipsRevision=3,
                    fipsPhysicalSecurityLevel=2,
                    fixtureFutureField="A field no MDS3 version defines",
                ),
            ],
            roots=[ec_root],
            get_info=FULL_GET_INFO,
        ),
        _fido2(
            2,
            "Fixture Security Key L2",
            "2026-08-15",
            [_status("FIDO_CERTIFIED_L2", "2026-08-15", "Fixture Security Key L2", "FIDO20020260815002")],
            roots=[rsa_root],
            icon="green",
            methods=("fingerprint_internal", "passcode_internal", "presence_internal"),
            transports=("usb", "nfc", "ble"),
        ),
        _fido2(
            3,
            "Fixture Certified Key",
            "2026-07-10",
            [_status("FIDO_CERTIFIED", "2026-07-10", "Fixture Certified Key", "FIDO20020260710003")],
            roots=[ed_root],
            icon="orange",
        ),
        _fido2(
            4,
            "Fixture Uncertified Key",
            "2026-06-01",
            [_status("NOT_FIDO_CERTIFIED", "2026-06-01")],
            roots=[ec_root],
            key_protection=("software",),
            attachment=("internal",),
            transports=("internal", "hybrid"),
        ),
        _fido2(
            5,
            "Fixture Revoked Key",
            "2026-05-20",
            [
                _status("FIDO_CERTIFIED_L1", "2023-01-10", "Fixture Revoked Key", "FIDO20020230110005"),
                _status("REVOKED", "2026-05-20"),
            ],
            roots=[ec_root],
        ),
        _fido2(
            6,
            "Fixture Key With Many Attestation Roots",
            "2026-04-02",
            [_status("FIDO_CERTIFIED_L1", "2026-04-02", "Fixture Key With Many Roots", "FIDO20020260402006")],
            roots=many_roots,
        ),
        _fido2(
            7,
            "Fixture Key With Every User Verification Method",
            "2026-03-03",
            [_status("FIDO_CERTIFIED_L2", "2026-03-03", "Fixture Biometric Key", "FIDO20020260303007")],
            roots=[ec_root],
            methods=USER_VERIFICATION_METHODS,
            verification=USER_VERIFICATION_COMBINATIONS,
            icon="green",
        ),
        _fido2(
            8,
            LONG_NAME,
            "2026-02-14",
            [_status("FIDO_CERTIFIED_L1", "2026-02-14", "Fixture Long Name Key", "FIDO20020260214008")],
            roots=[ec_root],
        ),
        _fido2(
            9,
            "Fixture Key Without An Icon",
            "2026-01-05",
            [_status("NOT_FIDO_CERTIFIED", "2026-01-05")],
            roots=[ec_root],
            icon=None,
        ),
        _fido2(10, "Fixture Key Without Status Reports", "2025-12-12", [], roots=[ec_root], icon="orange"),
    ]

    u2f_identifier = "f1d0000000000000000000000000000000000011"
    u2f = _statement(
        "Fixture U2F Key",
        protocol="u2f",
        roots=[ec_root],
        methods=("presence_internal",),
        algorithms=("secp256r1_ecdsa_sha256_raw",),
        attachment=("external", "wired"),
    )
    u2f["attestationCertificateKeyIdentifiers"] = [u2f_identifier]
    entries.append(
        {
            "attestationCertificateKeyIdentifiers": [u2f_identifier],
            "metadataStatement": u2f,
            "statusReports": [_status("FIDO_CERTIFIED_L1", "2025-11-11", "Fixture U2F Key", "U2F100020251111011")],
            "timeOfLastStatusChange": "2025-11-11",
        }
    )

    uaf = _statement(
        "Fixture UAF Authenticator",
        protocol="uaf",
        roots=[ed_root],
        icon="green",
        methods=("fingerprint_internal",),
        key_protection=("hardware", "tee"),
        attachment=("internal",),
        algorithms=("secp256r1_ecdsa_sha256_raw",),
    )
    uaf["aaid"] = "F1D0#0012"
    entries.append(
        {
            "aaid": "F1D0#0012",
            "metadataStatement": uaf,
            "statusReports": [_status("FIDO_CERTIFIED_L1", "2025-10-10", "Fixture UAF Authenticator", "UAF100020251010012")],
            "timeOfLastStatusChange": "2025-10-10",
        }
    )

    # Short entries so the list scrolls; the last two share a date, so the sort's
    # tie-break (the entry's index) decides their order.
    for offset in range(20):
        number = 20 + offset
        date = f"2025-{(offset % 9) + 1:02d}-{(offset % 27) + 1:02d}" if offset < 19 else "2025-01-01"
        entries.append(
            _fido2(
                number,
                f"Fixture Filler Key {offset + 1:02d}",
                date,
                [_status("FIDO_CERTIFIED_L1", date, f"Fixture Filler Key {offset + 1:02d}", f"FIDO200202501{number:05d}")],
                roots=[ec_root],
                icon=("blue", "green", "orange")[offset % 3],
                methods=("presence_internal",),
                algorithms=("secp256r1_ecdsa_sha256_raw",),
            )
        )
    return entries


def _signed_blob(payload: dict[str, Any]) -> tuple[bytes, bytes]:
    """The payload as an MDS3 BLOB (a JWS, RS256) and the root that verifies it."""

    key = material.rsa_key("mds-fixture:blob-signer")
    name = "Fixture MDS BLOB Signer"
    root = material.certificate(
        key.public_key(),
        common_name=name,
        serial=1,
        signing_key=key,
        issuer=material._name(name),
        algorithm=hashes.SHA256(),
        rsa_padding=padding.PKCS1v15(),
    )
    header = {"alg": "RS256", "typ": "JWT", "x5c": [_b64(root)]}
    message = b".".join(
        websafe_encode(json.dumps(part, separators=(",", ":"), sort_keys=True).encode("utf-8")).encode("ascii")
        for part in (header, payload)
    )
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return message + b"." + websafe_encode(signature).encode("ascii"), root


def blob_root() -> bytes:
    """The root the fixture's BLOBs verify against, which tests pin where the server pins FIDO's."""

    return _signed_blob({})[1]


def build_fixture_files() -> dict[str, bytes]:
    """Every fixture file, by its path under ``tests/fixtures/mds``."""

    payload = {"legalHeader": LEGAL_HEADER, "no": SNAPSHOT_NO, "nextUpdate": NEXT_UPDATE, "entries": _entries()}
    blob, root = _signed_blob(payload)
    verified = updater._build_verified_snapshot(blob, root)
    cache_state = updater._build_cache_state(
        last_modified=LAST_MODIFIED,
        etag=ETAG,
        existing_cache={
            "fetched_at": GENERATED_AT,
            "generated_at": GENERATED_AT,
            "last_modified": LAST_MODIFIED,
            "last_modified_iso": GENERATED_AT,
            "etag": ETAG,
        },
        blob_unchanged=True,
        verified_snapshot=verified,
    )
    files = {f"snapshot/{name}": data for name, data in mds_snapshot.snapshot_files(blob, verified, cache_state).items()}
    files["custom-metadata.json"] = (json.dumps(custom_metadata(), indent=2, sort_keys=True) + "\n").encode("utf-8")
    return files


def custom_metadata() -> dict[str, Any]:
    """A statement to upload in Manage Trusted Metadata: one entry, BLOB-shaped."""

    root = _ec_root("uploaded-root", "Fixture Uploaded Attestation Root", 1200)
    entry = _fido2(
        99,
        "Fixture Uploaded Authenticator",
        "2026-09-10",
        [_status("FIDO_CERTIFIED_L2", "2026-09-10", "Fixture Uploaded Authenticator", "FIDO20020260910099")],
        roots=[root],
        icon="orange",
    )
    return {"legalHeader": LEGAL_HEADER, "entries": [entry]}


def write_fixture(directory: Path = FIXTURE_DIR) -> None:
    for relative, data in build_fixture_files().items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


if __name__ == "__main__":
    write_fixture()
    print(f"Wrote the MDS fixture to {FIXTURE_DIR}.")
