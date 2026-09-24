"""A certificate's signed certificate timestamps are shown as data.

The certificate view showed the SCT list extension as ``str()`` of
cryptography's value: ``<PrecertificateSignedCertificateTimestamps([<...Sct
object at 0x...>, ...])>``, a memory address that changed every run and told a
reader nothing. Each SCT is now its version, log ID, timestamp, entry type and
signature algorithms. The certificate is the leaf of the real SafetyNet
attestation vector.
"""
from __future__ import annotations

import base64
import json

from server.app.webauthn.attestation import serialize_attestation_certificate
from tests.app.decoder import real_vectors

SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2"


def _safetynet_leaf() -> bytes:
    jws = bytes(real_vectors.ANDROID_SAFETYNET_ATT_STMT["response"]).decode("ascii")
    header_b64 = jws.split(".")[0]
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    return base64.b64decode(header["x5c"][0])


def _sct_extension(details):
    (extension,) = [ext for ext in details["extensions"] if ext["oid"] == SCT_LIST_OID]
    return extension


def test_each_sct_is_shown_as_its_fields():
    extension = _sct_extension(serialize_attestation_certificate(_safetynet_leaf()))

    assert extension["value"] == [
        {
            "Version": "v1",
            "Log ID": "a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10",
            "Timestamp": "2018-10-10T08:19:45.739+00:00",
            "Entry type": "PRE_CERTIFICATE",
            "Signature hash algorithm": "sha256",
            "Signature algorithm": "ECDSA",
        },
        {
            "Version": "v1",
            "Log ID": "5614069a2fd7c2ecd3f5e1bd44b23ec74676b9bc99115cc0ef949855d689d0dd",
            "Timestamp": "2018-10-10T08:19:45.764+00:00",
            "Entry type": "PRE_CERTIFICATE",
            "Signature hash algorithm": "sha256",
            "Signature algorithm": "ECDSA",
        },
    ]


def test_the_view_is_the_same_every_time_and_names_no_object():
    first = serialize_attestation_certificate(_safetynet_leaf())
    second = serialize_attestation_certificate(_safetynet_leaf())

    assert first == second
    rendered = json.dumps(first)
    assert "object at 0x" not in rendered
    assert "Log ID: a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10" in first["summary"]
