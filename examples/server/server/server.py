# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Example demo server to use a supported web browser to call the WebAuthn APIs
to register and use a credential.

See the file README.adoc in this directory for details.

Navigate to http://localhost:5000 in a supported web browser.
"""
from fido2.webauthn import (
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    RegistrationResponse,
)
from fido2.server import Fido2Server
from fido2.utils import ByteBuffer, websafe_decode
from fido2.attestation import (
    Attestation,
    InvalidData,
    InvalidSignature,
    UnsupportedType,
    UntrustedAttestation,
)
from fido2.mds3 import parse_blob, MdsAttestationVerifier
from fido2.cose import CoseKey
from flask import Flask, request, redirect, abort, jsonify, session, send_file

import os
import uuid
import fido2.features
import base64
import binascii
import pickle
import shutil
import tempfile
import time
import math
import textwrap
import urllib.error
import urllib.request
import hashlib
import ssl
import json
import string
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime, formatdate

from collections.abc import Iterable
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Set, Tuple, Union

try:
    import certifi
except ImportError:  # pragma: no cover - certifi is optional
    certifi = None  # type: ignore[assignment]

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, ec, rsa

# Enable webauthn-json mapping if available (compatible across fido2 versions)
try:
    fido2.features.webauthn_json_mapping.enabled = True
except Exception:
    try:
        fido2.features.webauthn_json.enabled = True
    except Exception:
        pass

app = Flask(__name__, static_url_path="")
app.secret_key = os.urandom(32)  # Used for session.

rp = PublicKeyCredentialRpEntity(name="Demo server", id="localhost")
server = Fido2Server(rp)

# Save credentials next to this server.py file, regardless of CWD.
basepath = os.path.abspath(os.path.dirname(__file__))

MDS_METADATA_URL = "https://mds3.fidoalliance.org/"
MDS_METADATA_FILENAME = "fido-mds3.jws"
MDS_METADATA_PATH = os.path.join(basepath, "static", MDS_METADATA_FILENAME)
MDS_METADATA_CACHE_PATH = MDS_METADATA_PATH + ".meta.json"

FIDO_METADATA_TRUST_ROOT_B64 = (
    "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G"
    "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp"
    "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4"
    "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG"
    "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI"
    "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8"
    "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT"
    "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm"
    "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd"
    "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ"
    "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw"
    "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o"
    "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU"
    "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp"
    "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK"
    "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX"
    "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs"
    "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH"
    "WD9f"
)
FIDO_METADATA_TRUST_ROOT_CERT = base64.b64decode(FIDO_METADATA_TRUST_ROOT_B64)
FIDO_METADATA_TRUST_ROOT_PEM = ssl.DER_cert_to_PEM_cert(FIDO_METADATA_TRUST_ROOT_CERT)

MDS_TLS_ADDITIONAL_TRUST_ANCHORS_PEM = textwrap.dedent(
    """\
    -----BEGIN CERTIFICATE-----
    MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
    TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
    cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
    WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
    ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
    MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
    h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
    0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
    A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
    T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
    B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
    B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
    KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
    OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
    jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
    qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
    rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
    HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
    hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
    ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
    3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
    NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
    ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
    TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
    jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
    oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
    4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
    mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
    emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
    MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
    d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
    MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
    MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
    b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG
    9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI
    2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx
    1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ
    q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz
    tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ
    vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP
    BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV
    5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY
    1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4
    NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG
    Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91
    8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe
    pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl
    MrY=
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ
    RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD
    VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX
    DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y
    ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy
    VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr
    mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr
    IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK
    mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu
    XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy
    dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye
    jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1
    BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
    DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92
    9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx
    jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0
    Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz
    ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS
    R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp
    -----END CERTIFICATE-----
    """
)

_mds_verifier_cache: Optional[MdsAttestationVerifier] = None
_mds_verifier_mtime: Optional[float] = None


class MetadataDownloadError(Exception):
    """Raised when the FIDO MDS metadata cannot be downloaded."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        retry_after: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


def extract_credential_data(cred):
    """Extract AttestedCredentialData from either old or new format"""
    if isinstance(cred, dict):
        # New format - return the credential_data
        return cred['credential_data']
    else:
        # Old format - return as is (it's already AttestedCredentialData)
        return cred

HINT_TO_ATTACHMENT_MAP: Dict[str, str] = {
    "security-key": "cross-platform",
    "hybrid": "cross-platform",
    "client-device": "platform",
}


def _normalize_attachment(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized or None


def _derive_allowed_attachments_from_hints(hints: Optional[Iterable[str]]) -> List[str]:
    allowed: List[str] = []
    if not hints:
        return allowed
    seen: Set[str] = set()
    for hint in hints:
        if not isinstance(hint, str):
            continue
        mapped = HINT_TO_ATTACHMENT_MAP.get(hint.strip().lower())
        if mapped and mapped not in seen:
            allowed.append(mapped)
            seen.add(mapped)
    return allowed


def _normalize_attachment_list(raw_values: Any) -> List[str]:
    if isinstance(raw_values, Mapping):
        candidates: Iterable[Any] = raw_values.values()
    elif isinstance(raw_values, (str, bytes, bytearray)) or raw_values is None:
        return []
    elif isinstance(raw_values, Iterable):
        candidates = raw_values
    else:
        return []

    normalized: List[str] = []
    seen: Set[str] = set()
    for candidate in candidates:
        normalized_value = _normalize_attachment(candidate)
        if normalized_value and normalized_value not in seen:
            normalized.append(normalized_value)
            seen.add(normalized_value)
    return normalized


def _combine_allowed_attachment_values(
    hints: Iterable[str],
    requested: Any,
) -> Tuple[List[str], List[str], Optional[str]]:
    derived_allowed = _derive_allowed_attachments_from_hints(hints)
    allowed: List[str] = list(derived_allowed)
    normalized_requested = _normalize_attachment_list(requested)

    requested_is_list = isinstance(requested, list)
    requested_has_entries = requested_is_list and len(requested) > 0

    if normalized_requested:
        if allowed:
            allowed = [value for value in allowed if value in normalized_requested]
        else:
            allowed = list(normalized_requested)
        if not allowed:
            return (
                [],
                normalized_requested,
                "No authenticator attachments remain after combining hints with allowedAuthenticatorAttachments.",
            )
    elif requested_has_entries:
        return (
            [],
            normalized_requested,
            "No authenticator attachments remain after combining hints with allowedAuthenticatorAttachments.",
        )

    return allowed, normalized_requested, None


def _build_credential_attachment_map() -> Dict[bytes, Optional[str]]:
    attachment_map: Dict[bytes, Optional[str]] = {}
    try:
        pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
    except Exception:
        return attachment_map

    for pkl_file in pkl_files:
        email = pkl_file.replace('_credential_data.pkl', '')
        try:
            user_creds = readkey(email)
        except Exception:
            continue

        for cred in user_creds:
            credential_data = extract_credential_data(cred)
            credential_id: Optional[bytes] = None
            if isinstance(credential_data, Mapping):
                raw_id = credential_data.get('credential_id')
                if isinstance(raw_id, (bytes, bytearray, memoryview)):
                    credential_id = bytes(raw_id)
            else:
                raw_id = getattr(credential_data, 'credential_id', None)
                if isinstance(raw_id, (bytes, bytearray, memoryview)):
                    credential_id = bytes(raw_id)

            if credential_id is None:
                continue

            attachment_value: Optional[str] = None
            if isinstance(cred, Mapping):
                attachment_value = _normalize_attachment(
                    cred.get('authenticator_attachment')
                    or cred.get('authenticatorAttachment')
                )
                if attachment_value is None:
                    properties = cred.get('properties')
                    if isinstance(properties, Mapping):
                        attachment_value = _normalize_attachment(
                            properties.get('authenticatorAttachment')
                            or properties.get('authenticator_attachment')
                        )

            attachment_map[credential_id] = attachment_value

    return attachment_map

def savekey(name, key):
    name = name + "_credential_data.pkl"
    with open(os.path.join(basepath, name), "wb") as f:
        f.write(pickle.dumps(key))

def readkey(name):
    name = name + "_credential_data.pkl"
    try:
        with open(os.path.join(basepath, name), "rb") as f:
            creds = pickle.loads(f.read())
            return creds
    except Exception:
        return []

def delkey(name):
    name = name + "_credential_data.pkl"
    try:
        os.remove(os.path.join(basepath, name))
    except Exception:
        pass


def _parse_http_datetime(value: Optional[str]) -> Optional[datetime]:
    """Best-effort parsing of an HTTP date header into an aware datetime."""

    if not value:
        return None

    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp into an aware datetime if possible."""

    if not value:
        return None

    text = value.strip()
    if not text:
        return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return parsed


def _format_last_modified(header: Optional[str]) -> Optional[str]:
    """Convert an HTTP Last-Modified header to an ISO formatted string."""

    if not header:
        return None

    parsed = _parse_http_datetime(header)
    if parsed is None:
        return header

    return parsed.isoformat()


def _clean_metadata_cache_value(value: Any) -> Optional[str]:
    """Return a trimmed string value from cached metadata state if present."""

    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return None


def _load_metadata_cache_entry() -> Dict[str, Optional[str]]:
    """Load cached metadata headers used for conditional download requests."""

    try:
        with open(MDS_METADATA_CACHE_PATH, "r", encoding="utf-8") as cache_file:
            cached = json.load(cache_file)
    except (OSError, ValueError, TypeError):
        return {}

    if not isinstance(cached, Mapping):
        return {}

    last_modified_header = _clean_metadata_cache_value(cached.get("last_modified"))
    last_modified_iso = _clean_metadata_cache_value(cached.get("last_modified_iso"))
    if not last_modified_iso and last_modified_header:
        last_modified_iso = _format_last_modified(last_modified_header)
    etag = _clean_metadata_cache_value(cached.get("etag"))
    fetched_at = _clean_metadata_cache_value(cached.get("fetched_at"))

    return {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": fetched_at,
    }


def _store_metadata_cache_entry(
    *,
    last_modified_header: Optional[str],
    last_modified_iso: Optional[str],
    etag: Optional[str],
) -> None:
    """Persist cached metadata download headers for future requests."""

    payload = {
        "last_modified": last_modified_header,
        "last_modified_iso": last_modified_iso,
        "etag": etag,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        os.makedirs(os.path.dirname(MDS_METADATA_CACHE_PATH), exist_ok=True)
        with open(MDS_METADATA_CACHE_PATH, "w", encoding="utf-8") as cache_file:
            json.dump(payload, cache_file, indent=2, sort_keys=True)
            cache_file.write("\n")
    except OSError:
        pass


def _guess_last_modified_from_path(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Derive Last-Modified headers from the local file mtime when possible."""

    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None, None

    header = formatdate(mtime, usegmt=True)
    iso = datetime.fromtimestamp(mtime, timezone.utc).isoformat()
    return header, iso


def _apply_last_modified_timestamp(
    path: str,
    header: Optional[str],
    iso: Optional[str],
) -> None:
    """Update the local file mtime to match the metadata Last-Modified value."""

    timestamp_source = _parse_iso_datetime(iso) or _parse_http_datetime(header)
    if timestamp_source is None:
        return

    timestamp = timestamp_source.timestamp()
    try:
        os.utime(path, (timestamp, timestamp))
    except OSError:
        pass


def _is_certificate_verification_error(error: BaseException) -> bool:
    """Return True if the error represents a TLS certificate verification failure."""

    if isinstance(error, ssl.SSLCertVerificationError):
        return True

    if isinstance(error, ssl.SSLError):
        error_parts = [str(error)]
        if getattr(error, "reason", None):
            error_parts.append(str(error.reason))
        error_parts.extend(str(arg) for arg in getattr(error, "args", ()) if arg)
        combined = " ".join(part for part in error_parts if part)
        if "certificate verify failed" in combined.lower():
            return True

    message = str(error)
    return "certificate verify failed" in message.lower()


def _metadata_ssl_contexts():
    """Yield SSL contexts with different trust stores for the metadata download."""

    contexts = []

    try:
        contexts.append(ssl.create_default_context())
    except Exception:
        pass

    if certifi is not None:
        try:
            contexts.append(ssl.create_default_context(cafile=certifi.where()))
        except Exception:
            pass

    fallback_bundle = "\n".join(
        part.strip()
        for part in (
            FIDO_METADATA_TRUST_ROOT_PEM,
            MDS_TLS_ADDITIONAL_TRUST_ANCHORS_PEM,
        )
        if part.strip()
    )

    if fallback_bundle:
        fallback_bundle += "\n"

        try:
            fallback = ssl.create_default_context()
            fallback.load_verify_locations(cadata=fallback_bundle)
            contexts.append(fallback)
        except Exception:
            pass

    seen = set()
    for context in contexts:
        identifier = id(context)
        if identifier in seen:
            continue
        seen.add(identifier)
        yield context


def download_metadata_blob(
    source_url: str = MDS_METADATA_URL,
    destination: str = MDS_METADATA_PATH,
) -> Tuple[bool, int, Optional[str]]:
    """Fetch the FIDO MDS metadata BLOB and store it locally."""

    metadata_exists = os.path.exists(destination)
    cached_state = _load_metadata_cache_entry()
    cached_last_modified = cached_state.get("last_modified")
    cached_last_modified_iso = cached_state.get("last_modified_iso")
    cached_etag = cached_state.get("etag")

    if metadata_exists and not cached_last_modified:
        fallback_header, fallback_iso = _guess_last_modified_from_path(destination)
        if fallback_header:
            cached_last_modified = fallback_header
            if not cached_last_modified_iso:
                cached_last_modified_iso = fallback_iso

    payload: Optional[bytes] = None
    last_modified_header: Optional[str] = None
    last_modified_iso: Optional[str] = None
    etag: Optional[str] = None
    last_cert_error: Optional[BaseException] = None

    for context in _metadata_ssl_contexts():
        headers: Dict[str, str] = {}
        if metadata_exists and cached_last_modified:
            headers["If-Modified-Since"] = cached_last_modified
        if metadata_exists and cached_etag:
            headers["If-None-Match"] = cached_etag

        request = urllib.request.Request(source_url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60, context=context) as response:
                status = getattr(response, "status", None) or response.getcode()
                if status != 200:
                    raise MetadataDownloadError(
                        f"Unexpected response status {status} while downloading metadata.",
                        status_code=status,
                    )
                payload = response.read()
                response_headers = getattr(response, "headers", None)
                if response_headers is not None:
                    last_modified_header = _clean_metadata_cache_value(
                        response_headers.get("Last-Modified")
                    )
                    etag = _clean_metadata_cache_value(response_headers.get("ETag"))
                else:
                    last_modified_header = None
                    etag = None
                last_modified_iso = _format_last_modified(last_modified_header)
                if last_modified_iso is None and cached_last_modified_iso:
                    last_modified_iso = cached_last_modified_iso
                break
        except urllib.error.HTTPError as exc:
            if exc.code == 304 and metadata_exists:
                header = cached_last_modified
                if exc.headers is not None:
                    header = header or _clean_metadata_cache_value(exc.headers.get("Last-Modified"))
                iso = cached_last_modified_iso or _format_last_modified(header)
                etag_header = None
                if exc.headers is not None:
                    etag_header = _clean_metadata_cache_value(exc.headers.get("ETag"))
                etag_to_store = etag_header or cached_etag
                _apply_last_modified_timestamp(destination, header, iso)
                _store_metadata_cache_entry(
                    last_modified_header=header,
                    last_modified_iso=iso,
                    etag=etag_to_store,
                )
                return False, 0, iso

            retry_after = None
            if exc.headers is not None:
                retry_after = _clean_metadata_cache_value(exc.headers.get("Retry-After"))
            raise MetadataDownloadError(
                f"Failed to download metadata (HTTP {exc.code}).",
                status_code=exc.code,
                retry_after=retry_after,
            ) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, BaseException) and _is_certificate_verification_error(reason):
                last_cert_error = reason
                continue
            if isinstance(reason, str) and "certificate verify failed" in reason.lower():
                last_cert_error = exc
                continue
            if _is_certificate_verification_error(exc):
                last_cert_error = exc
                continue
            raise MetadataDownloadError(
                f"Failed to reach FIDO Metadata Service: {reason}"
            ) from exc

    if payload is None:
        if last_cert_error is not None:
            message = "Failed to verify the TLS certificate for the FIDO Metadata Service."
            if str(last_cert_error):
                message = f"{message} ({last_cert_error})."
            raise MetadataDownloadError(message) from last_cert_error
        raise MetadataDownloadError("Failed to reach FIDO Metadata Service.")

    os.makedirs(os.path.dirname(destination), exist_ok=True)

    if metadata_exists and os.path.exists(destination):
        with open(destination, "rb") as existing_file:
            if existing_file.read() == payload:
                _apply_last_modified_timestamp(destination, last_modified_header, last_modified_iso)
                _store_metadata_cache_entry(
                    last_modified_header=last_modified_header,
                    last_modified_iso=last_modified_iso,
                    etag=etag or cached_etag,
                )
                return False, len(payload), last_modified_iso

    with tempfile.NamedTemporaryFile("wb", delete=False, dir=os.path.dirname(destination)) as temp_file:
        temp_file.write(payload)
        temp_path = temp_file.name

    try:
        shutil.move(temp_path, destination)
    except Exception:
        try:
            os.remove(temp_path)
        except OSError:
            pass
        raise

    _apply_last_modified_timestamp(destination, last_modified_header, last_modified_iso)
    _store_metadata_cache_entry(
        last_modified_header=last_modified_header,
        last_modified_iso=last_modified_iso,
        etag=etag,
    )

    return True, len(payload), last_modified_iso


def _colon_hex(data: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in data)


def _format_hex_bytes_lines(data: bytes, bytes_per_line: int = 16) -> List[str]:
    """Return colon separated hex grouped across multiple lines."""
    if not data:
        return []

    hex_pairs = [f"{byte:02x}" for byte in data]
    lines = []
    for start in range(0, len(hex_pairs), bytes_per_line):
        chunk = hex_pairs[start : start + bytes_per_line]
        if not chunk:
            continue
        lines.append(":".join(chunk))
    return lines


def _format_hex_string_lines(hex_string: str, bytes_per_line: int = 16) -> List[str]:
    cleaned = "".join(hex_string.split()).replace(":", "")
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    try:
        data = bytes.fromhex(cleaned)
    except ValueError:
        return [hex_string]
    return _format_hex_bytes_lines(data, bytes_per_line)


def _decode_asn1_octet_string(data: bytes) -> bytes:
    """Best-effort decode of a DER-encoded OCTET STRING payload."""

    current = data
    for _ in range(4):
        if not current or current[0] != 0x04 or len(current) < 2:
            break

        length_byte = current[1]
        offset = 2

        if length_byte == 0x80:
            break

        if length_byte & 0x80:
            length_octets = length_byte & 0x7F
            if length_octets == 0 or len(current) < offset + length_octets:
                break
            length = int.from_bytes(current[offset : offset + length_octets], "big")
            offset += length_octets
        else:
            length = length_byte

        if len(current) < offset + length:
            break

        next_value = current[offset : offset + length]
        if next_value == current:
            break
        current = next_value

    return current


EXTENSION_DISPLAY_METADATA: Dict[str, Dict[str, Any]] = {
    "1.3.6.1.4.1.45724.1.1.4": {
        "friendly_name": "FIDO: Device AAGUID",
    },
    "1.3.6.1.4.1.45724.2.1.1": {
        "friendly_name": "FIDO: Transports",
    },
    "2.5.29.14": {
        "friendly_name": "Subject key id",
    },
    "2.5.29.35": {
        "friendly_name": "Authority key identifier",
    },
    "2.5.29.19": {
        "friendly_name": "X509v3 Basic Constraints",
        "header": "X509v3 Basic Constraints",
        "include_oid_in_header": False,
    },
}


def _encode_base64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_json_safe(value: Any) -> Any:
    """Recursively convert bytes-like WebAuthn option values into JSON-friendly data."""
    if isinstance(value, (bytes, bytearray, memoryview, ByteBuffer)):
        return _encode_base64url(bytes(value))
    if isinstance(value, Mapping):
        return {key: _make_json_safe(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_make_json_safe(item) for item in value]
    return value


CRED_PROTECT_LABELS: Dict[Any, str] = {
    1: "userVerificationOptional",
    2: "userVerificationOptionalWithCredentialIDList",
    3: "userVerificationRequired",
    "userVerificationOptional": "userVerificationOptional",
    "userVerificationOptionalWithCredentialIDList": "userVerificationOptionalWithCredentialIDList",
    "userVerificationOptionalWithCredentialIdList": "userVerificationOptionalWithCredentialIDList",
    "userVerificationRequired": "userVerificationRequired",
}


def describe_cred_protect(value: Any) -> Any:
    """Return a human readable credProtect description when possible."""
    return CRED_PROTECT_LABELS.get(value, value)


def _coerce_non_negative_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        if math.isfinite(value) and value >= 0:
            return int(value)
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            parsed = int(stripped, 10)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def _normalize_aaguid_string(value: Any) -> Optional[str]:
    if isinstance(value, str):
        cleaned = ''.join(ch for ch in value if ch in string.hexdigits)
        if len(cleaned) == 32:
            return cleaned.lower()
    return None


def _augment_aaguid_fields(container: MutableMapping[str, Any]) -> None:
    if not isinstance(container, MutableMapping):
        return

    raw_value = container.get("aaguid")
    aaguid_hex: Optional[str] = None

    if isinstance(raw_value, (bytes, bytearray, memoryview)):
        aaguid_hex = bytes(raw_value).hex()
    elif isinstance(raw_value, str):
        aaguid_hex = _normalize_aaguid_string(raw_value)
    elif isinstance(raw_value, Mapping):
        for key in ("hex", "raw", "value"):
            candidate = raw_value.get(key)
            if isinstance(candidate, str):
                normalized = _normalize_aaguid_string(candidate)
                if normalized:
                    aaguid_hex = normalized
                    break

    if aaguid_hex:
        container["aaguid"] = aaguid_hex
        container["aaguidHex"] = aaguid_hex
        container["aaguidRaw"] = aaguid_hex
        try:
            container["aaguidGuid"] = str(uuid.UUID(hex=aaguid_hex))
        except ValueError:
            container.pop("aaguidGuid", None)
    else:
        container.pop("aaguidHex", None)
        container.pop("aaguidGuid", None)
        container.pop("aaguidRaw", None)


def _extract_min_pin_length(extension_results: Any) -> Optional[int]:
    if not isinstance(extension_results, Mapping):
        return None

    raw_value = extension_results.get("minPinLength")
    candidate = _coerce_non_negative_int(raw_value)
    if candidate is not None:
        return candidate

    if isinstance(raw_value, Mapping):
        for key in ("minPinLength", "minimumPinLength", "value"):
            nested_candidate = _coerce_non_negative_int(raw_value.get(key))
            if nested_candidate is not None:
                return nested_candidate

    return None


def summarize_authenticator_extensions(extensions: Mapping[str, Any]) -> Dict[str, Any]:
    """Augment authenticator extension outputs with human friendly metadata."""
    summary: Dict[str, Any] = {}
    for name, ext_value in extensions.items():
        summary[name] = ext_value
        if name == "credProtect":
            summary["credProtectLabel"] = describe_cred_protect(ext_value)
    return summary


def _extract_attestation_details(
    response: Any,
) -> Tuple[
    str,
    Dict[str, Any],
    Optional[str],
    Optional[str],
    Dict[str, Any],
    Optional[Dict[str, Any]],
]:
    """Parse attestation information from a registration response structure."""
    attestation_format = "none"
    attestation_statement: Dict[str, Any] = {}
    attestation_object_b64: Optional[str] = None
    client_data_b64: Optional[str] = None
    client_extension_results: Dict[str, Any] = {}
    attestation_certificate: Optional[Dict[str, Any]] = None

    if not isinstance(response, dict):
        return (
            attestation_format,
            attestation_statement,
            attestation_object_b64,
            client_data_b64,
            client_extension_results,
            attestation_certificate,
        )

    try:
        registration = RegistrationResponse.from_dict(response)
    except Exception as exc:  # pragma: no cover - debugging aid
        print(f"[DEBUG] Failed to parse registration response for attestation: {exc}")
        return (
            attestation_format,
            attestation_statement,
            attestation_object_b64,
            client_data_b64,
            client_extension_results,
            attestation_certificate,
        )

    attestation_object = registration.response.attestation_object
    attestation_format = getattr(attestation_object, "fmt", None) or "none"
    attestation_statement = attestation_object.att_stmt or {}
    attestation_object_b64 = _encode_base64url(bytes(attestation_object))

    if isinstance(attestation_statement, Mapping):
        cert_chain = attestation_statement.get("x5c") or []
        if isinstance(cert_chain, (list, tuple)) and cert_chain:
            try:
                first_cert = cert_chain[0]
                if isinstance(first_cert, str):
                    cert_bytes = base64.b64decode(first_cert)
                else:
                    cert_bytes = bytes(first_cert)
                attestation_certificate = serialize_attestation_certificate(cert_bytes)
            except Exception as cert_error:
                attestation_certificate = {"error": str(cert_error)}

    client_data = registration.response.client_data
    client_data_b64 = getattr(client_data, "b64", None)
    if client_data_b64 is None:
        client_data_b64 = _encode_base64url(bytes(client_data))

    extension_outputs = registration.client_extension_results
    if extension_outputs:
        if isinstance(extension_outputs, dict):
            client_extension_results = extension_outputs
        elif isinstance(extension_outputs, Mapping):
            client_extension_results = dict(extension_outputs)
        else:
            client_extension_results = extension_outputs  # type: ignore[assignment]

    return (
        attestation_format,
        attestation_statement,
        attestation_object_b64,
        client_data_b64,
        client_extension_results,
        attestation_certificate,
    )


def _format_x509_name(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _get_mds_verifier() -> Optional[MdsAttestationVerifier]:
    """Return a cached MDS attestation verifier if metadata is available."""

    global _mds_verifier_cache, _mds_verifier_mtime

    try:
        mtime = os.path.getmtime(MDS_METADATA_PATH)
    except OSError:
        _mds_verifier_cache = None
        _mds_verifier_mtime = None
        return None

    if _mds_verifier_cache is not None and _mds_verifier_mtime == mtime:
        return _mds_verifier_cache

    try:
        with open(MDS_METADATA_PATH, "rb") as blob_file:
            blob_data = blob_file.read()
        metadata = parse_blob(blob_data, FIDO_METADATA_TRUST_ROOT_CERT)
        verifier = MdsAttestationVerifier(metadata)
    except FileNotFoundError:
        _mds_verifier_cache = None
        _mds_verifier_mtime = None
        return None
    except Exception as exc:
        app.logger.warning(
            "Failed to load MDS metadata from %s: %s",
            MDS_METADATA_PATH,
            exc,
        )
        _mds_verifier_cache = None
        _mds_verifier_mtime = None
        return None

    _mds_verifier_cache = verifier
    _mds_verifier_mtime = mtime
    return verifier


def _parse_fido_transport_bitfield(raw_value: bytes):
    if not raw_value:
        return []

    data = raw_value
    if raw_value[0] == 0x03 and len(raw_value) >= 3:
        # BIT STRING tag followed by length and unused bits indicator
        unused_bits = raw_value[2]
        data = raw_value[3: 3 + raw_value[1] - 1]
    else:
        unused_bits = 0

    aggregate = 0
    for byte in data:
        aggregate = (aggregate << 8) | byte

    if unused_bits:
        aggregate >>= unused_bits

    transport_map = [
        (0x01, "USB"),
        (0x02, "NFC"),
        (0x04, "BLE"),
        (0x08, "TEST"),
        (0x10, "INTERNAL"),
        (0x20, "USB-C"),
        (0x40, "LIGHTNING"),
        (0x80, "BT CLASSIC"),
    ]

    transports = [label for mask, label in transport_map if aggregate & mask]
    return transports


def _serialize_public_key_info(public_key):
    info = {
        "type": public_key.__class__.__name__,
        "keySize": getattr(public_key, "key_size", None),
        "subjectPublicKeyInfoBase64": base64.b64encode(
            public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode("ascii"),
        "algorithm": {
            "name": None,
        },
    }

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = getattr(public_key.curve, "name", "unknown")
        info.update(
            {
                "type": "ECC",
                "curve": curve_name,
                "uncompressedPoint": _colon_hex(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint,
                    )
                ),
            }
        )
        info["algorithm"].update(
            {
                "name": "ECDSA",
                "namedCurve": curve_name,
            }
        )
    elif isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        modulus_hex = f"0x{numbers.n:x}"
        key_size = getattr(public_key, "key_size", None)
        info.update(
            {
                "type": "RSA",
                "publicExponent": numbers.e,
                "modulusHex": modulus_hex,
            }
        )
        info["algorithm"].update(
            {
                "name": "RSASSA-PKCS1-v1_5",
                "modulusLength": key_size,
            }
        )
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        info.update(
            {
                "type": public_key.__class__.__name__,
                "publicKeyHex": _colon_hex(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                ),
            }
        )
        info["algorithm"].update(
            {
                "name": "EdDSA",
            }
        )

    if not info["algorithm"].get("name"):
        info["algorithm"]["name"] = info.get("type") or public_key.__class__.__name__

    return info


def _serialize_extension_value(ext):
    value = ext.value
    if isinstance(value, x509.SubjectKeyIdentifier):
        hex_lines = _format_hex_bytes_lines(value.digest)
        return {
            "Hex value": hex_lines if hex_lines else _colon_hex(value.digest),
        }
    if isinstance(value, x509.AuthorityKeyIdentifier):
        serialized = {}
        if value.key_identifier:
            hex_lines = _format_hex_bytes_lines(value.key_identifier)
            serialized["Hex value"] = hex_lines if hex_lines else _colon_hex(value.key_identifier)
        if value.authority_cert_serial_number is not None:
            serialized["Authority Cert Serial Number"] = (
                f"{value.authority_cert_serial_number} "
                f"(0x{value.authority_cert_serial_number:x})"
            )
        if value.authority_cert_issuer:
            serialized["Authority Cert Issuer"] = [
                _format_x509_name(name) for name in value.authority_cert_issuer
            ]
        return serialized
    if isinstance(value, x509.BasicConstraints):
        serialized = {"CA": "TRUE" if value.ca else "FALSE"}
        if value.path_length is not None:
            serialized["Path Length"] = value.path_length
        return serialized
    if isinstance(value, x509.UnrecognizedExtension):
        raw_bytes = value.value
        raw_hex = raw_bytes.hex()
        oid = ext.oid.dotted_string

        if oid == "1.3.6.1.4.1.45724.1.1.4":
            aaguid_bytes = _decode_asn1_octet_string(raw_bytes)
            if len(aaguid_bytes) == 16:
                return {"AAGUID": aaguid_bytes.hex()}
            return {"Hex value": raw_hex}

        serialized: Dict[str, Any] = {"Hex value": raw_hex}
        if oid == "1.3.6.1.4.1.45724.2.1.1":
            transports = _parse_fido_transport_bitfield(raw_bytes)
            if transports:
                serialized["Transports"] = " ".join(transports)
        return serialized

    try:
        return str(value)
    except Exception:
        return repr(value)

def serialize_attestation_certificate(cert_bytes: bytes):
    if not cert_bytes:
        return None

    certificate = x509.load_der_x509_certificate(cert_bytes)
    version_number = certificate.version.value + 1
    version_hex = f"0x{certificate.version.value:x}"

    def _isoformat(value: datetime) -> str:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat()
        return value.astimezone(timezone.utc).isoformat()

    def _get_cert_datetime(attribute: str) -> datetime:
        utc_attribute = f"{attribute}_utc"
        try:
            return getattr(certificate, utc_attribute)
        except AttributeError:
            return getattr(certificate, attribute)

    not_valid_before = _get_cert_datetime("not_valid_before")
    not_valid_after = _get_cert_datetime("not_valid_after")

    extensions = []
    for ext in certificate.extensions:
        oid = ext.oid.dotted_string
        metadata = EXTENSION_DISPLAY_METADATA.get(oid, {})
        metadata_friendly = metadata.get("friendly_name")
        default_name = getattr(ext.oid, "_name", None)
        include_oid = metadata.get("include_oid_in_header")
        extensions.append(
            {
                "oid": oid,
                "name": metadata_friendly or default_name or oid,
                "friendlyName": metadata_friendly,
                "critical": ext.critical,
                "value": _serialize_extension_value(ext),
                "displayHeader": metadata.get("header"),
                "includeOidInHeader": True if include_oid is None else bool(include_oid),
            }
        )

    fingerprints = {
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "sha1": certificate.fingerprint(hashes.SHA1()).hex(),
        "md5": certificate.fingerprint(hashes.MD5()).hex(),
    }

    der_bytes = certificate.public_bytes(serialization.Encoding.DER)
    der_base64 = base64.b64encode(der_bytes).decode("ascii")
    pem_body = "\n".join(textwrap.wrap(der_base64, 64))
    pem = f"-----BEGIN CERTIFICATE-----\n{pem_body}\n-----END CERTIFICATE-----"

    summary_lines = []

    def _append_line(line: str):
        summary_lines.append(line)

    def _append_blank_line():
        if summary_lines and summary_lines[-1] != "":
            summary_lines.append("")

    signature_algorithm = getattr(
        certificate.signature_algorithm_oid,
        "_name",
        certificate.signature_algorithm_oid.dotted_string,
    )
    issuer_str = _format_x509_name(certificate.issuer)
    subject_str = _format_x509_name(certificate.subject)
    public_key = certificate.public_key()
    public_key_info = _serialize_public_key_info(public_key)
    signature_bytes = certificate.signature
    signature_lines = _format_hex_bytes_lines(signature_bytes)
    signature_hex = signature_bytes.hex()
    signature_colon = _colon_hex(signature_bytes)

    try:
        signature_hash_algorithm = certificate.signature_hash_algorithm
    except Exception:  # pragma: no cover - cryptography may raise if unavailable
        signature_hash_algorithm = None
    if signature_hash_algorithm is not None:
        hash_name = getattr(signature_hash_algorithm, "name", None)
        if not hash_name:
            hash_name = signature_hash_algorithm.__class__.__name__
        signature_hash = {"name": hash_name}
    else:
        signature_hash = None

    serial_decimal = str(certificate.serial_number)
    serial_hex = f"0x{certificate.serial_number:x}"

    _append_line(f"Version: {version_number} ({version_hex})")
    _append_line(
        f"Certificate Serial Number: {serial_decimal} ({serial_hex})"
    )
    _append_line(f"Signature Algorithm: {signature_algorithm}")
    _append_line(f"Issuer: {issuer_str}")

    _append_blank_line()
    _append_line("Validity:")
    _append_line(f"    Not Before: {_isoformat(not_valid_before)}")
    _append_line(f"    Not After: {_isoformat(not_valid_after)}")

    _append_blank_line()
    _append_line(f"Subject: {subject_str}")

    pk_summary_entries: List[Tuple[str, Any]] = []
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        pk_summary_entries.append(("Type", "ECC"))
        if public_key.key_size:
            pk_summary_entries.append(("Public-Key", f"({public_key.key_size} bit)"))
        ecc_point_lines = _format_hex_bytes_lines(
            public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
        )
        if ecc_point_lines:
            pk_summary_entries.append(("pub", ecc_point_lines))
        curve_name = getattr(public_key.curve, "name", None)
        if curve_name:
            pk_summary_entries.append(("Curve", curve_name))
    elif isinstance(public_key, rsa.RSAPublicKey):
        pk_summary_entries.append(("Type", "RSA"))
        if public_key.key_size:
            pk_summary_entries.append(("Public-Key", f"({public_key.key_size} bit)"))
        numbers = public_key.public_numbers()
        modulus_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        modulus_lines = _format_hex_bytes_lines(modulus_bytes)
        if modulus_lines:
            pk_summary_entries.append(("Modulus", modulus_lines))
        pk_summary_entries.append(("Exponent", str(numbers.e)))
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        key_type = "Ed25519" if isinstance(public_key, ed25519.Ed25519PublicKey) else "Ed448"
        pk_summary_entries.append(("Type", key_type))
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        raw_lines = _format_hex_bytes_lines(raw_bytes)
        if raw_lines:
            pk_summary_entries.append(("Public Key", raw_lines))
    else:
        pk_summary_entries.append(("Type", public_key.__class__.__name__))

    if pk_summary_entries:
        _append_blank_line()
        _append_line("Subject Public Key Info:")
        for label, value in pk_summary_entries:
            if value is None or (isinstance(value, list) and not value):
                continue
            if isinstance(value, list):
                _append_line(f"    {label}:")
                for line in value:
                    _append_line(f"        {line}")
            else:
                _append_line(f"    {label}: {value}")

    if extensions:
        _append_blank_line()
        _append_line("X509v3 extensions:")

        def _append_structured(value: Any, indent: int) -> None:
            indent_str = " " * 4 * indent
            if value is None:
                return
            if isinstance(value, Mapping):
                for key, val in value.items():
                    if val in (None, ""):
                        continue
                    if isinstance(val, (Mapping, list, tuple)):
                        _append_line(f"{indent_str}{key}:")
                        _append_structured(val, indent + 1)
                    else:
                        _append_line(f"{indent_str}{key}: {val}")
                return
            if isinstance(value, (list, tuple)):
                if all(isinstance(item, str) for item in value):
                    for item in value:
                        if item:
                            _append_line(f"{indent_str}{item}")
                else:
                    for item in value:
                        _append_structured(item, indent)
                return
            _append_line(f"{indent_str}{value}")

        for ext_info in extensions:
            oid = ext_info.get("oid")
            friendly = ext_info.get("friendlyName")
            name = ext_info.get("name")
            include_oid = ext_info.get("includeOidInHeader", True)
            header_override = ext_info.get("displayHeader")

            if isinstance(header_override, str) and header_override.strip():
                header = header_override.strip()
            else:
                header_parts: List[str] = []
                if include_oid and oid:
                    header_parts.append(oid)
                display_name = friendly or (name if name and name != oid else None)
                if display_name:
                    if include_oid and header_parts:
                        header_parts.append(f"({display_name})")
                    else:
                        header_parts.append(display_name)
                if not header_parts:
                    fallback = name or friendly or oid or "Extension"
                    header_parts.append(fallback)
                header = " ".join(header_parts)

            if ext_info.get("critical"):
                header = f"{header} [critical]"
            _append_line(f"    {header}:")
            _append_structured(ext_info.get("value"), 2)

    if signature_lines:
        _append_blank_line()
        _append_line(f"Signature Algorithm: {signature_algorithm}")
        for line in signature_lines:
            _append_line(f"    {line}")

    fingerprint_order = ["md5", "sha1", "sha256"]
    if any(fingerprints.get(label) for label in fingerprint_order):
        _append_blank_line()
        _append_line("Fingerprint:")
        for label in fingerprint_order:
            hex_value = fingerprints.get(label)
            if not hex_value:
                continue
            colon_lines = _format_hex_string_lines(hex_value)
            _append_line(f"    {label.upper()}:")
            for line in colon_lines:
                _append_line(f"        {line}")

    try:
        ski_extension = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
    except x509.ExtensionNotFound:
        ski_lines: List[str] = []
    else:
        ski_lines = _format_hex_bytes_lines(ski_extension.value.digest)

    if ski_lines:
        _append_blank_line()
        _append_line("Subject Key Identifier:")
        for line in ski_lines:
            _append_line(f"    {line}")

    summary = "\n".join(line for line in summary_lines if line is not None).strip()

    return {
        "version": {
            "display": f"{version_number} ({version_hex})",
            "numeric": version_number,
            "hex": version_hex,
        },
        "serialNumber": {
            "decimal": str(certificate.serial_number),
            "hex": f"0x{certificate.serial_number:x}",
        },
        "signatureAlgorithm": signature_algorithm,
        "issuer": _format_x509_name(certificate.issuer),
        "validity": {
            "notBefore": _isoformat(not_valid_before),
            "notAfter": _isoformat(not_valid_after),
        },
        "subject": _format_x509_name(certificate.subject),
        "publicKeyInfo": public_key_info,
        "extensions": extensions,
        "fingerprints": fingerprints,
        "signature": {
            "algorithm": signature_algorithm,
            "hash": signature_hash,
            "hex": signature_hex,
            "colon": signature_colon,
            "lines": signature_lines,
        },
        "derBase64": der_base64,
        "pem": pem,
        "summary": summary,
    }


def perform_attestation_checks(
    response: Mapping[str, Any],
    state: Optional[Mapping[str, Any]],
    public_key_options: Optional[Mapping[str, Any]],
    auth_data: Optional[AuthenticatorData],
    expected_origin: str,
    rp_id: str,
) -> Dict[str, Any]:
    """Execute a comprehensive set of attestation validation checks."""

    results: Dict[str, Any] = {
        "attestation_format": None,
        "signature_valid": None,
        "root_valid": None,
        "rp_id_hash_valid": None,
        "aaguid_match": None,
        "client_data": {},
        "authenticator_data": {},
        "metadata": {},
        "hash_binding": {},
        "errors": [],
    }

    if not isinstance(response, Mapping):
        results["errors"].append("registration_response_invalid")
        return results

    try:
        registration = RegistrationResponse.from_dict(response)
    except Exception as exc:
        results["errors"].append(f"registration_parse_error: {exc}")
        return results

    client_data = registration.response.client_data
    attestation_object = registration.response.attestation_object
    results["attestation_format"] = attestation_object.fmt

    if isinstance(auth_data, AuthenticatorData):
        auth_data_obj = auth_data
    else:
        auth_data_obj = attestation_object.auth_data

    def _coerce_expected_bytes(value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, ByteBuffer):
            return bytes(value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        if isinstance(value, str):
            try:
                return websafe_decode(value)
            except Exception:
                pass
            try:
                padded = value + "=" * ((4 - len(value) % 4) % 4)
                return base64.b64decode(padded)
            except Exception:
                pass
            try:
                return bytes.fromhex(value)
            except Exception:
                pass
            return value.encode("utf-8")
        if isinstance(value, Mapping):
            if "$base64url" in value:
                return _coerce_expected_bytes(value["$base64url"])
            if "$base64" in value:
                encoded = value["$base64"]
                try:
                    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
                    return base64.b64decode(padded)
                except Exception:
                    return b""
            if "$hex" in value:
                try:
                    return bytes.fromhex(value["$hex"])
                except Exception:
                    return b""
        return b""

    expected_challenge_bytes = b""
    if isinstance(state, Mapping):
        expected_challenge_bytes = _coerce_expected_bytes(state.get("challenge"))
    if not expected_challenge_bytes and isinstance(public_key_options, Mapping):
        expected_challenge_bytes = _coerce_expected_bytes(
            public_key_options.get("challenge")
        )

    challenge_matches = (
        bool(expected_challenge_bytes)
        and client_data.challenge == expected_challenge_bytes
    )

    expected_origin_normalized = (expected_origin or "").rstrip("/")
    origin_matches = bool(expected_origin_normalized) and (
        client_data.origin == expected_origin_normalized
    )

    results["client_data"] = {
        "type": client_data.type,
        "expected_type": CollectedClientData.TYPE.CREATE.value,
        "type_valid": client_data.type
        == CollectedClientData.TYPE.CREATE.value,
        "challenge": _encode_base64url(client_data.challenge),
        "expected_challenge": (
            _encode_base64url(expected_challenge_bytes)
            if expected_challenge_bytes
            else None
        ),
        "challenge_matches": challenge_matches,
        "origin": client_data.origin,
        "expected_origin": expected_origin_normalized,
        "origin_valid": origin_matches,
        "cross_origin": bool(client_data.cross_origin),
        "cross_origin_ok": not bool(client_data.cross_origin),
    }

    if not results["client_data"]["type_valid"]:
        results["errors"].append("client_data_type_invalid")
    if expected_challenge_bytes and not challenge_matches:
        results["errors"].append("challenge_mismatch")
    if expected_origin_normalized and not origin_matches:
        results["errors"].append("origin_mismatch")
    if bool(client_data.cross_origin):
        results["errors"].append("cross_origin_not_allowed")

    rp_id_value = rp_id or ""
    rp_id_hash_expected = hashlib.sha256(rp_id_value.encode("utf-8")).digest()
    rp_id_hash_valid = auth_data_obj.rp_id_hash == rp_id_hash_expected
    results["rp_id_hash_valid"] = rp_id_hash_valid

    if not rp_id_hash_valid:
        results["errors"].append("rp_id_hash_mismatch")

    flags = auth_data_obj.flags
    user_present = bool(flags & AuthenticatorData.FLAG.UP)
    user_verified = bool(flags & AuthenticatorData.FLAG.UV)
    attested_credential_included = bool(flags & AuthenticatorData.FLAG.AT)

    uv_required = False
    if isinstance(state, Mapping):
        state_uv = state.get("user_verification")
        if getattr(state_uv, "value", None) == "required" or state_uv == "required":
            uv_required = True

    if not uv_required and isinstance(public_key_options, Mapping):
        uv_setting: Optional[str] = None
        authenticator_selection = public_key_options.get("authenticatorSelection")
        if isinstance(authenticator_selection, Mapping):
            uv_setting = authenticator_selection.get("userVerification")
        if not uv_setting:
            uv_setting = public_key_options.get("userVerification")
        if isinstance(uv_setting, str) and uv_setting.lower() == "required":
            uv_required = True

    uv_satisfied = user_verified or not uv_required

    if not user_present:
        results["errors"].append("user_presence_missing")
    if uv_required and not uv_satisfied:
        results["errors"].append("user_verification_required_not_satisfied")
    if not attested_credential_included:
        results["errors"].append("attested_credential_data_missing")

    allowed_algorithms: List[int] = []
    if isinstance(public_key_options, Mapping):
        params = public_key_options.get("pubKeyCredParams")
        if isinstance(params, list):
            for param in params:
                if isinstance(param, Mapping) and isinstance(param.get("alg"), int):
                    allowed_algorithms.append(param["alg"])

    credential_data = getattr(auth_data_obj, "credential_data", None)
    credential_id_length: Optional[int] = None
    credential_aaguid: Optional[str] = None
    credential_aaguid_bytes = b""
    algorithm: Optional[int] = None
    cose_key_valid = False

    if credential_data is not None:
        try:
            credential_id_length = len(credential_data.credential_id)
        except Exception:
            credential_id_length = None

        try:
            cose_map = dict(credential_data.public_key)
        except Exception:
            cose_map = {}

        try:
            if cose_map:
                algorithm = cose_map.get(3)
                CoseKey.parse(cose_map)
            else:
                algorithm = credential_data.public_key.get(3)
                CoseKey.parse(dict(credential_data.public_key))
            cose_key_valid = True
        except Exception as exc:
            if algorithm is None:
                try:
                    algorithm = credential_data.public_key.get(3)
                except Exception:
                    algorithm = None
            results["errors"].append(f"cose_key_error: {exc}")

        try:
            credential_aaguid_bytes = bytes(credential_data.aaguid)
            credential_aaguid = credential_aaguid_bytes.hex()
        except Exception:
            credential_aaguid_bytes = b""
            credential_aaguid = None

    algorithm_allowed = True
    if allowed_algorithms:
        if isinstance(algorithm, int):
            algorithm_allowed = algorithm in allowed_algorithms
        else:
            algorithm_allowed = False

    if allowed_algorithms and not algorithm_allowed:
        results["errors"].append("algorithm_not_allowed")

    results["authenticator_data"] = {
        "user_present": user_present,
        "user_verified": user_verified,
        "user_verification_required": uv_required,
        "user_verification_satisfied": uv_satisfied,
        "attested_credential_data": attested_credential_included,
        "counter": auth_data_obj.counter,
        "credential_id_length": credential_id_length,
        "credential_aaguid": credential_aaguid,
        "algorithm": algorithm,
        "algorithm_allowed": algorithm_allowed,
        "cose_key_valid": cose_key_valid,
    }

    client_data_hash = client_data.hash
    verification_data = bytes(auth_data_obj) + client_data_hash
    results["hash_binding"] = {
        "client_data_hash": _encode_base64url(client_data_hash),
        "verification_data": _encode_base64url(verification_data),
    }

    attestation_format_value = (attestation_object.fmt or "").lower()
    signature_valid: Optional[bool] = None
    attestation_result = None
    if attestation_format_value == "none":
        signature_valid = False
    else:
        try:
            attestation_cls = Attestation.for_type(attestation_object.fmt)
            attestation_instance = attestation_cls()
            attestation_result = attestation_instance.verify(
                attestation_object.att_stmt,
                attestation_object.auth_data,
                client_data_hash,
            )
            signature_valid = True
        except UnsupportedType as exc:
            results["errors"].append(f"unsupported_attestation: {exc}")
            signature_valid = False
        except (InvalidSignature, InvalidData) as exc:
            results["errors"].append(f"attestation_invalid: {exc}")
            signature_valid = False
        except Exception as exc:
            results["errors"].append(f"attestation_error: {exc}")
            signature_valid = False

    results["signature_valid"] = signature_valid

    metadata_entry = None
    now = datetime.now(timezone.utc)
    root_valid: Optional[bool] = None
    if signature_valid and attestation_result is not None:
        trust_path = attestation_result.trust_path or []
        if trust_path:
            certs_valid = True
            for cert_der in trust_path:
                try:
                    cert = x509.load_der_x509_certificate(cert_der)
                    not_before = cert.not_valid_before
                    not_after = cert.not_valid_after
                    if not_before.tzinfo is None:
                        not_before = not_before.replace(tzinfo=timezone.utc)
                    else:
                        not_before = not_before.astimezone(timezone.utc)
                    if not_after.tzinfo is None:
                        not_after = not_after.replace(tzinfo=timezone.utc)
                    else:
                        not_after = not_after.astimezone(timezone.utc)
                    if now < not_before or now > not_after:
                        certs_valid = False
                        results["errors"].append(
                            f"certificate_out_of_validity: {cert.subject.rfc4514_string()}"
                        )
                except Exception as exc:
                    certs_valid = False
                    results["errors"].append(f"certificate_parse_error: {exc}")
            if certs_valid:
                verifier = _get_mds_verifier()
                if verifier is not None:
                    try:
                        metadata_entry = verifier.find_entry(
                            attestation_object,
                            client_data_hash,
                        )
                        if metadata_entry is not None:
                            root_valid = True
                        else:
                            root_valid = None
                            results["errors"].append("metadata_entry_not_found")
                    except UntrustedAttestation as exc:
                        results["errors"].append(f"untrusted_attestation: {exc}")
                        root_valid = False
                else:
                    results["errors"].append("metadata_not_available")
                    root_valid = None
            else:
                results["errors"].append("certificate_chain_invalid")
                root_valid = False
        else:
            results["errors"].append("trust_path_missing")
            root_valid = None
    elif signature_valid is False and attestation_format_value != "none":
        results["errors"].append("attestation_signature_invalid")
        root_valid = False

    metadata_description: Optional[str] = None
    metadata_aaguid: Optional[str] = None
    metadata_algorithm_supported: Optional[bool] = None
    metadata_aaguid_bytes = b""

    if metadata_entry is not None:
        metadata_statement = getattr(metadata_entry, "metadata_statement", None)
        if getattr(metadata_statement, "description", None):
            metadata_description = metadata_statement.description
        authenticator_info = getattr(
            metadata_statement,
            "authenticator_get_info",
            None,
        )
        if (
            isinstance(authenticator_info, Mapping)
            and isinstance(algorithm, int)
        ):
            alg_list = authenticator_info.get("algorithms")
            if isinstance(alg_list, (list, tuple)):
                numeric_algs = [alg for alg in alg_list if isinstance(alg, int)]
                if numeric_algs:
                    metadata_algorithm_supported = algorithm in numeric_algs
        entry_aaguid = getattr(metadata_entry, "aaguid", None)
        if entry_aaguid is not None:
            try:
                metadata_aaguid = str(entry_aaguid)
                metadata_aaguid_bytes = bytes(entry_aaguid)
                results["aaguid_match"] = (
                    metadata_aaguid_bytes == credential_aaguid_bytes
                )
            except Exception:
                metadata_aaguid = None
                results["aaguid_match"] = None

    if metadata_entry is None and credential_aaguid_bytes:
        if metadata_aaguid_bytes:
            results["aaguid_match"] = metadata_aaguid_bytes == credential_aaguid_bytes
        else:
            results["aaguid_match"] = False

    if results["aaguid_match"] is False and not credential_aaguid_bytes:
        results["aaguid_match"] = None

    if metadata_entry is None and not credential_aaguid_bytes:
        results["aaguid_match"] = None

    if results["aaguid_match"] is None and credential_aaguid_bytes and metadata_entry is not None:
        results["aaguid_match"] = metadata_aaguid_bytes == credential_aaguid_bytes

    results["metadata"] = {
        "available": metadata_entry is not None,
        "description": metadata_description,
        "aaguid": metadata_aaguid,
        "algorithm_supported": metadata_algorithm_supported,
    }

    if metadata_entry is not None and results["aaguid_match"] is False:
        results["errors"].append("aaguid_mismatch")
    if metadata_algorithm_supported is False:
        results["errors"].append("algorithm_not_in_metadata")

    if results["aaguid_match"] is False and metadata_entry is None:
        results["aaguid_match"] = None

    if root_valid is not None:
        results["root_valid"] = root_valid

    return results


@app.route("/")
def index():
    return redirect("/index.html")


@app.route("/api/mds/update", methods=["POST"])
def api_update_mds_metadata():
    metadata_existed = os.path.exists(MDS_METADATA_PATH)
    try:
        updated, bytes_written, last_modified = download_metadata_blob()
    except MetadataDownloadError as exc:
        if metadata_existed and getattr(exc, "status_code", None) == 429:
            app.logger.warning("Metadata update rate limited by FIDO MDS: %s", exc)
            cached_state = _load_metadata_cache_entry()
            cached_last_modified_iso = cached_state.get("last_modified_iso") if cached_state else None
            retry_after = getattr(exc, "retry_after", None)
            if retry_after:
                note = (
                    "Metadata already up to date. The FIDO Metadata Service asked us to wait before "
                    f"downloading again (retry after {retry_after})."
                )
            else:
                note = (
                    "Metadata already up to date. The FIDO Metadata Service asked us to wait before downloading again."
                )
            payload: Dict[str, Any] = {
                "updated": False,
                "bytes_written": 0,
                "message": note,
            }
            if cached_last_modified_iso:
                payload["last_modified"] = cached_last_modified_iso
            return jsonify(payload)
        return jsonify({"updated": False, "message": str(exc)}), 502
    except OSError as exc:
        app.logger.exception("Failed to store metadata BLOB: %s", exc)
        return (
            jsonify(
                {
                    "updated": False,
                    "message": "Failed to store the metadata BLOB on the server.",
                }
            ),
            500,
        )

    if updated:
        if metadata_existed:
            message = "Metadata updated successfully."
        else:
            message = "Metadata downloaded successfully."
    else:
        message = "Metadata already up to date."

    payload: Dict[str, Any] = {
        "updated": updated,
        "bytes_written": bytes_written,
        "message": message,
    }
    if last_modified:
        payload["last_modified"] = last_modified

    return jsonify(payload)


@app.route("/api/mds/decode-certificate", methods=["POST"])
def api_decode_mds_certificate():
    if not request.is_json:
        return jsonify({"error": "Expected JSON payload."}), 400

    payload = request.get_json(silent=True) or {}
    certificate_value = payload.get("certificate")
    if not certificate_value or not isinstance(certificate_value, str):
        return jsonify({"error": "Certificate is required."}), 400

    cleaned = "".join(certificate_value.split())
    padding = len(cleaned) % 4
    if padding:
        cleaned += "=" * (4 - padding)

    try:
        certificate_bytes = base64.b64decode(cleaned)
    except (ValueError, binascii.Error):
        return jsonify({"error": "Invalid certificate encoding."}), 400

    try:
        details = serialize_attestation_certificate(certificate_bytes)
    except Exception as exc:  # pylint: disable=broad-except
        return jsonify({"error": f"Unable to decode certificate: {exc}"}), 422

    return jsonify({"details": details})


@app.route("/api/register/begin", methods=["POST"])
def register_begin():
    uname = request.args.get("email")
    credentials = readkey(uname)
    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(
            id=b"user_id",
            name="a_user",
            display_name="A. User",
        ),
        credentials,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    session["state"] = state

    return jsonify(_make_json_safe(dict(options)))

@app.route("/api/register/complete", methods=["POST"])
def register_complete():
    uname = request.args.get("email")
    credentials = readkey(uname)
    response = request.json or {}
    credential_response = response.get('response', {}) if isinstance(response, dict) else {}

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
    ) = _extract_attestation_details(response)

    raw_attestation_object = credential_response.get('attestationObject')
    client_data_json = credential_response.get('clientDataJSON')

    if parsed_attestation_object:
        raw_attestation_object = parsed_attestation_object
    if parsed_client_data_json:
        client_data_json = parsed_client_data_json

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get('clientExtensionResults', {}) if isinstance(response, dict) else {})
    )

    min_pin_length_value = _extract_min_pin_length(client_extension_results)

    auth_data = server.register_complete(session["state"], response)

    authenticator_attachment_response = _normalize_attachment(
        response.get('authenticatorAttachment') if isinstance(response, Mapping) else None
    )

    # Store comprehensive credential data (same format as advanced)
    credential_info = {
        'credential_data': auth_data.credential_data,  # AttestedCredentialData
        'auth_data': auth_data,  # Full AuthenticatorData for flags, counter, etc.
        'user_info': {
            'name': uname,
            'display_name': uname,
            'user_handle': uname.encode('utf-8')  # Use username as user_handle for simple registration
        },
        'registration_time': time.time(),
        'client_data_json': client_data_json or '',
        'attestation_object': raw_attestation_object or '',
        'attestation_format': attestation_format,  # Store parsed attestation format
        'attestation_statement': attestation_statement,  # Store attestation statement for details
        'attestation_certificate': attestation_certificate_details,
        'client_extension_outputs': client_extension_results,
        'authenticator_attachment': authenticator_attachment_response,
        # Store request parameters for simple registration (defaults)
        'request_params': {
            'user_verification': 'discouraged',
            'authenticator_attachment': 'cross-platform',
            'attestation': 'none',
            'resident_key': None,
            'extensions': {},
            'timeout': 90000
        },
        # Properties section - detailed credential information
        'properties': {
            'excludeCredentialsSentCount': 0,  # Simple auth doesn't use exclude credentials
            'excludeCredentialsUsed': False,   # Simple auth doesn't use exclude credentials
            'credentialIdLength': len(auth_data.credential_data.credential_id),
            'fakeCredentialIdLengthRequested': None,  # Simple auth doesn't use fake credentials
            'hintsSent': [],  # Simple auth doesn't use hints
            'allowedAuthenticatorAttachments': [],
            'authenticatorAttachment': authenticator_attachment_response,
            # Enhanced largeBlob debugging information (simple auth defaults)
            'largeBlobRequested': {},  # Simple auth doesn't use largeBlob
            'largeBlobClientOutput': client_extension_results.get('largeBlob', {}),
            'residentKeyRequested': None,  # Simple auth defaults
            'residentKeyRequired': False  # Simple auth defaults
        }
    }

    if min_pin_length_value is not None:
        credential_info['properties']['minPinLength'] = min_pin_length_value

    add_public_key_material(
        credential_info,
        getattr(auth_data.credential_data, 'public_key', {})
    )

    credential_data = auth_data.credential_data
    if getattr(credential_data, 'aaguid', None):
        aaguid_bytes = bytes(credential_data.aaguid)
        aaguid_hex = aaguid_bytes.hex()
        credential_info['properties']['aaguid'] = aaguid_hex
        credential_info['properties']['aaguidHex'] = aaguid_hex
        try:
            credential_info['properties']['aaguidGuid'] = str(uuid.UUID(bytes=aaguid_bytes))
        except ValueError:
            pass

    credentials.append(credential_info)
    # Persist the updated credentials list so authenticate can find it.
    savekey(uname, credentials)

    algo = auth_data.credential_data.public_key[3]
    algoname = ""
    if algo == -50:
        algoname = "ML-DSA-87 (PQC)"
    elif algo == -49:
        algoname = "ML-DSA-65 (PQC)"
    elif algo == -48:
        algoname = "ML-DSA-44 (PQC)"
    elif algo == -7:
        algoname = "ES256 (ECDSA)"
    elif algo == -257:
        algoname = "RS256 (RSA)"
    else:
        algoname = "Other (Classical)"

    # Extract actual credential information for debug
    debug_info = {
        "attestationFormat": attestation_format,
        "algorithmsUsed": [algo],
        "excludeCredentialsUsed": False,  # Simple auth doesn't use exclude credentials
        "hintsUsed": [],  # Simple auth doesn't use hints
        "credProtectUsed": "none",  # Simple auth doesn't use credProtect
        "enforceCredProtectUsed": False,
        "actualResidentKey": bool(auth_data.flags & 0x04) if hasattr(auth_data, 'flags') else False,  # RK flag from authenticator data
    }

    return jsonify({
        "status": "OK", 
        "algo": algoname,
        **debug_info
    })

@app.route("/api/authenticate/begin", methods=["POST"])
def authenticate_begin():
    uname = request.args.get("email")
    credentials = readkey(uname)
    if not credentials:
        abort(404)

    # Extract credential data in compatible format
    credential_data_list = [extract_credential_data(cred) for cred in credentials]
    
    options, state = server.authenticate_begin(
        credential_data_list,
        user_verification="discouraged"
    )
    session["state"] = state

    return jsonify(_make_json_safe(dict(options)))

@app.route("/api/authenticate/complete", methods=["POST"])
def authenticate_complete():
    uname = request.args.get("email")
    credentials = readkey(uname)
    if not credentials:
        abort(404)

    # Extract credential data in compatible format
    credential_data_list = [extract_credential_data(cred) for cred in credentials]

    response = request.json
    server.authenticate_complete(
        session.pop("state"),
        credential_data_list,
        response,
    )

    # Extract actual authentication information for debug  
    debug_info = {
        "hintsUsed": [],  # Simple auth doesn't use hints
    }

    return jsonify({
        "status": "OK",
        **debug_info
    })

@app.route("/api/deletepub", methods=["POST"])
def deletepub():
    response = request.json
    email = response["email"]
    delkey(email)
    return jsonify({"status": "OK"})

@app.route("/api/downloadcred", methods=["GET"])
def downloadcred():
    name = request.args.get("email")
    name = name + "_credential_data.pkl"
    return send_file(os.path.join(basepath, name), as_attachment=True, download_name=name)

def convert_bytes_for_json(obj):
    """Recursively convert bytes-like objects to base64 strings for JSON serialization."""
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(obj)).decode('utf-8')
    elif isinstance(obj, dict):
        return {k: convert_bytes_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_bytes_for_json(item) for item in obj]
    else:
        return obj


def add_public_key_material(target: Dict[str, Any], public_key: Any) -> None:
    """Populate JSON-friendly COSE public key details if available."""
    if not isinstance(public_key, dict):
        return

    cose_map = dict(public_key)
    target['publicKeyCose'] = convert_bytes_for_json(cose_map)

    raw_key = cose_map.get(-1)
    if isinstance(raw_key, (bytes, bytearray, memoryview)):
        target['publicKeyBytes'] = convert_bytes_for_json(raw_key)

    if 'publicKeyType' not in target:
        target['publicKeyType'] = cose_map.get(1)

    if 'publicKeyAlgorithm' not in target:
        target['publicKeyAlgorithm'] = cose_map.get(3)

@app.route("/api/credentials", methods=["GET"])
def list_credentials():
    """List all saved credentials from PKL files with comprehensive details"""
    credentials = []
    
    try:
        # Get all .pkl files in the server directory
        pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
        
        for pkl_file in pkl_files:
            # Extract email from filename
            email = pkl_file.replace('_credential_data.pkl', '')
            
            try:
                # Load credentials for this email
                user_creds = readkey(email)
                for cred in user_creds:
                    try:
                        # Handle both old format (just AttestedCredentialData) and new format (dict with comprehensive data)
                        if isinstance(cred, dict) and 'credential_data' in cred:
                            # New format with comprehensive data
                            if isinstance(cred['credential_data'], dict):
                                # Simple dict format for testing
                                cred_data = cred['credential_data']
                                auth_data = cred['auth_data']
                                user_info = cred['user_info']

                                properties_source = cred.get('properties')
                                properties_copy = properties_source.copy() if isinstance(properties_source, dict) else {}
                                attachment_value = _normalize_attachment(
                                    cred.get('authenticator_attachment')
                                    or cred.get('authenticatorAttachment')
                                    or properties_copy.get('authenticatorAttachment')
                                    or properties_copy.get('authenticator_attachment')
                                )

                                credential_info = {
                                    'email': email,
                                    'credentialId': base64.b64encode(cred_data['credential_id']).decode('utf-8'),
                                    'userName': user_info.get('name', email),
                                    'displayName': user_info.get('display_name', email),
                                    'userHandle': base64.b64encode(user_info.get('user_handle', cred_data['credential_id'])).decode('utf-8') if user_info.get('user_handle') else None,
                                    'algorithm': cred_data.get('public_key', {}).get(3, 'Unknown'),
                                    'type': 'WebAuthn',
                                    'createdAt': cred.get('registration_time'),
                                    'signCount': auth_data.get('counter', 0),
                                    
                                    # Detailed WebAuthn data
                                    'aaguid': cred_data.get('aaguid').hex() if cred_data.get('aaguid') and isinstance(cred_data.get('aaguid'), bytes) else cred_data.get('aaguid'),
                                    'flags': auth_data.get('flags', {}),
                                    'clientExtensionOutputs': cred.get('client_extension_outputs', {}),
                                    'attestationFormat': cred.get('attestation_format', 'none'),  # Fixed: use attestation_format not attestation_object
                                    'attestationStatement': convert_bytes_for_json(cred.get('attestation_statement', {})),  # Convert bytes for JSON
                                    'publicKeyAlgorithm': cred_data.get('public_key', {}).get(3),
                                    'authenticatorAttachment': attachment_value,

                                    # Properties
                                    'residentKey': auth_data.get('flags', {}).get('be', False),
                                    'largeBlob': cred.get('client_extension_outputs', {}).get('largeBlob', {}).get('supported', False),

                                    # Properties section - detailed credential information
                                    'properties': properties_copy,
                                }

                                if attachment_value is not None:
                                    properties_copy['authenticatorAttachment'] = attachment_value

                                certificate_details = cred.get('attestation_certificate')
                                if certificate_details is not None:
                                    credential_info['attestationCertificate'] = certificate_details

                                add_public_key_material(credential_info, cred_data.get('public_key', {}))
                                if credential_info.get('publicKeyAlgorithm') is not None:
                                    credential_info['algorithm'] = credential_info['publicKeyAlgorithm']

                                _augment_aaguid_fields(credential_info)
                                if isinstance(properties_copy, MutableMapping):
                                    if credential_info.get('aaguidHex'):
                                        properties_copy.setdefault('aaguid', credential_info['aaguidHex'])
                                        properties_copy.setdefault('aaguidHex', credential_info['aaguidHex'])
                                        properties_copy.setdefault('aaguidRaw', credential_info['aaguidHex'])
                                    if credential_info.get('aaguidGuid'):
                                        properties_copy.setdefault('aaguidGuid', credential_info['aaguidGuid'])
                            else:
                                # New format with real FIDO2 objects
                                cred_data = cred['credential_data']
                                auth_data = cred['auth_data']
                                user_info = cred['user_info']

                                properties_source = cred.get('properties')
                                properties_copy = properties_source.copy() if isinstance(properties_source, dict) else {}
                                attachment_value = _normalize_attachment(
                                    cred.get('authenticator_attachment')
                                    or cred.get('authenticatorAttachment')
                                    or properties_copy.get('authenticatorAttachment')
                                    or properties_copy.get('authenticator_attachment')
                                )
                                
                                # Extract detailed information
                                # Properties determined from multiple sources for best accuracy
                                # 1. First check credProps extension result (most reliable)
                                rk_from_credprops = cred.get('client_extension_outputs', {}).get('credProps', {}).get('rk', None)
                                
                                # 2. Check request parameters as fallback
                                rk_from_request = cred.get('request_params', {}).get('resident_key') == 'required'
                                
                                # 3. Use credProps if available, otherwise fall back to request params
                                resident_key_status = rk_from_credprops if rk_from_credprops is not None else rk_from_request
                                
                                # Debug resident key detection
                                
                                credential_info = {
                                    'email': email,
                                    'credentialId': base64.b64encode(cred_data.credential_id).decode('utf-8'),
                                    'userName': user_info.get('name', email),
                                    'displayName': user_info.get('display_name', email),
                                    'userHandle': base64.b64encode(user_info.get('user_handle')).decode('utf-8') if user_info.get('user_handle') else None,
                                    'algorithm': cred_data.public_key[3] if hasattr(cred_data, 'public_key') and len(cred_data.public_key) > 3 else 'Unknown',
                                    'type': 'WebAuthn',
                                    'createdAt': cred.get('registration_time'),
                                    'signCount': auth_data.counter if hasattr(auth_data, 'counter') else 0,
                                    
                                    # Detailed WebAuthn data
                                    'aaguid': cred_data.aaguid.hex() if hasattr(cred_data, 'aaguid') and cred_data.aaguid else None,
                                    'flags': {
                                        'up': bool(auth_data.flags & auth_data.FLAG.UP) if hasattr(auth_data, 'flags') else True,
                                        'uv': bool(auth_data.flags & auth_data.FLAG.UV) if hasattr(auth_data, 'flags') else True,
                                        'at': bool(auth_data.flags & auth_data.FLAG.AT) if hasattr(auth_data, 'flags') else True,
                                        'ed': bool(auth_data.flags & auth_data.FLAG.ED) if hasattr(auth_data, 'flags') else False,
                                        'be': bool(auth_data.flags & auth_data.FLAG.BE) if hasattr(auth_data, 'flags') else False,
                                        'bs': bool(auth_data.flags & auth_data.FLAG.BS) if hasattr(auth_data, 'flags') else False,
                                    },
                                    'clientExtensionOutputs': cred.get('client_extension_outputs', {}),
                                    'attestationFormat': cred.get('attestation_format', 'none'),  # Use stored attestation format
                                    'attestationStatement': convert_bytes_for_json(cred.get('attestation_statement', {})),  # Include attestation statement with bytes converted
                                    'publicKeyAlgorithm': cred_data.public_key[3] if hasattr(cred_data, 'public_key') and len(cred_data.public_key) > 3 else None,
                                    'authenticatorAttachment': attachment_value,

                                    # Properties determined from multiple sources for best accuracy
                                    'residentKey': resident_key_status,
                                    'largeBlob': cred.get('client_extension_outputs', {}).get('largeBlob', {}).get('supported', False),

                                    # Add original request parameters for debugging/verification
                                    'requestParams': cred.get('request_params', {}),

                                    # Properties section - detailed credential information
                                    'properties': properties_copy,
                                }

                                certificate_details = cred.get('attestation_certificate')
                                if certificate_details is not None:
                                    credential_info['attestationCertificate'] = certificate_details

                                if attachment_value is not None:
                                    properties_copy['authenticatorAttachment'] = attachment_value

                                add_public_key_material(credential_info, getattr(cred_data, 'public_key', {}))
                                if credential_info.get('publicKeyAlgorithm') is not None:
                                    credential_info['algorithm'] = credential_info['publicKeyAlgorithm']

                                _augment_aaguid_fields(credential_info)
                                if isinstance(properties_copy, MutableMapping):
                                    if credential_info.get('aaguidHex'):
                                        properties_copy.setdefault('aaguid', credential_info['aaguidHex'])
                                        properties_copy.setdefault('aaguidHex', credential_info['aaguidHex'])
                                        properties_copy.setdefault('aaguidRaw', credential_info['aaguidHex'])
                                    if credential_info.get('aaguidGuid'):
                                        properties_copy.setdefault('aaguidGuid', credential_info['aaguidGuid'])
                        else:
                            # Old format (just AttestedCredentialData)
                            credential_info = {
                                'email': email,
                                'credentialId': base64.b64encode(cred.credential_id).decode('utf-8'),
                                'userName': email,
                                'displayName': email,
                                'userHandle': None,
                                'algorithm': cred.public_key[3] if hasattr(cred, 'public_key') and len(cred.public_key) > 3 else 'Unknown',
                                'type': 'WebAuthn',
                                'createdAt': None,
                                'signCount': 0,

                                'authenticatorAttachment': None,

                                # Limited data available for old format
                                'aaguid': cred.aaguid.hex() if hasattr(cred, 'aaguid') and cred.aaguid else None,
                                'flags': {
                                    'up': True,  # Default assumptions for old data
                                    'uv': True,
                                    'at': True,
                                    'ed': False,
                                    'be': False,
                                    'bs': False,
                                },
                                'clientExtensionOutputs': {},
                                'attestationFormat': 'none',
                                'attestationStatement': {},  # No attestation statement for old format
                                'publicKeyAlgorithm': cred.public_key[3] if hasattr(cred, 'public_key') and len(cred.public_key) > 3 else None,
                                'residentKey': False,
                                'largeBlob': False,
                                
                                # Properties section - empty for old format
                                'properties': {},
                            }

                            add_public_key_material(credential_info, getattr(cred, 'public_key', {}))
                            if credential_info.get('publicKeyAlgorithm') is not None:
                                credential_info['algorithm'] = credential_info['publicKeyAlgorithm']

                            _augment_aaguid_fields(credential_info)

                        credentials.append(credential_info)
                    except Exception as e:
                        continue
            except Exception as e:
                continue
                
    except Exception as e:
        pass  # Continue if error reading credentials
    
    return jsonify(credentials)

# Advanced Authentication Endpoints
@app.route("/api/advanced/register/begin", methods=["POST"])
def advanced_register_begin():
    """
    Process WebAuthn CredentialCreationOptions JSON directly from the frontend.
    This preserves full extensibility and enables custom extensions.
    """
    data = request.json
    
    # Extract the publicKey object from the WebAuthn-standard JSON
    if not data or not data.get("publicKey"):
        return jsonify({"error": "Invalid request: Missing publicKey in CredentialCreationOptions"}), 400
    
    public_key = data["publicKey"]
    
    # Extract required fields with validation
    if not public_key.get("rp"):
        return jsonify({"error": "Missing required field: rp"}), 400
    if not public_key.get("user"):
        return jsonify({"error": "Missing required field: user"}), 400
    if not public_key.get("challenge"):
        return jsonify({"error": "Missing required field: challenge"}), 400
    
    # Extract user information
    user_info = public_key["user"]
    username = user_info.get("name", "")
    display_name = user_info.get("displayName", username)
    
    if not username:
        return jsonify({"error": "Username is required in user.name"}), 400
    
    # Get existing credentials for exclusion
    credentials = readkey(username)
    
    # Import required WebAuthn classes
    from fido2.webauthn import (
        PublicKeyCredentialUserEntity, 
        AttestationConveyancePreference,
        UserVerificationRequirement,
        AuthenticatorAttachment,
        ResidentKeyRequirement,
        PublicKeyCredentialParameters,
        PublicKeyCredentialType,
        PublicKeyCredentialDescriptor
    )
    from fido2.server import Fido2Server
    import secrets
    
    # Helper function to extract binary values from JSON format
    def extract_binary_value(value):
        if isinstance(value, str):
            return value
        elif isinstance(value, dict):
            if "$hex" in value:
                return bytes.fromhex(value["$hex"])
            elif "$base64" in value:
                return base64.urlsafe_b64decode(value["$base64"] + "==")
            elif "$base64url" in value:
                return base64.urlsafe_b64decode(value["$base64url"] + "==")
        return value
    
    # Process user ID
    user_id_value = user_info.get("id", "")
    if user_id_value:
        try:
            user_id_bytes = extract_binary_value(user_id_value)
            if isinstance(user_id_bytes, str):
                user_id_bytes = bytes.fromhex(user_id_bytes)
        except (ValueError, TypeError) as e:
            return jsonify({"error": f"Invalid user ID format: {e}"}), 400
    else:
        user_id_bytes = username.encode('utf-8')
    
    # Process challenge
    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = extract_binary_value(challenge_value)
            if isinstance(challenge_bytes, str):
                challenge_bytes = bytes.fromhex(challenge_bytes)
        except (ValueError, TypeError) as e:
            return jsonify({"error": f"Invalid challenge format: {e}"}), 400
    
    # Create temporary server instance
    temp_server = Fido2Server(rp)
    
    # Process timeout
    timeout = public_key.get("timeout", 90000)
    temp_server.timeout = timeout / 1000.0 if timeout else None
    
    # Process attestation
    attestation = public_key.get("attestation", "none")
    if attestation == "direct":
        temp_server.attestation = AttestationConveyancePreference.DIRECT
    elif attestation == "indirect":
        temp_server.attestation = AttestationConveyancePreference.INDIRECT
    elif attestation == "enterprise":
        temp_server.attestation = AttestationConveyancePreference.ENTERPRISE
    else:
        temp_server.attestation = AttestationConveyancePreference.NONE
    
    # Process pubKeyCredParams (algorithms)
    pub_key_cred_params = public_key.get("pubKeyCredParams", [])
    if pub_key_cred_params:
        allowed_algorithms = []
        for param in pub_key_cred_params:
            if isinstance(param, dict) and param.get("type") == "public-key" and "alg" in param:
                allowed_algorithms.append(
                    PublicKeyCredentialParameters(
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        alg=param["alg"]
                    )
                )
        if allowed_algorithms:
            temp_server.allowed_algorithms = allowed_algorithms
    else:
        # Default algorithms
        temp_server.allowed_algorithms = [
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-50),  # ML-DSA-87
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-48),  # ML-DSA-44
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-49),  # ML-DSA-65
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7),  # ES256
            PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-257),  # RS256
        ]
    
    # Process authenticatorSelection
    auth_selection = public_key.get("authenticatorSelection", {})
    if not isinstance(auth_selection, dict):
        auth_selection = {}
        public_key["authenticatorSelection"] = auth_selection

    raw_hints = public_key.get("hints")
    hints_list: List[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]

    requested_allowed = (
        public_key.get('allowedAuthenticatorAttachments')
        if 'allowedAuthenticatorAttachments' in public_key
        else None
    )
    (
        allowed_attachment_values,
        _normalized_requested,
        combine_error,
    ) = _combine_allowed_attachment_values(hints_list, requested_allowed)
    if combine_error:
        return jsonify({"error": combine_error}), 400

    if allowed_attachment_values:
        public_key['allowedAuthenticatorAttachments'] = allowed_attachment_values
    elif 'allowedAuthenticatorAttachments' in public_key:
        public_key.pop('allowedAuthenticatorAttachments', None)

    session["advanced_register_allowed_attachments"] = list(allowed_attachment_values)

    uv_req = UserVerificationRequirement.PREFERRED
    user_verification = auth_selection.get("userVerification", "preferred")
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED
    
    auth_attachment = None
    authenticator_attachment = auth_selection.get("authenticatorAttachment")
    normalized_attachment = (
        authenticator_attachment.strip()
        if isinstance(authenticator_attachment, str)
        else None
    )
    if allowed_attachment_values:
        if normalized_attachment:
            if normalized_attachment not in allowed_attachment_values:
                return (
                    jsonify(
                        {
                            "error": (
                                "Selected authenticator attachment is not permitted "
                                "by the provided hints."
                            )
                        }
                    ),
                    400,
                )
            if len(allowed_attachment_values) != 1:
                if isinstance(auth_selection, dict) and "authenticatorAttachment" in auth_selection:
                    auth_selection.pop("authenticatorAttachment", None)
                normalized_attachment = None
        elif len(allowed_attachment_values) == 1:
            normalized_attachment = allowed_attachment_values[0]
            auth_selection["authenticatorAttachment"] = normalized_attachment
        elif isinstance(auth_selection, dict) and "authenticatorAttachment" in auth_selection:
            auth_selection.pop("authenticatorAttachment", None)
            normalized_attachment = None
    else:
        if isinstance(auth_selection, dict) and "authenticatorAttachment" in auth_selection:
            auth_selection.pop("authenticatorAttachment", None)
        normalized_attachment = None

    if normalized_attachment == "platform":
        auth_attachment = AuthenticatorAttachment.PLATFORM
    elif normalized_attachment == "cross-platform":
        auth_attachment = AuthenticatorAttachment.CROSS_PLATFORM
    
    rk_req = ResidentKeyRequirement.PREFERRED
    resident_key = auth_selection.get("residentKey", "preferred")
    if auth_selection.get("requireResidentKey") is True:
        rk_req = ResidentKeyRequirement.REQUIRED
    elif resident_key == "required":
        rk_req = ResidentKeyRequirement.REQUIRED
    elif resident_key == "discouraged":
        rk_req = ResidentKeyRequirement.DISCOURAGED
    
    # Create user entity
    user_entity = PublicKeyCredentialUserEntity(
        id=user_id_bytes,
        name=username,
        display_name=display_name,
    )
    
    # Process excludeCredentials
    exclude_list = []
    exclude_credentials = public_key.get("excludeCredentials") if "excludeCredentials" in public_key else None
    if isinstance(exclude_credentials, list):
        for exclude_cred in exclude_credentials:
            if isinstance(exclude_cred, dict) and exclude_cred.get("type") == "public-key":
                cred_id = extract_binary_value(exclude_cred.get("id", ""))
                if isinstance(cred_id, str):
                    cred_id = bytes.fromhex(cred_id)
                if cred_id:
                    exclude_list.append(PublicKeyCredentialDescriptor(
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        id=cred_id
                    ))
    
    # Process extensions - pass through ALL extensions for full extensibility
    extensions = public_key.get("extensions", {})
    processed_extensions = {}
    
    # Process each extension generically to preserve custom extensions
    for ext_name, ext_value in extensions.items():
        if ext_name == "credProps":
            processed_extensions["credProps"] = bool(ext_value)
        elif ext_name == "minPinLength":
            processed_extensions["minPinLength"] = bool(ext_value)
        elif ext_name in ("credProtect", "credentialProtectionPolicy"):
            if isinstance(ext_value, int):
                protect_map = {
                    1: "userVerificationOptional",
                    2: "userVerificationOptionalWithCredentialIDList",
                    3: "userVerificationRequired",
                }
                processed_extensions["credentialProtectionPolicy"] = protect_map.get(ext_value, ext_value)
            elif isinstance(ext_value, str):
                alias_map = {
                    "userVerificationOptional": "userVerificationOptional",
                    "userVerificationOptionalWithCredentialIDList": "userVerificationOptionalWithCredentialIDList",
                    "userVerificationOptionalWithCredentialIdList": "userVerificationOptionalWithCredentialIDList",
                    "userVerificationRequired": "userVerificationRequired",
                }
                processed_extensions["credentialProtectionPolicy"] = alias_map.get(ext_value, ext_value)
            else:
                processed_extensions["credentialProtectionPolicy"] = ext_value
        elif ext_name in ("enforceCredProtect", "enforceCredentialProtectionPolicy"):
            processed_extensions["enforceCredentialProtectionPolicy"] = bool(ext_value)
        elif ext_name == "largeBlob":
            if isinstance(ext_value, str):
                processed_extensions["largeBlob"] = {"support": ext_value}
            else:
                processed_extensions["largeBlob"] = ext_value
        elif ext_name == "prf":
            if isinstance(ext_value, dict) and "eval" in ext_value:
                prf_eval = ext_value["eval"]
                processed_eval = {}
                if isinstance(prf_eval, dict):
                    if "first" in prf_eval:
                        first_value = extract_binary_value(prf_eval["first"])
                        if isinstance(first_value, str):
                            first_value = bytes.fromhex(first_value)
                        processed_eval["first"] = first_value
                    if "second" in prf_eval:
                        second_value = extract_binary_value(prf_eval["second"])
                        if isinstance(second_value, str):
                            second_value = bytes.fromhex(second_value)
                        processed_eval["second"] = second_value
                if processed_eval:
                    processed_extensions["prf"] = {"eval": processed_eval}
                else:
                    processed_extensions["prf"] = ext_value
            else:
                processed_extensions["prf"] = ext_value
        else:
            # Pass through any custom extensions as-is for full extensibility
            processed_extensions[ext_name] = ext_value
    
    # Call Fido2Server.register_begin with processed parameters
    options, state = temp_server.register_begin(
        user_entity,
        exclude_list,
        user_verification=uv_req,
        authenticator_attachment=auth_attachment,
        resident_key_requirement=rk_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )
    
    # Debug logging for largeBlob extension
    if "largeBlob" in processed_extensions:
        print(f"[DEBUG] largeBlob extension sent to Fido2Server: {processed_extensions['largeBlob']}")
        options_dict = dict(options)
        if 'extensions' in options_dict.get('publicKey', {}):
            print(f"[DEBUG] largeBlob extension in server response: {options_dict['publicKey'].get('extensions', {}).get('largeBlob')}")
        else:
            print(f"[DEBUG] No extensions in server response")
    
    # Store state and original request for completion
    session["advanced_state"] = state
    session["advanced_original_request"] = data
    
    return jsonify(_make_json_safe(dict(options)))

@app.route("/api/advanced/register/complete", methods=["POST"])
def advanced_register_complete():
    """
    Complete registration using the JSON editor content as primary source with credential response.
    The complete JSON editor content is now sent as the main object structure.
    """
    data = request.json
    
    # Extract credential response from special field
    response = data.get("__credential_response")
    if not response:
        return jsonify({"error": "Credential response is required"}), 400

    credential_response = response.get('response', {}) if isinstance(response, dict) else {}

    # The rest of the data IS the original JSON editor content (primary source of truth)
    original_request = {key: value for key, value in data.items() if not key.startswith("__")}

    original_public_key = original_request.get("publicKey") if isinstance(original_request, Mapping) else None
    original_hints: List[str] = []
    if isinstance(original_public_key, Mapping):
        raw_hints = original_public_key.get("hints")
        if isinstance(raw_hints, list):
            original_hints = [item for item in raw_hints if isinstance(item, str)]
    requested_allowed = (
        original_public_key.get('allowedAuthenticatorAttachments')
        if isinstance(original_public_key, Mapping)
        and 'allowedAuthenticatorAttachments' in original_public_key
        else None
    )
    (
        request_allowed_attachments,
        _normalized_requested,
        combine_error,
    ) = _combine_allowed_attachment_values(original_hints, requested_allowed)
    if combine_error:
        return jsonify({"error": combine_error}), 400

    session_allowed_marker = session.pop("advanced_register_allowed_attachments", None)
    if session_allowed_marker is None:
        allowed_attachments = request_allowed_attachments
    else:
        allowed_attachments = _normalize_attachment_list(session_allowed_marker)

    response_attachment = _normalize_attachment(
        response.get('authenticatorAttachment') if isinstance(response, Mapping) else None
    )
    if allowed_attachments:
        if response_attachment is None:
            return jsonify({
                "error": "Authenticator attachment could not be determined to enforce selected hints."
            }), 400
        if response_attachment not in allowed_attachments:
            return jsonify({
                "error": "Authenticator attachment is not permitted by the selected hints."
            }), 400

    if not original_request.get("publicKey"):
        return jsonify({"error": "Invalid request: Missing publicKey in JSON editor content"}), 400

    # Extract user information from the JSON editor content
    public_key = original_request["publicKey"]
    user_info = public_key.get("user", {})
    username = user_info.get("name", "")
    display_name = user_info.get("displayName", username)

    if not username:
        return jsonify({"error": "Username is required in user.name"}), 400

    credentials = readkey(username)

    auth_selection = public_key.get('authenticatorSelection', {})
    resident_key_requested = auth_selection.get('residentKey')
    resident_key_required = auth_selection.get('requireResidentKey')
    if resident_key_required is None:
        resident_key_required = resident_key_requested == 'required'

    allowed_attachment_values = list(request_allowed_attachments)

    (
        attestation_format,
        attestation_statement,
        parsed_attestation_object,
        parsed_client_data_json,
        parsed_extension_results,
        attestation_certificate_details,
    ) = _extract_attestation_details(response)

    raw_attestation_object = credential_response.get('attestationObject')
    client_data_json = credential_response.get('clientDataJSON')

    if parsed_attestation_object:
        raw_attestation_object = parsed_attestation_object
    if parsed_client_data_json:
        client_data_json = parsed_client_data_json

    client_extension_results = (
        parsed_extension_results
        if parsed_extension_results
        else (response.get('clientExtensionResults', {}) if isinstance(response, dict) else {})
    )

    min_pin_length_value = _extract_min_pin_length(client_extension_results)

    authenticator_attachment_response = _normalize_attachment(
        response.get('authenticatorAttachment') if isinstance(response, Mapping) else None
    )

    try:
        state = session.pop("advanced_state", None)
        stored_original_request = session.pop("advanced_original_request", None)
        if state is None:
            return (
                jsonify(
                    {
                        "error": "Registration state not found or has expired. "
                        "Please restart the registration process.",
                    }
                ),
                400,
            )

        auth_data = server.register_complete(state, response)

        stored_public_key: Optional[Mapping[str, Any]] = None
        if isinstance(stored_original_request, Mapping):
            stored_public_key = stored_original_request.get("publicKey")
            if not isinstance(stored_public_key, Mapping):
                stored_public_key = None

        public_key_for_checks: Optional[Mapping[str, Any]] = None
        if isinstance(stored_public_key, Mapping):
            public_key_for_checks = stored_public_key
        elif isinstance(public_key, Mapping):
            public_key_for_checks = public_key

        expected_origin = request.headers.get("Origin") or request.host_url.rstrip("/")
        attestation_checks = perform_attestation_checks(
            response if isinstance(response, Mapping) else {},
            state if isinstance(state, Mapping) else None,
            public_key_for_checks,
            auth_data,
            expected_origin,
            rp.id,
        )

        attestation_signature_valid = attestation_checks.get("signature_valid")
        attestation_root_valid = attestation_checks.get("root_valid")
        attestation_rp_id_hash_valid = attestation_checks.get("rp_id_hash_valid")
        attestation_aaguid_match = attestation_checks.get("aaguid_match")
        attestation_checks_safe = _make_json_safe(attestation_checks)
        attestation_summary = {
            "signatureValid": attestation_signature_valid,
            "rootValid": attestation_root_valid,
            "rpIdHashValid": attestation_rp_id_hash_valid,
            "aaguidMatch": attestation_aaguid_match,
        }

        # Debug logging for largeBlob extension results
        if 'largeBlob' in client_extension_results:
            print(f"[DEBUG] largeBlob client extension results: {client_extension_results['largeBlob']}")
        else:
            print(f"[DEBUG] No largeBlob extension results in client response")
            
        authenticator_extensions_summary: Dict[str, Any] = {}
        if hasattr(auth_data, 'extensions'):
            authenticator_extensions = getattr(auth_data, 'extensions')
            print(f"[DEBUG] Server auth_data extensions: {authenticator_extensions}")
            if isinstance(authenticator_extensions, Mapping):
                cred_protect_value = authenticator_extensions.get('credProtect')
                if cred_protect_value is not None:
                    cred_protect_label = describe_cred_protect(cred_protect_value)
                    if cred_protect_label != cred_protect_value:
                        print(
                            "[DEBUG] credProtect resolved to "
                            f"{cred_protect_label} (raw: {cred_protect_value})"
                        )
                authenticator_extensions_summary = summarize_authenticator_extensions(
                    authenticator_extensions
                )
        else:
            print(f"[DEBUG] No extensions in auth_data")
        
        # Helper function to extract binary values
        def extract_binary_value(value):
            if isinstance(value, str):
                return value
            elif isinstance(value, dict):
                if "$hex" in value:
                    return bytes.fromhex(value["$hex"])
                elif "$base64" in value:
                    return base64.urlsafe_b64decode(value["$base64"] + "==")
                elif "$base64url" in value:
                    return base64.urlsafe_b64decode(value["$base64url"] + "==")
            return value
        
        # Determine user handle from JSON editor content
        user_id_value = user_info.get("id", "")
        if user_id_value:
            try:
                user_handle = extract_binary_value(user_id_value)
                if isinstance(user_handle, str):
                    user_handle = bytes.fromhex(user_handle)
            except (ValueError, TypeError):
                user_handle = username.encode('utf-8')
        else:
            user_handle = username.encode('utf-8')
        
        # Store comprehensive credential data
        credential_info = {
            'credential_data': auth_data.credential_data,
            'auth_data': auth_data,
            'user_info': {
                'name': username,
                'display_name': display_name,
                'user_handle': user_handle
            },
            'registration_time': time.time(),
            'client_data_json': client_data_json or '',
            'attestation_object': raw_attestation_object or '',
            'attestation_format': attestation_format,
            'attestation_statement': attestation_statement,
            'client_extension_outputs': client_extension_results,
            'authenticator_attachment': authenticator_attachment_response,
            # Store complete original WebAuthn request for full traceability
            'original_webauthn_request': original_request,
            # Properties section - detailed credential information
            'properties': {
                'excludeCredentialsSentCount': len(public_key.get('excludeCredentials', [])),
                'excludeCredentialsUsed': False,  # Successful registration means exclusion didn't trigger
                'credentialIdLength': len(auth_data.credential_data.credential_id),
                'fakeCredentialIdLengthRequested': None,  # Extract from original request if present
                'hintsSent': public_key.get('hints', []),
                'allowedAuthenticatorAttachments': allowed_attachment_values,
                'authenticatorAttachment': authenticator_attachment_response,
                # Enhanced largeBlob debugging information
                'largeBlobRequested': public_key.get('extensions', {}).get('largeBlob', {}),
                'largeBlobClientOutput': client_extension_results.get('largeBlob', {}),
                'residentKeyRequested': resident_key_requested,
                'residentKeyRequired': bool(resident_key_required),
                'attestationSignatureValid': attestation_signature_valid,
                'attestationRootValid': attestation_root_valid,
                'attestationRpIdHashValid': attestation_rp_id_hash_valid,
                'attestationAaguidMatch': attestation_aaguid_match,
                'attestationChecks': attestation_checks_safe,
                'attestationSummary': attestation_summary,
            }
        }

        if min_pin_length_value is not None:
            credential_info['properties']['minPinLength'] = min_pin_length_value

        add_public_key_material(
            credential_info,
            getattr(auth_data.credential_data, 'public_key', {})
        )

        if authenticator_extensions_summary:
            credential_info['authenticator_extensions'] = authenticator_extensions_summary

        if attestation_certificate_details is not None:
            credential_info['attestation_certificate'] = attestation_certificate_details

        credentials.append(credential_info)
        savekey(username, credentials)
        
        # Get algorithm info
        algo = auth_data.credential_data.public_key[3]
        algoname = ""
        if algo == -50:
            algoname = "ML-DSA-87 (PQC)"
        elif algo == -49:
            algoname = "ML-DSA-65 (PQC)"
        elif algo == -48:
            algoname = "ML-DSA-44 (PQC)"
        elif algo == -7:
            algoname = "ES256 (ECDSA)"
        elif algo == -257:
            algoname = "RS256 (RSA)"
        else:
            algoname = "Other (Classical)"
        
        # Extract debug info from processed data and original request
        pub_key_params = public_key.get("pubKeyCredParams", [])
        algorithms_used = [param.get("alg") for param in pub_key_params if isinstance(param, dict) and "alg" in param]
        
        debug_info = {
            "attestationFormat": attestation_format,
            "algorithmsUsed": algorithms_used or [algo],
            "excludeCredentialsUsed": bool(public_key.get("excludeCredentials")),
            "hintsUsed": public_key.get("hints", []),
            "actualResidentKey": bool(auth_data.flags & 0x04) if hasattr(auth_data, 'flags') else False,
        }

        debug_info.update(
            {
                "attestationSignatureValid": attestation_signature_valid,
                "attestationRootValid": attestation_root_valid,
                "attestationRpIdHashValid": attestation_rp_id_hash_valid,
                "attestationAaguidMatch": attestation_aaguid_match,
                "attestationChecks": attestation_checks_safe,
                "attestationSummary": attestation_summary,
            }
        )

        extensions_requested = public_key.get("extensions", {})
        if not isinstance(extensions_requested, dict):
            extensions_requested = {}

        cred_protect_requested = extensions_requested.get("credentialProtectionPolicy")
        if cred_protect_requested is None:
            cred_protect_requested = extensions_requested.get("credProtect")

        cred_protect_mapping = {
            1: "userVerificationOptional",
            2: "userVerificationOptionalWithCredentialIDList",
            3: "userVerificationRequired",
        }

        if isinstance(cred_protect_requested, int):
            cred_protect_display = cred_protect_mapping.get(cred_protect_requested, cred_protect_requested)
        elif cred_protect_requested:
            cred_protect_display = cred_protect_requested
        else:
            cred_protect_display = "none"

        debug_info["credProtectUsed"] = cred_protect_display

        enforce_requested = extensions_requested.get("enforceCredentialProtectionPolicy")
        if enforce_requested is None:
            enforce_requested = extensions_requested.get("enforceCredProtect")
        debug_info["enforceCredProtectUsed"] = bool(enforce_requested)
        
        credential_data = auth_data.credential_data
        credential_id_bytes = getattr(credential_data, 'credential_id', b'') or b''
        credential_id_hex = credential_id_bytes.hex() if credential_id_bytes else None
        credential_id_b64 = (
            base64.b64encode(credential_id_bytes).decode('ascii') if credential_id_bytes else None
        )
        credential_id_b64url = (
            base64.urlsafe_b64encode(credential_id_bytes).rstrip(b'=').decode('ascii')
            if credential_id_bytes else None
        )

        aaguid_hex = None
        aaguid_guid = None
        if getattr(credential_data, 'aaguid', None):
            aaguid_bytes = bytes(credential_data.aaguid)
            aaguid_hex = aaguid_bytes.hex()
            try:
                aaguid_guid = str(uuid.UUID(bytes=aaguid_bytes))
            except ValueError:
                aaguid_guid = None

        if aaguid_hex:
            credential_info['properties']['aaguid'] = aaguid_hex
            credential_info['properties']['aaguidHex'] = aaguid_hex
        if aaguid_guid:
            credential_info['properties']['aaguidGuid'] = aaguid_guid

        flags_dict = {
            "AT": bool(auth_data.flags & auth_data.FLAG.AT),
            "BE": bool(auth_data.flags & auth_data.FLAG.BE),
            "BS": bool(auth_data.flags & auth_data.FLAG.BS),
            "ED": bool(auth_data.flags & auth_data.FLAG.ED),
            "UP": bool(auth_data.flags & auth_data.FLAG.UP),
            "UV": bool(auth_data.flags & auth_data.FLAG.UV),
        }

        authenticator_data_hex = bytes(auth_data).hex()
        registration_timestamp = datetime.fromtimestamp(
            credential_info['registration_time'], timezone.utc
        ).isoformat()

        resident_key_result = None
        cred_props = (
            client_extension_results.get('credProps')
            if isinstance(client_extension_results, dict)
            else None
        )
        if isinstance(cred_props, dict) and 'rk' in cred_props:
            resident_key_result = bool(cred_props.get('rk'))
        elif isinstance(cred_props, bool):
            resident_key_result = bool(cred_props)
        else:
            resident_key_result = bool(auth_data.flags & auth_data.FLAG.BE) or bool(resident_key_required)

        large_blob_result = False
        if isinstance(client_extension_results, dict) and 'largeBlob' in client_extension_results:
            large_blob_value = client_extension_results.get('largeBlob')
            if isinstance(large_blob_value, dict):
                large_blob_result = bool(
                    large_blob_value.get('supported')
                    or large_blob_value.get('written')
                    or large_blob_value.get('blob')
                    or large_blob_value.get('result')
                )
            else:
                large_blob_result = bool(large_blob_value)

        rp_info = {
            "aaguid": {
                "raw": aaguid_hex,
                "guid": aaguid_guid,
            },
            "attestationFmt": attestation_format,
            "attestationObject": credential_info.get('attestation_object'),
            "createdAt": registration_timestamp,
            "credentialId": credential_id_hex,
            "credentialIdBase64": credential_id_b64,
            "credentialIdBase64Url": credential_id_b64url,
            "device": {
                "name": "Unknown device",
                "type": "unknown",
            },
            "largeBlob": large_blob_result,
            "publicKeyAlgorithm": algo,
            "registrationData": {
                "authenticatorData": authenticator_data_hex,
                "clientExtensionResults": client_extension_results,
                "flags": flags_dict,
                "signatureCounter": auth_data.counter,
                "attestationChecks": attestation_checks_safe,
                "attestationSummary": attestation_summary,
            },
            "residentKey": resident_key_result,
            "userHandle": {
                "base64": base64.b64encode(user_handle).decode('ascii'),
                "base64url": base64.urlsafe_b64encode(user_handle).rstrip(b'=').decode('ascii'),
                "hex": user_handle.hex(),
            },
        }

        rp_info["attestationSummary"] = attestation_summary

        if authenticator_extensions_summary:
            rp_info["registrationData"]["authenticatorExtensions"] = _make_json_safe(
                authenticator_extensions_summary
            )

        if attestation_certificate_details:
            rp_info["attestationCertificate"] = attestation_certificate_details

        return jsonify({
            "status": "OK",
            "algo": algoname,
            **debug_info,
            "relyingParty": rp_info,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/advanced/authenticate/begin", methods=["POST"])
def advanced_authenticate_begin():
    """
    Process WebAuthn CredentialRequestOptions JSON directly from the frontend.
    This preserves full extensibility and enables custom extensions.
    """
    data = request.json
    
    # Extract the publicKey object from the WebAuthn-standard JSON
    if not data or not data.get("publicKey"):
        return jsonify({"error": "Invalid request: Missing publicKey in CredentialRequestOptions"}), 400
    
    public_key = data["publicKey"]

    # Extract required fields with validation
    if not public_key.get("challenge"):
        return jsonify({"error": "Missing required field: challenge"}), 400

    raw_hints = public_key.get("hints")
    hints_list: List[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]
    requested_allowed = (
        public_key.get("allowedAuthenticatorAttachments")
        if "allowedAuthenticatorAttachments" in public_key
        else None
    )
    (
        allowed_attachment_values,
        _normalized_requested,
        combine_error,
    ) = _combine_allowed_attachment_values(hints_list, requested_allowed)
    if combine_error:
        return jsonify({"error": combine_error}), 400

    session["advanced_authenticate_allowed_attachments"] = list(allowed_attachment_values)

    # Helper function to extract binary values
    def extract_binary_value(value):
        if isinstance(value, str):
            return value
        elif isinstance(value, dict):
            if "$hex" in value:
                return bytes.fromhex(value["$hex"])
            elif "$base64" in value:
                return base64.urlsafe_b64decode(value["$base64"] + "==")
            elif "$base64url" in value:
                return base64.urlsafe_b64decode(value["$base64url"] + "==")
        return value
    
    # Process challenge
    challenge_value = public_key.get("challenge", "")
    challenge_bytes = None
    if challenge_value:
        try:
            challenge_bytes = extract_binary_value(challenge_value)
            if isinstance(challenge_bytes, str):
                challenge_bytes = bytes.fromhex(challenge_bytes)
        except (ValueError, TypeError) as e:
            return jsonify({"error": f"Invalid challenge format: {e}"}), 400
    
    # Import required WebAuthn classes
    from fido2.webauthn import (
        UserVerificationRequirement,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType
    )
    from fido2.server import Fido2Server
    import secrets

    # Create temporary server instance
    temp_server = Fido2Server(rp)

    credential_attachment_map: Dict[bytes, Optional[str]] = {}
    if allowed_attachment_values:
        credential_attachment_map = _build_credential_attachment_map()

    # Process timeout
    timeout = public_key.get("timeout", 90000)
    temp_server.timeout = timeout / 1000.0 if timeout else None
    
    # Process user verification
    user_verification = public_key.get("userVerification", "preferred")
    uv_req = UserVerificationRequirement.PREFERRED
    if user_verification == "required":
        uv_req = UserVerificationRequirement.REQUIRED
    elif user_verification == "discouraged":
        uv_req = UserVerificationRequirement.DISCOURAGED
    
    # Process allowCredentials
    allow_credentials = public_key.get("allowCredentials", [])
    selected_credentials = None
    
    if not allow_credentials or len(allow_credentials) == 0:
        # Empty allowCredentials for discoverable credentials only
        selected_credentials = None
    else:
        # Process allowCredentials list
        selected_credentials = []
        for allow_cred in allow_credentials:
            if isinstance(allow_cred, dict) and allow_cred.get("type") == "public-key":
                cred_id = extract_binary_value(allow_cred.get("id", ""))
                if isinstance(cred_id, str):
                    cred_id = bytes.fromhex(cred_id)
                if cred_id:
                    selected_credentials.append(PublicKeyCredentialDescriptor(
                        type=PublicKeyCredentialType.PUBLIC_KEY,
                        id=cred_id
                    ))
        
        # If no valid credentials were parsed but allowCredentials was specified,
        # try to match with stored credentials by scanning all users
        if not selected_credentials:
            try:
                pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
                for pkl_file in pkl_files:
                    email = pkl_file.replace('_credential_data.pkl', '')
                    try:
                        user_creds = readkey(email)
                        for cred in user_creds:
                            credential_data = extract_credential_data(cred)
                            cred_id_bytes: Optional[bytes] = None
                            if isinstance(credential_data, Mapping):
                                raw_id = credential_data.get('credential_id')
                                if isinstance(raw_id, (bytes, bytearray, memoryview)):
                                    cred_id_bytes = bytes(raw_id)
                            else:
                                raw_id = getattr(credential_data, 'credential_id', None)
                                if isinstance(raw_id, (bytes, bytearray, memoryview)):
                                    cred_id_bytes = bytes(raw_id)
                            if cred_id_bytes:
                                selected_credentials.append(PublicKeyCredentialDescriptor(
                                    type=PublicKeyCredentialType.PUBLIC_KEY,
                                    id=cred_id_bytes
                                ))
                    except Exception:
                        continue
            except Exception:
                selected_credentials = []

        if allowed_attachment_values and isinstance(selected_credentials, list):
            filtered_descriptors: List[PublicKeyCredentialDescriptor] = []
            for descriptor in selected_credentials:
                descriptor_id_bytes: Optional[bytes] = None
                try:
                    descriptor_id_bytes = bytes(descriptor.id)
                except Exception:
                    descriptor_id_bytes = None
                if descriptor_id_bytes is None:
                    continue
                attachment_value = credential_attachment_map.get(descriptor_id_bytes)
                if attachment_value and attachment_value in allowed_attachment_values:
                    filtered_descriptors.append(descriptor)
            selected_credentials = filtered_descriptors

    # For non-empty allowCredentials, ensure we have credentials
    if allow_credentials and selected_credentials is not None and len(selected_credentials) == 0:
        if allowed_attachment_values:
            return jsonify({
                "error": "No credentials matched the selected hints. Please adjust your hints or select different credentials."
            }), 404
        return jsonify({"error": "No matching credentials found. Please register first."}), 404
    
    # Process extensions - pass through ALL extensions for full extensibility
    extensions = public_key.get("extensions", {})
    processed_extensions = {}
    
    # Process each extension generically to preserve custom extensions
    for ext_name, ext_value in extensions.items():
        if ext_name == "largeBlob":
            if isinstance(ext_value, dict):
                if ext_value.get("read"):
                    processed_extensions["largeBlob"] = {"read": True}
                elif ext_value.get("write"):
                    write_value = extract_binary_value(ext_value["write"])
                    if isinstance(write_value, str):
                        write_value = bytes.fromhex(write_value)
                    processed_extensions["largeBlob"] = {"write": write_value}
                else:
                    processed_extensions["largeBlob"] = ext_value
            else:
                processed_extensions["largeBlob"] = ext_value
        elif ext_name == "prf":
            if isinstance(ext_value, dict) and "eval" in ext_value:
                prf_eval = ext_value["eval"]
                processed_eval = {}
                if "first" in prf_eval:
                    first_value = extract_binary_value(prf_eval["first"])
                    if isinstance(first_value, str):
                        first_value = bytes.fromhex(first_value)
                    processed_eval["first"] = first_value
                if "second" in prf_eval:
                    second_value = extract_binary_value(prf_eval["second"])
                    if isinstance(second_value, str):
                        second_value = bytes.fromhex(second_value)
                    processed_eval["second"] = second_value
                if processed_eval:
                    processed_extensions["prf"] = {"eval": processed_eval}
            else:
                processed_extensions["prf"] = ext_value
        else:
            # Pass through any custom extensions as-is for full extensibility
            processed_extensions[ext_name] = ext_value
    
    # Call Fido2Server.authenticate_begin with processed parameters
    options, state = temp_server.authenticate_begin(
        selected_credentials,
        user_verification=uv_req,
        challenge=challenge_bytes,
        extensions=processed_extensions if processed_extensions else None,
    )
    
    # Store state and original request for completion
    session["advanced_auth_state"] = state
    session["advanced_original_auth_request"] = data
    
    return jsonify(_make_json_safe(dict(options)))

@app.route("/api/advanced/authenticate/complete", methods=["POST"])
def advanced_authenticate_complete():
    """
    Complete authentication using the JSON editor content as primary source with assertion response.
    The complete JSON editor content is now sent as the main object structure.
    """
    data = request.json
    
    # Extract assertion response from special field
    response = data.get("__assertion_response")
    if not response:
        return jsonify({"error": "Assertion response is required"}), 400
    
    # The rest of the data IS the original JSON editor content (primary source of truth)
    original_request = {key: value for key, value in data.items() if not key.startswith("__")}

    public_key_raw = original_request.get("publicKey")
    if not isinstance(public_key_raw, Mapping):
        return jsonify({"error": "Invalid request: Missing publicKey in JSON editor content"}), 400

    public_key = public_key_raw

    raw_hints = public_key.get("hints")
    hints_list: List[str] = []
    if isinstance(raw_hints, list):
        hints_list = [item for item in raw_hints if isinstance(item, str)]

    requested_allowed = (
        public_key.get("allowedAuthenticatorAttachments")
        if "allowedAuthenticatorAttachments" in public_key
        else None
    )
    (
        request_allowed_attachments,
        _normalized_requested,
        combine_error,
    ) = _combine_allowed_attachment_values(hints_list, requested_allowed)
    if combine_error:
        return jsonify({"error": combine_error}), 400

    session_allowed_marker = session.pop("advanced_authenticate_allowed_attachments", None)
    if session_allowed_marker is None:
        allowed_attachments = request_allowed_attachments
    else:
        allowed_attachments = _normalize_attachment_list(session_allowed_marker)

    if allowed_attachments:
        response_attachment = _normalize_attachment(
            response.get('authenticatorAttachment') if isinstance(response, Mapping) else None
        )
        if response_attachment is None:
            return jsonify({
                "error": "Authenticator attachment could not be determined to enforce selected hints."
            }), 400
        if response_attachment not in allowed_attachments:
            return jsonify({
                "error": "Authenticator attachment is not permitted by the selected hints."
            }), 400
    
    # Get all credentials from all users to find the matching one
    all_credentials = []
    try:
        pkl_files = [f for f in os.listdir(basepath) if f.endswith('_credential_data.pkl')]
        for pkl_file in pkl_files:
            email = pkl_file.replace('_credential_data.pkl', '')
            try:
                user_creds = readkey(email)
                credential_data_list = [extract_credential_data(cred) for cred in user_creds]
                all_credentials.extend(credential_data_list)
            except Exception:
                continue
    except Exception:
        pass
        
    if not all_credentials:
        return jsonify({"error": "No credentials found"}), 404
    
    try:
        # Complete authentication using stored state
        auth_result = server.authenticate_complete(
            session.pop("advanced_auth_state"),
            all_credentials,
            response,
        )
        
        # Extract debug information from original request for traceability
        hints_used = public_key.get("hints", [])
        
        debug_info = {
            "hintsUsed": hints_used,
        }
        
        return jsonify({
            "status": "OK",
            **debug_info
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def main():
    # Note: using localhost without TLS, as some browsers do
    # not allow Webauthn in case of TLS certificate errors.
    # See https://lists.w3.org/Archives/Public/public-webauthn/2022Nov/0135.html
    app.run(
        host="localhost",
        port=5000,
        ssl_context=("localhost+1.pem", "localhost+1-key.pem"),
        debug=True
    )

if __name__ == "__main__":
    main()