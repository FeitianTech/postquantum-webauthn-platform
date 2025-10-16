"""Configuration and application setup for the demo WebAuthn server."""
from __future__ import annotations

import base64
import os
import re
import ssl
import textwrap
from typing import Mapping, Optional, Set

import fido2.features
from flask import Flask, has_request_context, request
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

# Enable webauthn-json mapping if available (compatible across fido2 versions)
try:  # pragma: no cover - compatibility shim
    fido2.features.webauthn_json_mapping.enabled = True
except Exception:  # pragma: no cover - compatibility shim
    try:
        fido2.features.webauthn_json.enabled = True
    except Exception:  # pragma: no cover - compatibility shim
        pass

app = Flask(__name__, static_url_path="", template_folder="static/templates")
app.secret_key = os.urandom(32)  # Used for session.


def _env_flag(name: str) -> Optional[bool]:
    """Return ``True`` or ``False`` when the named env var is explicitly set."""

    raw_value = os.environ.get(name)
    if raw_value is None:
        return None

    normalised = raw_value.strip().lower()
    if normalised in {"", "0", "false", "off", "no"}:
        return False
    return True

_DEFAULT_RP_NAME = os.environ.get("FIDO_SERVER_RP_NAME", "Demo server")
_DEFAULT_RP_ID = os.environ.get("FIDO_SERVER_RP_ID")
app.config.setdefault("FIDO_SERVER_RP_NAME", _DEFAULT_RP_NAME)
app.config.setdefault("FIDO_SERVER_RP_ID", _DEFAULT_RP_ID)

_session_metadata_recover_flag = _env_flag("FIDO_SERVER_SESSION_METADATA_RECOVER")
if _session_metadata_recover_flag is not None:
    app.config["SESSION_METADATA_RECOVER_ON_START"] = _session_metadata_recover_flag


def _parse_trusted_ca_subjects(raw_value: Optional[str]) -> Optional[Set[str]]:
    """Normalise a comma or newline separated list of CA subject names."""

    if raw_value is None:
        return None

    components = re.split(r"[,;\n]+", raw_value)
    subjects = {component.strip() for component in components if component.strip()}
    if not subjects:
        return None
    return subjects


def _parse_trusted_ca_fingerprints(raw_value: Optional[str]) -> Optional[Set[str]]:
    """Normalise a list of hexadecimal fingerprints for trusted CA certificates."""

    if raw_value is None:
        return None

    components = re.split(r"[,;\n]+", raw_value)
    fingerprints = set()
    for component in components:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", component)
        if cleaned:
            normalised = cleaned.upper()
            # Require at least 20 bytes / 40 hex characters to avoid trivial matches.
            if len(normalised) >= 40:
                fingerprints.add(normalised)
    if not fingerprints:
        return None
    return fingerprints


app.config.setdefault(
    "TRUSTED_ATTESTATION_CA_SUBJECTS",
    _parse_trusted_ca_subjects(
        os.environ.get("FIDO_SERVER_TRUSTED_ATTESTATION_CA_SUBJECTS")
    ),
)
app.config.setdefault(
    "TRUSTED_ATTESTATION_CA_FINGERPRINTS",
    _parse_trusted_ca_fingerprints(
        os.environ.get("FIDO_SERVER_TRUSTED_ATTESTATION_CA_FINGERPRINTS")
    ),
)


def determine_rp_id(explicit_id: Optional[str] = None) -> str:
    """Resolve the relying party identifier for the current request."""

    if explicit_id:
        return explicit_id

    configured_id = app.config.get("FIDO_SERVER_RP_ID")
    if isinstance(configured_id, str) and configured_id.strip():
        return configured_id.strip()

    if has_request_context():
        host = request.host.split(":", 1)[0].strip().lower()
        if host in {"", None}:
            return "localhost"
        if host in {"127.0.0.1", "::1"}:
            return "localhost"
        return host

    return "localhost"


def build_rp_entity(
    rp_data: Optional[Mapping[str, str]] = None,
    *,
    rp_id: Optional[str] = None,
    rp_name: Optional[str] = None,
) -> PublicKeyCredentialRpEntity:
    """Create a ``PublicKeyCredentialRpEntity`` for the active request."""

    rp_id_value = determine_rp_id(rp_id or (rp_data or {}).get("id"))

    rp_name_value = (
        rp_name
        or (rp_data or {}).get("name")
        or app.config.get("FIDO_SERVER_RP_NAME")
        or "Demo server"
    )

    return PublicKeyCredentialRpEntity(name=rp_name_value, id=rp_id_value)


def create_fido_server(
    rp_data: Optional[Mapping[str, str]] = None,
    *,
    rp_id: Optional[str] = None,
    rp_name: Optional[str] = None,
) -> Fido2Server:
    """Instantiate a :class:`Fido2Server` bound to the resolved RP ID."""

    entity = build_rp_entity(rp_data, rp_id=rp_id, rp_name=rp_name)
    return Fido2Server(entity)


rp = build_rp_entity()
server = Fido2Server(rp)

# Save credentials next to this module, regardless of CWD.
basepath = os.path.abspath(os.path.dirname(__file__))

MDS_METADATA_URL = "https://mds3.fidoalliance.org/"
MDS_METADATA_FILENAME = "fido-mds3.jws"
MDS_METADATA_PATH = os.path.join(basepath, "static", MDS_METADATA_FILENAME)
MDS_METADATA_CACHE_PATH = MDS_METADATA_PATH + ".meta.json"
SESSION_METADATA_DIR = os.path.join(basepath, "static", "session-metadata")

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

__all__ = [
    "app",
    "basepath",
    "build_rp_entity",
    "create_fido_server",
    "determine_rp_id",
    "rp",
    "server",
    "MDS_METADATA_CACHE_PATH",
    "MDS_METADATA_FILENAME",
    "MDS_METADATA_PATH",
    "MDS_METADATA_URL",
    "SESSION_METADATA_DIR",
    "FIDO_METADATA_TRUST_ROOT_CERT",
    "FIDO_METADATA_TRUST_ROOT_PEM",
    "MDS_TLS_ADDITIONAL_TRUST_ANCHORS_PEM",
]
