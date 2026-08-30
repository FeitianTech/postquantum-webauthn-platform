"""Configuration and application setup for the demo WebAuthn server."""
from __future__ import annotations

import base64
import gzip
import ipaddress
import os
from pathlib import Path
import re
import ssl
import tempfile
import textwrap
from typing import Mapping, Optional, Set
from urllib.parse import urlsplit

import fido2.features
from flask import Flask, has_request_context, request
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

from .env_flags import parse_env_flag

# Enable webauthn-json mapping if available (compatible across fido2 versions)
try:  # pragma: no cover - compatibility shim
    fido2.features.webauthn_json_mapping.enabled = True
except Exception:  # pragma: no cover - compatibility shim
    try:
        fido2.features.webauthn_json.enabled = True
    except Exception:  # pragma: no cover - compatibility shim
        pass

_PACKAGE_ROOT = Path(__file__).resolve().parent


def _discover_project_root(package_root: Path) -> Path:
    """Locate the repository/application root across supported layouts."""

    for candidate in package_root.parents:
        if (candidate / "frontend").is_dir():
            return candidate

    # Fallback keeps previous behavior for environments without frontend files.
    return package_root.parents[1]


_PROJECT_ROOT = _discover_project_root(_PACKAGE_ROOT)
_FRONTEND_ROOT = _PROJECT_ROOT / "frontend"
_FRONTEND_STATIC_ROOT = _FRONTEND_ROOT / "static"
_FRONTEND_TEMPLATE_ROOT = _FRONTEND_ROOT / "templates"
_SERVER_RUNTIME_ROOT = Path(
    os.environ.get(
        "FIDO_SERVER_RUNTIME_ROOT",
        str(_PROJECT_ROOT / "server" / "runtime"),
    )
)

_existing_app = globals().get("app")
if isinstance(_existing_app, Flask):
    app = _existing_app
else:
    app = Flask(
        __name__,
        static_folder=str(_FRONTEND_STATIC_ROOT),
        static_url_path="",
        template_folder=str(_FRONTEND_TEMPLATE_ROOT),
    )


def _resolve_secret_key() -> bytes:
    """Return the Flask session secret."""

    env_value = os.environ.get("FIDO_SERVER_SECRET_KEY")
    if isinstance(env_value, str) and env_value:
        return env_value.encode("utf-8")

    file_path = os.environ.get("FIDO_SERVER_SECRET_KEY_FILE")
    if isinstance(file_path, str) and file_path:
        try:
            with open(file_path, "rb") as key_file:
                file_value = key_file.read()
                if file_value:
                    return file_value
        except OSError as exc:  # pragma: no cover - depends on deployment
            app.logger.warning(
                "Unable to read secret key file %s: %s", file_path, exc
            )

    default_path = os.path.join(app.instance_path, "session-secret.key")

    def _read_stored_key() -> Optional[bytes]:
        try:
            with open(default_path, "rb") as stored_key:
                stored_value = stored_key.read()
                if stored_value:
                    return stored_value
        except FileNotFoundError:
            return None
        except OSError:
            return None
        return None

    stored = _read_stored_key()
    if stored:
        return stored

    secret = os.urandom(32)

    try:
        os.makedirs(os.path.dirname(default_path), exist_ok=True)
    except OSError as exc:  # pragma: no cover - depends on deployment
        app.logger.warning("Unable to store generated session secret: %s", exc)
        return secret

    try:
        fd, temp_path = tempfile.mkstemp(
            prefix="session-secret.", dir=os.path.dirname(default_path)
        )
    except OSError as exc:  # pragma: no cover - depends on deployment
        app.logger.warning("Unable to store generated session secret: %s", exc)
        return secret
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(secret)
            target.flush()
            os.fsync(target.fileno())
        try:
            os.replace(temp_path, default_path)
        except OSError as exc:  # pragma: no cover - depends on deployment
            app.logger.warning("Unable to store generated session secret: %s", exc)
            try:
                os.unlink(temp_path)
            except OSError:
                pass
    finally:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    stored = _read_stored_key()
    if stored:
        return stored

    return secret


app.secret_key = _resolve_secret_key()

_COMPRESSIBLE_MIMETYPES = {
    "application/javascript",
    "application/json",
    "application/manifest+json",
    "application/xml",
    "image/svg+xml",
    "text/css",
    "text/html",
    "text/javascript",
    "text/plain",
    "text/xml",
}
_DEFAULT_COMPRESSION_MIN_SIZE = 512
_RESPONSE_COMPRESSION_MARKER = "_postquantum_response_compression"


def _accepts_gzip() -> bool:
    if not has_request_context():
        return False
    accepted = request.headers.get("Accept-Encoding", "")
    return "gzip" in accepted.lower()


def _append_vary(existing: Optional[str], value: str) -> str:
    tokens = [token.strip() for token in (existing or "").split(",") if token.strip()]
    lowered = {token.lower() for token in tokens}
    if value.lower() not in lowered:
        tokens.append(value)
    return ", ".join(tokens)


def maybe_compress_response(response):
    if not _accepts_gzip():
        return response

    if response.status_code < 200 or response.status_code >= 300:
        return response

    if response.headers.get("Content-Encoding"):
        return response

    mimetype = (response.mimetype or "").lower()
    if mimetype not in _COMPRESSIBLE_MIMETYPES and not mimetype.startswith("text/"):
        return response

    if response.direct_passthrough:
        response.direct_passthrough = False

    try:
        payload = response.get_data()
    except Exception:  # pragma: no cover - depends on response type
        return response

    min_size = app.config.get("RESPONSE_COMPRESSION_MIN_SIZE", _DEFAULT_COMPRESSION_MIN_SIZE)
    if not payload or len(payload) < int(min_size):
        return response

    compressed = gzip.compress(payload, compresslevel=6)
    if len(compressed) >= len(payload):
        return response

    response.set_data(compressed)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = str(len(compressed))
    response.headers["Vary"] = _append_vary(response.headers.get("Vary"), "Accept-Encoding")
    response.headers.pop("ETag", None)
    response.headers.pop("Content-MD5", None)
    return response


setattr(maybe_compress_response, _RESPONSE_COMPRESSION_MARKER, True)


def _register_after_request_once(flask_app: Flask, handler) -> None:
    existing_handlers = flask_app.after_request_funcs.setdefault(None, [])
    for existing in existing_handlers:
        if getattr(existing, _RESPONSE_COMPRESSION_MARKER, False):
            return

    if flask_app._got_first_request:
        return

    flask_app.after_request(handler)


_register_after_request_once(app, maybe_compress_response)


def _env_flag(name: str) -> Optional[bool]:
    """Return ``True`` or ``False`` when the named env var is explicitly set."""
    return parse_env_flag(name)

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
        host = _resolve_request_host()
        if host in {"", None}:
            return "localhost"
        try:
            if ipaddress.ip_address(host).is_loopback:
                return "localhost"
        except ValueError:
            pass
        if host in {"127.0.0.1", "::1"}:
            return "localhost"
        return host

    return "localhost"


def _resolve_request_host() -> Optional[str]:
    """Return the current request host without port decoration."""

    if not has_request_context():
        return None

    for raw_host in (
        request.headers.get("Host"),
        request.environ.get("HTTP_HOST"),
        request.environ.get("SERVER_NAME"),
    ):
        host = _normalise_request_host(raw_host)
        if host:
            return host

    return None


def _normalise_request_host(raw_host: Optional[str]) -> Optional[str]:
    """Normalise a raw host header into a lowercase hostname or IP literal."""

    if not isinstance(raw_host, str):
        return None

    host = raw_host.strip().lower()
    if not host:
        return None

    if host.startswith("["):
        closing_index = host.find("]")
        if closing_index != -1:
            unwrapped = host[1:closing_index].strip()
            return unwrapped or None

    if host.count(":") > 1:
        # Treat unbracketed multi-colon values as IPv6 literals without ports.
        return host

    parsed = urlsplit(f"//{host}")
    normalised = parsed.hostname
    if isinstance(normalised, str) and normalised.strip():
        return normalised.strip().lower()

    return host


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
MDS_METADATA_FILENAME = "blob.jwt"
MDS_METADATA_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), MDS_METADATA_FILENAME)
MDS_METADATA_VERIFIED_PATH = os.path.join(
    str(_FRONTEND_STATIC_ROOT), "fido-mds3.verified.json"
)
MDS_METADATA_CACHE_PATH = MDS_METADATA_VERIFIED_PATH + ".meta.json"
MDS_EXPLORER_PATH = os.path.join(str(_FRONTEND_STATIC_ROOT), "fido-mds3.explorer.json")
MDS_EXPLORER_META_PATH = MDS_EXPLORER_PATH + ".meta.json"
SESSION_METADATA_DIR = os.environ.get(
    "FIDO_SERVER_SESSION_METADATA_DIR",
    os.path.join(str(_SERVER_RUNTIME_ROOT), "session-metadata"),
)

FIDO_METADATA_TRUST_ROOT_B64 = (
    "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"
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
    "MDS_EXPLORER_META_PATH",
    "MDS_EXPLORER_PATH",
    "MDS_METADATA_FILENAME",
    "MDS_METADATA_PATH",
    "MDS_METADATA_VERIFIED_PATH",
    "MDS_METADATA_URL",
    "SESSION_METADATA_DIR",
    "FIDO_METADATA_TRUST_ROOT_CERT",
    "FIDO_METADATA_TRUST_ROOT_PEM",
    "MDS_TLS_ADDITIONAL_TRUST_ANCHORS_PEM",
]
