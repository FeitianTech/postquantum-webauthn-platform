"""Read an android-safetynet attestation's response: a JWS, shown and NOT verified.

WebAuthn L3 section 8.5: attStmt.response is the UTF-8 result of SafetyNet's
getJwsResult(), a JWS in compact serialization (RFC 7515 section 7.1):
BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature). The header
and payload are decoded as JSON, the header's x5c certificates (base64 DER,
RFC 7515 section 4.1.6) as X.509 with ``cryptography``; the signature is shown
as bytes. None of it is verified: not the signature, not its chain to
attest.android.com, not the nonce, not ctsProfileMatch. And the format is
deprecated: section 8.5 says it "is expected to be removed".
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ... import encoding
from . import certificate_summary

NOT_VERIFIED = (
    "NOT VERIFIED: the JWS signature, its certificate chain, the nonce "
    "(base64 of SHA-256(authenticatorData || clientDataHash)) and ctsProfileMatch are not checked"
)
DEPRECATED = "WebAuthn L3 section 8.5: this format is deprecated and expected to be removed"


def read_response(response: Any) -> dict[str, Any]:
    view: dict[str, Any] = {"verification": NOT_VERIFIED, "deprecated": DEPRECATED}
    if isinstance(response, bytes):
        try:
            text = response.decode("utf-8")
        except UnicodeDecodeError as exc:
            view["error"] = f"response is not UTF-8 (at byte {exc.start})"
            return view
    elif isinstance(response, str):
        text = response
    else:
        view["error"] = "response is a byte string holding a JWS; this is not"
        return view

    parts = text.split(".")
    if len(parts) != 3:
        view["error"] = f"a JWS in compact serialization has 3 parts separated by '.'; this has {len(parts)}"
        return view
    header, payload, signature = parts
    view["header"] = _json_part("header", header)
    view["payload"] = _json_part("payload", payload)
    signature_bytes = encoding.try_decode_base64url(signature)
    view["signature"] = (
        {"length": len(signature_bytes), "hex": signature_bytes.hex(), "note": "not verified"}
        if signature_bytes is not None
        else {"error": "the signature part is not base64url"}
    )
    certificates = view["header"].get("json", {}).get("x5c") if isinstance(view["header"].get("json"), dict) else None
    if isinstance(certificates, list):
        view["header"]["certificates"] = [_certificate(entry) for entry in certificates]
    timestamp = view["payload"].get("json", {}).get("timestampMs") if isinstance(view["payload"].get("json"), dict) else None
    if isinstance(timestamp, int) and not isinstance(timestamp, bool):
        view["payload"]["timestampUtc"] = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).isoformat()
    return view


def _json_part(name: str, part: str) -> dict[str, Any]:
    data = encoding.try_decode_base64url(part)
    if data is None:
        return {"error": f"the {name} part is not base64url"}
    try:
        return {"json": json.loads(data.decode("utf-8"))}
    except UnicodeDecodeError as exc:
        return {"error": f"the {name} is not UTF-8 (at byte {exc.start})"}
    except json.JSONDecodeError as exc:
        return {"error": f"the {name} is not JSON: {exc.msg} at character {exc.pos}", "text": data.decode("utf-8")}


def _certificate(entry: Any) -> dict[str, Any]:
    der = encoding.try_decode_base64(entry) if isinstance(entry, str) else None
    if der is None:
        return {"error": "an x5c entry is base64 DER; this is not"}
    return certificate_summary.summarize(der)
