"""Signature-counter regression detection (WebAuthn L3 §7.2 step 21).

Where the "stored" counter comes from
-------------------------------------
The simple flow keeps two copies of each credential: the server-side record
written by ``savekey`` at registration, and the browser's own copy, which it
sends back as the credential list on ``/authenticate/begin``. The server record
is authoritative; the browser copy is attacker-controllable, so it may only
ever make the check *stricter*. The stored value is therefore the larger of the
two, and a missing copy simply does not contribute.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Mapping, Optional, Tuple

#: Key under which the server-side credential record keeps its latest counter.
#: Records written before it existed fall back to the registration-time
#: ``auth_data.counter``.
RECORD_SIGN_COUNT_KEY = "sign_count"


def _as_counter(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def record_credential_id(record: Any) -> Optional[bytes]:
    if not isinstance(record, Mapping):
        return None
    credential_id = getattr(record.get("credential_data"), "credential_id", None)
    if isinstance(credential_id, (bytes, bytearray, memoryview)):
        return bytes(credential_id)
    return None


def record_sign_count(record: Mapping[str, Any]) -> Optional[int]:
    counter = _as_counter(record.get(RECORD_SIGN_COUNT_KEY))
    if counter is not None:
        return counter
    return _as_counter(getattr(record.get("auth_data"), "counter", None))


def load_server_records_impl(simple_module: Any, uname: Any) -> tuple[Optional[list[Any]], Optional[str]]:
    """Read the caller's server-side credential records, or ``(None, None)``."""

    if not isinstance(uname, str) or not uname:
        return None, None
    try:
        session_id = simple_module.ensure_metadata_session_id()
        records = simple_module.readkey(uname, session_id=session_id)
    except Exception:
        simple_module.app.logger.warning(
            "Could not read stored credentials for the signature counter check", exc_info=True
        )
        return None, None
    if not isinstance(records, list):
        return None, None
    return records, session_id


def find_server_record_index(records: Optional[list[Any]], credential_id: bytes) -> Optional[int]:
    if not records:
        return None
    for index, record in enumerate(records):
        if record_credential_id(record) == credential_id:
            return index
    return None


def client_supplied_sign_count_impl(
    simple_module: Any, session_credentials: Iterable[Any], credential_id: bytes
) -> Optional[int]:
    for entry in session_credentials or ():
        if not isinstance(entry, Mapping):
            continue
        raw_id = entry.get("credentialId")
        if raw_id is None:
            continue
        try:
            entry_id = simple_module._decode_binary_value(raw_id)
        except Exception:
            continue
        if entry_id == credential_id:
            return _as_counter(entry.get("signCount"))
    return None


def resolve_stored_sign_count(
    server_record: Optional[Mapping[str, Any]], client_supplied: Optional[int]
) -> int:
    candidates = [
        value
        for value in (
            record_sign_count(server_record) if server_record is not None else None,
            client_supplied,
        )
        if value is not None
    ]
    return max(candidates) if candidates else 0
