"""Tests of registration persistence behavior."""

from __future__ import annotations

import json

from server.app.storage import common as storage_common
from server.app.storage import credentials, github_mirror
from tests.app.entry_app import entry_app
from tests.app.security import ceremony_helpers as ceremony


def test_real_registration_round_trips_through_the_json_store(monkeypatch, tmp_path):
    """A genuinely-signed registration persists its counter record and reads it back intact.

    The record is what the counter check reads, with the registration's time and
    user handle: the credential ID and the user handle as bytes, the counter, the
    time. The store's codec keeps fido2's own types for records stored whole by
    earlier versions (``test_record_format.py``).
    """

    root = tmp_path / "instance" / "session-credentials"
    root.mkdir(parents=True)
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(root))
    (tmp_path / "flat").mkdir()
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)
    monkeypatch.setattr(github_mirror, "record_registration_event", lambda _event: None)

    # The encoder raises on a value it cannot represent, so a 200 means the record has none.
    client = entry_app().test_client()
    begin = client.post(
        "/api/register/begin?email=alice@example.com",
        json={"credentials": []},
        headers={"Host": ceremony.RP_ID},
    )
    assert begin.status_code == 200
    challenge = ceremony.unb64u(begin.get_json()["publicKey"]["challenge"])

    authenticator = ceremony.Authenticator()
    complete = client.post(
        "/api/register/complete?email=alice@example.com",
        json=ceremony.registration_payload(authenticator, challenge=challenge),
        headers={"Host": ceremony.RP_ID, "Origin": ceremony.ORIGIN},
    )
    assert complete.status_code == 200, complete.get_data(as_text=True)

    written = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix != ".lock" and p.name != ".gitignore")
    assert len(written) == 1
    assert written[0].name == "alice@example.com_credential_data.json"
    envelope = json.loads(written[0].read_text(encoding="utf-8"))
    assert envelope["version"] == 1 and envelope["encoding"] == "base64url"

    # The store reads it back from the session folder it wrote it into.
    records = credentials.readkey("alice@example.com", session_id=written[0].parent.name)
    assert len(records) == 1
    assert sorted(records[0]) == ["credential_id", "registration_time", "sign_count", "user_handle"]
    assert records[0]["credential_id"] == authenticator.credential_id
    assert records[0]["sign_count"] == 0
    assert len(records[0]["user_handle"]) == 32
