"""Tests of credentials behavior."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pickle
import struct
from pathlib import Path

import pytest
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from server.app import visitor_session
from server.app.storage import common as storage_common
from server.app.storage import credentials
from server.app.storage import credentials as storage
from tests.app.storage.credential_seed import seed_records


@pytest.fixture
def storage_local(monkeypatch, tmp_path):
    monkeypatch.setenv("FIDO_SERVER_CREDENTIAL_DIR", str(tmp_path / "session-credentials"))
    monkeypatch.setattr(storage_common, "using_gcs", lambda: False)

    os.makedirs(storage._local_credential_base(), exist_ok=True)

    return tmp_path


def test_storage_identifier_validators_reject_invalid_inputs(storage_local):
    with pytest.raises(ValueError):
        storage._credential_prefix(None)
    with pytest.raises(ValueError):
        storage._credential_prefix("   ")

    with pytest.raises(ValueError):
        storage._credential_blob(None, "session-a")
    with pytest.raises(ValueError):
        storage._credential_blob("", "session-a")


    with pytest.raises(ValueError):
        storage._local_filename("", "session-a")
    with pytest.raises(ValueError):
        storage._local_filename(123, "session-a")


def test_resolve_session_id_uses_explicit_value_or_metadata_fallback(storage_local, monkeypatch):
    assert storage._resolve_session_id("  explicit-session  ") == "explicit-session"

    monkeypatch.setattr(
        visitor_session,
        "ensure_id",
        lambda: "fallback-session",
    )

    assert storage._resolve_session_id("   ") == "fallback-session"
    assert storage._resolve_session_id(None) == "fallback-session"


def test_local_save_and_read_roundtrip(storage_local):
    payload = [{"credential_data": "demo"}]

    seed_records(storage, "alice", payload, session_id="session-a")
    assert storage.readkey("alice", session_id="session-a") == payload


def test_local_readkey_returns_empty_for_content_that_is_not_json(storage_local):
    path = storage._local_filename("alice", "session-a", create=True)

    with open(path, "wb") as handle:
        handle.write(pickle.dumps({"not": "a list"}))
    assert storage.readkey("alice", session_id="session-a") == []

    with open(path, "wb") as handle:
        handle.write(b"not-a-pickle")
    assert storage.readkey("alice", session_id="session-a") == []


def test_public_key_material_helper(storage_local):
    target = {}
    public_key = {1: "type-a", 3: -7, -1: b"\xAA\xBB"}
    storage.add_public_key_material(target, public_key)

    assert target["publicKeyCose"][-1] == "qrs"
    assert target["publicKeyBytes"] == "qrs"
    assert target["publicKeyType"] == "type-a"
    assert target["publicKeyAlgorithm"] == -7


def test_add_public_key_material_respects_existing_type_and_algorithm(storage_local):
    target = {"publicKeyType": "existing-type", "publicKeyAlgorithm": "existing-alg"}
    storage.add_public_key_material(target, {1: "new-type", 3: "new-alg"})

    assert target["publicKeyType"] == "existing-type"
    assert target["publicKeyAlgorithm"] == "existing-alg"

    untouched = {"x": 1}
    storage.add_public_key_material(untouched, "not-a-dict")
    assert untouched == {"x": 1}


TRAVERSAL_NAMES = [
    "../x",
    "..%2Fx",
    "../../../../../../private/tmp/X",
    "a/b",
    "a\\b",
    "alice\x00.pkl",
    "a\x01b",  # a control character, as ?email=a%01b sends it
    "/etc/passwd",
    "/private/tmp/X",
    "foo/../../bar",
    "..",
    ".",
    ".hidden",
    "C:\\windows\\system32",
]


LEGITIMATE_NAMES = [
    "alice@example.com",
    "first.last@example.com",
    "user+tag@example.com",
    "a.b.c.d@example.co.uk",
    "UPPER.Case@Example.COM",
    "name_with_underscores",
    "dash-separated@example.com",
]


@pytest.fixture
def gcs_backend(monkeypatch):
    monkeypatch.setattr(storage_common, "using_gcs", lambda: True)


def _build_attested_credential_data(credential_id: bytes = b"credential-id") -> AttestedCredentialData:
    cose_key = ES256({1: 2, 3: -7, -1: 1, -2: b"\x01" * 32, -3: b"\x02" * 32})
    return AttestedCredentialData.create(bytes(16), credential_id, cose_key)


def _build_authenticator_data(credential_data: AttestedCredentialData) -> AuthenticatorData:
    raw = (
        hashlib.sha256(b"example.com").digest()
        + bytes([AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV | AuthenticatorData.FLAG.AT])
        + struct.pack(">I", 7)
        + bytes(credential_data)
    )
    return AuthenticatorData(raw)


class _CraftedPickle:
    """Pickles to ``os.makedirs(<marker>)`` -- the classic RCE gadget shape."""

    def __init__(self, marker: str):
        self._marker = marker

    def __reduce__(self):
        return (os.makedirs, (self._marker,))


@pytest.mark.parametrize("name", TRAVERSAL_NAMES)
def test_local_path_helpers_reject_traversal_names(local_store, name):
    store = credentials

    with pytest.raises(ValueError):
        store._local_filename(name, "session-a")


@pytest.mark.parametrize("name", TRAVERSAL_NAMES)
def test_public_api_rejects_traversal_names(local_store, name):
    """Saving and reading refuse rather than touching the path."""

    store = credentials

    with pytest.raises(ValueError):
        store.save_if_unchanged(name, [{"credential_data": "x"}], None, session_id="session-a")
    with pytest.raises(ValueError):
        store.readkey(name, session_id="session-a")
    with pytest.raises(ValueError):
        store.read_for_update(name, session_id="session-a")


@pytest.mark.parametrize("session_id", TRAVERSAL_NAMES)
def test_session_identifier_rejects_traversal(local_store, session_id):
    """The session segment is attacker-influenced too, so it gets the same check."""

    store = credentials

    with pytest.raises(ValueError):
        store._local_filename("alice@example.com", session_id)


def test_traversal_never_creates_anything_outside_the_root(local_store):
    """The verified exploit path: ``?email=../../../..`` must not write out."""

    store = credentials
    outside = local_store.tmp_path / "outside"
    outside.mkdir()
    escape = "../../outside/pwned"

    with pytest.raises(ValueError):
        store.save_if_unchanged(escape, [{"credential_data": "x"}], None, session_id="session-a")

    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("name", LEGITIMATE_NAMES)
def test_legitimate_names_resolve_inside_the_credential_root(local_store, name):
    store = credentials
    root = os.path.realpath(str(local_store.root))

    path = store._local_filename(name, "session-a")
    resolved = os.path.realpath(path)

    assert resolved.startswith(root + os.sep)
    assert os.path.basename(resolved) == f"{name}_credential_data.json"


@pytest.mark.parametrize("name", LEGITIMATE_NAMES)
def test_legitimate_names_round_trip_through_the_store(local_store, name):
    store = credentials
    payload = [{"credential_data": "demo", "user_info": {"name": name}}]

    seed_records(store, name, payload, session_id="session-a")
    assert store.readkey(name, session_id="session-a") == payload


def test_dotted_name_is_not_confused_with_a_parent_reference(local_store):
    """``first.last`` must work even though ``..`` is rejected."""

    store = credentials

    seed_records(store, "first.last@example.com", [{"a": 1}], session_id="session-a")

    assert store.readkey("first.last@example.com", session_id="session-a") == [{"a": 1}]
    with pytest.raises(ValueError):
        store.readkey("first..last@example.com", session_id="session-a")


@pytest.mark.parametrize("name", TRAVERSAL_NAMES)
def test_gcs_blob_helpers_reject_traversal_names(gcs_backend, name):
    with pytest.raises(ValueError):
        credentials._credential_blob(name, "session-a")


@pytest.mark.parametrize("session_id", TRAVERSAL_NAMES)
def test_gcs_blob_helpers_reject_traversal_sessions(gcs_backend, session_id):
    with pytest.raises(ValueError):
        credentials._credential_blob("alice@example.com", session_id)


@pytest.mark.parametrize("name", LEGITIMATE_NAMES)
def test_gcs_object_keys_stay_under_the_configured_prefix(gcs_backend, name):
    blob_name = credentials._credential_blob(name, "session-a")
    prefix = credentials._credential_prefix("session-a")

    assert blob_name.startswith(prefix.rstrip("/") + "/")
    assert ".." not in blob_name.split("/")
    assert blob_name.endswith(f"{name}_credential_data.json")


def test_json_round_trip_preserves_bytes_fields_exactly(local_store):
    store = credentials
    credential_data = _build_attested_credential_data()
    auth_data = _build_authenticator_data(credential_data)

    record = {
        "credential_data": credential_data,
        "auth_data": auth_data,
        "user_info": {
            "name": "alice@example.com",
            "user_handle": bytes(range(256)),
        },
        "attestation_statement": {
            "sig": b"\xde\xad\xbe\xef",
            "x5c": [b"\x30\x82\x01", b"\xff" * 64],
        },
        # A COSE map is keyed by integers; JSON object keys are strings, so the
        # encoder has to preserve the key types explicitly.
        "public_key": {1: 2, 3: -7, -1: b"\x00\x01\x02"},
        "empty": b"",
        "properties": {"nested": {"deeper": [b"\x01", {"k": b"\x02"}]}},
    }

    seed_records(store, "alice@example.com", [record], session_id="session-a")
    (restored,) = store.readkey("alice@example.com", session_id="session-a")

    assert restored["user_info"]["user_handle"] == bytes(range(256))
    assert isinstance(restored["user_info"]["user_handle"], bytes)
    assert restored["attestation_statement"]["sig"] == b"\xde\xad\xbe\xef"
    assert restored["attestation_statement"]["x5c"] == [b"\x30\x82\x01", b"\xff" * 64]
    assert restored["public_key"] == {1: 2, 3: -7, -1: b"\x00\x01\x02"}
    assert restored["empty"] == b""
    assert restored["properties"]["nested"]["deeper"] == [b"\x01", {"k": b"\x02"}]

    # The fido2 value classes are bytes subclasses, so they survive as the same
    # class with their parsed attributes intact.
    assert isinstance(restored["credential_data"], AttestedCredentialData)
    assert bytes(restored["credential_data"]) == bytes(credential_data)
    assert restored["credential_data"].credential_id == b"credential-id"
    assert restored["credential_data"].public_key[3] == -7

    assert isinstance(restored["auth_data"], AuthenticatorData)
    assert bytes(restored["auth_data"]) == bytes(auth_data)
    assert restored["auth_data"].counter == 7


def test_stored_file_is_json_with_base64url_bytes(local_store):
    store = credentials
    raw = bytes([0xFB, 0xFF, 0x3E, 0x3F])  # encodes with - and _ in base64url

    seed_records(store, "alice@example.com", [{"blob": raw}], session_id="session-a")

    path = store._local_filename("alice@example.com", "session-a")
    envelope = json.loads(Path(path).read_text(encoding="utf-8"))

    assert envelope["version"] == 1
    assert envelope["encoding"] == "base64url"

    encoded = envelope["credentials"][0]["blob"]["__v"]
    assert encoded == base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    assert "+" not in encoded and "/" not in encoded and "=" not in encoded
    assert base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)) == raw


def test_saving_never_writes_a_pickle_file(local_store):
    store = credentials

    seed_records(store, "alice@example.com", [{"a": 1}], session_id="session-a")

    # Beside each credential file, the empty lock file its writers take.
    locks = [p for p in local_store.root.rglob("*.lock") if p.is_file()]
    assert [p.stat().st_size for p in locks] == [0]
    written = [
        str(p) for p in local_store.root.rglob("*") if p.is_file() and p not in locks and p.name != ".gitignore"
    ]
    assert written, "expected the credential file to be written"
    assert not any(p.endswith(".pkl") for p in written)
    assert all(p.endswith(".json") for p in written)


def test_readkey_ignores_corrupt_json(local_store):
    store = credentials
    path = store._local_filename("alice@example.com", "session-a", create=True)
    Path(path).write_bytes(b"{not json at all")

    assert store.readkey("alice@example.com", session_id="session-a") == []


def test_crafted_pickle_payload_is_never_executed(local_store):
    """The proof that the deserialisation bug class is gone.

    The payload is first shown to be live -- plain ``pickle.loads`` runs it --
    and then fed to the store where the records live, which is the worst case:
    an attacker who planted it there. ``readkey`` must not run it.
    """

    store = credentials
    control_marker = local_store.tmp_path / "control-executed"
    attack_marker = local_store.tmp_path / "pwned"

    # Control: the gadget really does execute under stock pickle, so a passing
    # test below means the payload was refused, not that it was inert.
    pickle.loads(pickle.dumps(_CraftedPickle(str(control_marker))))
    assert control_marker.is_dir()

    payload = pickle.dumps(_CraftedPickle(str(attack_marker)))
    path = store._local_filename("alice@example.com", "session-a", create=True)
    Path(path).write_bytes(payload)

    assert store.readkey("alice@example.com", session_id="session-a") == []
    assert not attack_marker.exists()

    # Nor the save's read, which refuses the copy rather than replace it unread.
    with pytest.raises(store.CredentialsUndecodable):
        store.read_for_update("alice@example.com", session_id="session-a")
    assert not attack_marker.exists()


def test_crafted_pickle_payload_is_never_executed_from_gcs(monkeypatch, tmp_path):
    """Same guarantee for a downloaded object, which never touches the disk."""

    marker = tmp_path / "pwned-from-gcs"
    payload = pickle.dumps(_CraftedPickle(str(marker)))

    monkeypatch.setattr(storage_common, "using_gcs", lambda: True)
    monkeypatch.setattr(credentials, "download_bytes", lambda _blob: payload)

    assert credentials.readkey("alice@example.com", session_id="session-a") == []
    assert not marker.exists()
