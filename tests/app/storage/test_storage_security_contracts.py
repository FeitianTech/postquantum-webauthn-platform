"""Security contracts for the credential store.

Two classes of bug are pinned down here:

* **Path traversal.** ``name`` reaches the store straight from ``?email=``, so
  every helper that turns it into a filesystem path or a GCS object key must
  reject separators, ``..``, NULs, leading dots and absolute paths, and the
  resolved location must provably stay under the credential root.
* **Pickle deserialisation.** The store used to be pickle, so reading a file an
  attacker could influence was arbitrary code execution. New writes are JSON,
  and the one remaining reader for pre-existing ``.pkl`` files refuses to
  import anything outside a small allowlist of FIDO2 value classes.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import pickle
import struct
import sys
import types
from pathlib import Path

import pytest


def _discover_repo_root(start: Path) -> Path:
    for candidate in start.parents:
        if (candidate / "server").is_dir() and (candidate / "tests").is_dir():
            return candidate

    return start.parents[3]


_ROOT = _discover_repo_root(Path(__file__).resolve())

# Mirrors the bootstrap in ``test_storage.py`` so this module imports cleanly on
# its own (``pytest tests/app/storage/test_storage_security_contracts.py``).
_server_pkg = types.ModuleType("server")
_server_pkg.__path__ = [str(_ROOT / "server")]
sys.modules.setdefault("server", _server_pkg)

_server_app_pkg = types.ModuleType("server.app")
_server_app_pkg.__path__ = [str(_ROOT / "server" / "app")]
sys.modules.setdefault("server.app", _server_app_pkg)

credentials = importlib.import_module("server.app.storage.credentials")
record_format = importlib.import_module("server.app.storage.record_format")

from fido2.cose import ES256  # noqa: E402
from fido2.webauthn import AttestedCredentialData, AuthenticatorData  # noqa: E402

# Every one of these must be refused outright, not sanitised into something
# that happens to land inside the root.
TRAVERSAL_NAMES = [
    "../x",
    "..%2Fx",
    "../../../../../../private/tmp/X",
    "a/b",
    "a\\b",
    "alice\x00.pkl",
    "/etc/passwd",
    "/private/tmp/X",
    "foo/../../bar",
    "..",
    ".",
    ".hidden",
    "C:\\windows\\system32",
]

# Addresses that must keep working. Dots are legal inside an email local part,
# so the containment check must not reject them wholesale.
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
def local_store(monkeypatch, tmp_path):
    """Point the store at a temporary root with the local (non-GCS) backend."""

    root = tmp_path / "instance" / "session-credentials"
    legacy_root = tmp_path / "source-tree" / "session-credentials"
    flat_legacy = tmp_path / "source-tree"
    root.mkdir(parents=True)
    legacy_root.mkdir(parents=True)

    monkeypatch.setattr(credentials, "_LOCAL_CREDENTIAL_BASE", str(root))
    monkeypatch.setattr(credentials, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(legacy_root))
    monkeypatch.setattr(credentials, "basepath", str(flat_legacy))
    monkeypatch.setattr(credentials, "_using_gcs", lambda: False)

    return types.SimpleNamespace(
        storage=credentials,
        root=root,
        legacy_root=legacy_root,
        flat_legacy=flat_legacy,
        tmp_path=tmp_path,
    )


@pytest.fixture
def gcs_store(monkeypatch):
    monkeypatch.setattr(credentials, "_using_gcs", lambda: True)
    return credentials


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


# --------------------------------------------------------------------------
# 1. Path containment
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", TRAVERSAL_NAMES)
def test_local_path_helpers_reject_traversal_names(local_store, name):
    store = local_store.storage

    with pytest.raises(ValueError):
        store._local_filename(name, "session-a")
    with pytest.raises(ValueError):
        store._legacy_local_filename(name)


@pytest.mark.parametrize("name", TRAVERSAL_NAMES)
def test_public_api_rejects_traversal_names(local_store, name):
    """``savekey``/``readkey``/``delkey`` refuse rather than touching the path."""

    store = local_store.storage

    with pytest.raises(ValueError):
        store.savekey(name, [{"credential_data": "x"}], session_id="session-a")
    with pytest.raises(ValueError):
        store.readkey(name, session_id="session-a")
    with pytest.raises(ValueError):
        store.delkey(name, session_id="session-a")


@pytest.mark.parametrize("session_id", TRAVERSAL_NAMES)
def test_session_identifier_rejects_traversal(local_store, session_id):
    """The session segment is attacker-influenced too, so it gets the same check."""

    store = local_store.storage

    with pytest.raises(ValueError):
        store._local_directory(session_id)
    with pytest.raises(ValueError):
        store._local_filename("alice@example.com", session_id)


def test_traversal_never_creates_anything_outside_the_root(local_store):
    """The verified exploit path: ``?email=../../../..`` must not write out."""

    store = local_store.storage
    outside = local_store.tmp_path / "outside"
    outside.mkdir()
    escape = "../../outside/pwned"

    with pytest.raises(ValueError):
        store.savekey(escape, [{"credential_data": "x"}], session_id="session-a")

    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("name", LEGITIMATE_NAMES)
def test_legitimate_names_resolve_inside_the_credential_root(local_store, name):
    store = local_store.storage
    root = os.path.realpath(str(local_store.root))

    path = store._local_filename(name, "session-a")
    resolved = os.path.realpath(path)

    assert resolved.startswith(root + os.sep)
    assert os.path.basename(resolved) == f"{name}_credential_data.json"


@pytest.mark.parametrize("name", LEGITIMATE_NAMES)
def test_legitimate_names_round_trip_through_the_store(local_store, name):
    store = local_store.storage
    payload = [{"credential_data": "demo", "user_info": {"name": name}}]

    store.savekey(name, payload, session_id="session-a")
    assert store.readkey(name, session_id="session-a") == payload

    store.delkey(name, session_id="session-a")
    assert store.readkey(name, session_id="session-a") == []


def test_dotted_name_is_not_confused_with_a_parent_reference(local_store):
    """``first.last`` must work even though ``..`` is rejected."""

    store = local_store.storage

    store.savekey("first.last@example.com", [{"a": 1}], session_id="session-a")

    assert store.readkey("first.last@example.com", session_id="session-a") == [{"a": 1}]
    with pytest.raises(ValueError):
        store.readkey("first..last@example.com", session_id="session-a")


def test_resolve_contained_path_rejects_a_symlink_escape(local_store):
    """Containment is checked after symlink resolution, not just lexically."""

    storage_common = importlib.import_module("server.app.storage.common")
    root = local_store.root
    outside = local_store.tmp_path / "outside"
    outside.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError):
        storage_common.resolve_contained_path(str(root), "escape", "loot")


# --------------------------------------------------------------------------
# 2. GCS object-key containment
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", TRAVERSAL_NAMES)
def test_gcs_blob_helpers_reject_traversal_names(gcs_store, name):
    with pytest.raises(ValueError):
        gcs_store._credential_blob(name, "session-a")
    with pytest.raises(ValueError):
        gcs_store._legacy_credential_blob(name)


@pytest.mark.parametrize("session_id", TRAVERSAL_NAMES)
def test_gcs_blob_helpers_reject_traversal_sessions(gcs_store, session_id):
    with pytest.raises(ValueError):
        gcs_store._credential_blob("alice@example.com", session_id)


@pytest.mark.parametrize("name", LEGITIMATE_NAMES)
def test_gcs_object_keys_stay_under_the_configured_prefix(gcs_store, name):
    blob_name = gcs_store._credential_blob(name, "session-a")
    prefix = gcs_store._credential_prefix("session-a")

    assert blob_name.startswith(prefix.rstrip("/") + "/")
    assert ".." not in blob_name.split("/")
    assert blob_name.endswith(f"{name}_credential_data.json")


def test_assert_contained_blob_name_rejects_escapes():
    storage_common = importlib.import_module("server.app.storage.common")

    with pytest.raises(ValueError):
        storage_common.assert_contained_blob_name("user-data/../loot", prefix="user-data")
    with pytest.raises(ValueError):
        storage_common.assert_contained_blob_name("elsewhere/loot", prefix="user-data")
    with pytest.raises(ValueError):
        storage_common.assert_contained_blob_name("user-data//loot", prefix="user-data")

    assert (
        storage_common.assert_contained_blob_name("user-data/ok", prefix="user-data")
        == "user-data/ok"
    )


# --------------------------------------------------------------------------
# 3. The store lives outside the source tree
# --------------------------------------------------------------------------


def test_credential_root_is_not_inside_the_source_tree():
    config = importlib.import_module("server.app.config")
    package_dir = os.path.realpath(config.basepath)
    root = os.path.realpath(credentials._LOCAL_CREDENTIAL_BASE)

    assert not root.startswith(package_dir + os.sep)
    assert root != package_dir

    if not os.environ.get("FIDO_SERVER_CREDENTIAL_DIR"):
        assert root == os.path.realpath(
            os.path.join(config.app.instance_path, "session-credentials")
        )


def test_previous_source_tree_location_is_still_readable(local_store):
    """Relocating the store must not orphan an existing deployment's data."""

    store = local_store.storage
    session_dir = local_store.legacy_root / "session-a"
    session_dir.mkdir(parents=True)
    (session_dir / "alice@example.com_credential_data.pkl").write_bytes(
        pickle.dumps([{"where": "old-source-tree-location"}])
    )

    assert store.readkey("alice@example.com", session_id="session-a") == [
        {"where": "old-source-tree-location"}
    ]


# --------------------------------------------------------------------------
# 4. JSON encoding
# --------------------------------------------------------------------------


def test_json_round_trip_preserves_bytes_fields_exactly(local_store):
    store = local_store.storage
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

    store.savekey("alice@example.com", [record], session_id="session-a")
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
    store = local_store.storage
    raw = bytes([0xFB, 0xFF, 0x3E, 0x3F])  # encodes with - and _ in base64url

    store.savekey("alice@example.com", [{"blob": raw}], session_id="session-a")

    path = store._local_filename("alice@example.com", "session-a")
    envelope = json.loads(Path(path).read_text(encoding="utf-8"))

    assert envelope["version"] == 1
    assert envelope["encoding"] == "base64url"

    encoded = envelope["credentials"][0]["blob"]["__v"]
    assert encoded == base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    assert "+" not in encoded and "/" not in encoded and "=" not in encoded
    assert base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)) == raw


def test_savekey_never_writes_a_pickle_file(local_store):
    store = local_store.storage

    store.savekey("alice@example.com", [{"a": 1}], session_id="session-a")

    # Beside each credential file, the empty lock file its writers take.
    locks = [p for p in local_store.root.rglob("*.lock") if p.is_file()]
    assert [p.stat().st_size for p in locks] == [0]
    written = [str(p) for p in local_store.root.rglob("*") if p.is_file() and p not in locks]
    assert written, "expected the credential file to be written"
    assert not any(p.endswith(".pkl") for p in written)
    assert all(p.endswith(".json") for p in written)


def test_readkey_ignores_corrupt_json(local_store):
    store = local_store.storage
    path = store._local_filename("alice@example.com", "session-a", create=True)
    Path(path).write_bytes(b"{not json at all")

    assert store.readkey("alice@example.com", session_id="session-a") == []


# --------------------------------------------------------------------------
# 5. Legacy .pkl compatibility and migration
# --------------------------------------------------------------------------


def test_legacy_pickle_file_is_readable(local_store):
    store = local_store.storage
    credential_data = _build_attested_credential_data()
    legacy_records = [{"credential_data": credential_data, "user_info": {"name": "alice"}}]

    path = store._local_filename(
        "alice@example.com", "session-a", create=True, suffix="_credential_data.pkl"
    )
    Path(path).write_bytes(pickle.dumps(legacy_records))

    restored = store.readkey("alice@example.com", session_id="session-a")

    assert len(restored) == 1
    assert restored[0]["user_info"] == {"name": "alice"}
    assert bytes(restored[0]["credential_data"]) == bytes(credential_data)


def test_legacy_pickle_is_converted_to_json_on_the_next_write(local_store):
    store = local_store.storage
    pickle_path = Path(
        store._local_filename(
            "alice@example.com", "session-a", create=True, suffix="_credential_data.pkl"
        )
    )
    pickle_path.write_bytes(pickle.dumps([{"seq": 1}]))

    existing = store.readkey("alice@example.com", session_id="session-a")
    assert existing == [{"seq": 1}]

    existing.append({"seq": 2})
    store.savekey("alice@example.com", existing, session_id="session-a")

    json_path = Path(store._local_filename("alice@example.com", "session-a"))
    assert json_path.is_file()
    assert json.loads(json_path.read_text(encoding="utf-8"))["credentials"] == [
        {"seq": 1},
        {"seq": 2},
    ]
    # The superseded pickle is removed so it can never be read again.
    assert not pickle_path.exists()
    assert store.readkey("alice@example.com", session_id="session-a") == [
        {"seq": 1},
        {"seq": 2},
    ]


def test_iter_credentials_reads_both_json_and_legacy_pickle(local_store):
    store = local_store.storage
    session_dir = Path(store._local_directory("session-a", create=True))

    store.savekey("alice@example.com", [{"where": "json"}], session_id="session-a")
    (session_dir / "bob@example.com_credential_data.pkl").write_bytes(
        pickle.dumps([{"where": "pickle"}])
    )

    assert dict(store.iter_credentials(session_id="session-a")) == {
        "alice@example.com": [{"where": "json"}],
        "bob@example.com": [{"where": "pickle"}],
    }


def test_legacy_pickle_reads_can_be_switched_off(local_store, monkeypatch):
    store = local_store.storage
    path = store._local_filename(
        "alice@example.com", "session-a", create=True, suffix="_credential_data.pkl"
    )
    Path(path).write_bytes(pickle.dumps([{"seq": 1}]))

    assert store.readkey("alice@example.com", session_id="session-a") == [{"seq": 1}]

    monkeypatch.setenv("FIDO_SERVER_LEGACY_PICKLE_READS", "0")
    assert store.readkey("alice@example.com", session_id="session-a") == []


# --------------------------------------------------------------------------
# 6. A crafted pickle is never executed
# --------------------------------------------------------------------------


class _CraftedPickle:
    """Pickles to ``os.makedirs(<marker>)`` -- the classic RCE gadget shape."""

    def __init__(self, marker: str):
        self._marker = marker

    def __reduce__(self):
        return (os.makedirs, (self._marker,))


def test_crafted_pickle_payload_is_never_executed(local_store):
    """The proof that the deserialisation bug class is gone.

    The payload is first shown to be live -- plain ``pickle.loads`` runs it --
    and then fed to the store through a path that passes every containment
    check, which is the worst case: an attacker who planted a ``.pkl`` while
    the old code was still deployed. ``readkey`` must not run it.
    """

    store = local_store.storage
    control_marker = local_store.tmp_path / "control-executed"
    attack_marker = local_store.tmp_path / "pwned"

    # Control: the gadget really does execute under stock pickle, so a passing
    # test below means the payload was refused, not that it was inert.
    pickle.loads(pickle.dumps(_CraftedPickle(str(control_marker))))
    assert control_marker.is_dir()

    payload = pickle.dumps(_CraftedPickle(str(attack_marker)))
    path = store._local_filename(
        "alice@example.com", "session-a", create=True, suffix="_credential_data.pkl"
    )
    Path(path).write_bytes(payload)

    assert store.readkey("alice@example.com", session_id="session-a") == []
    assert not attack_marker.exists()

    assert list(store.iter_credentials(session_id="session-a")) == []
    assert not attack_marker.exists()


def test_crafted_pickle_payload_is_never_executed_from_gcs(monkeypatch, tmp_path):
    """Same guarantee for a downloaded object, which never touches the disk."""

    marker = tmp_path / "pwned-from-gcs"
    payload = pickle.dumps(_CraftedPickle(str(marker)))

    monkeypatch.setattr(credentials, "_using_gcs", lambda: True)
    monkeypatch.setattr(credentials, "download_bytes", lambda _blob: payload)

    assert credentials.readkey("alice@example.com", session_id="session-a") == []
    assert not marker.exists()


def test_restricted_unpickler_refuses_disallowed_modules():
    for module, name in (
        ("os", "system"),
        ("posix", "system"),
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("subprocess", "Popen"),
        ("shutil", "rmtree"),
    ):
        payload = pickle.dumps(_ReduceTo(module, name))
        with pytest.raises(pickle.UnpicklingError):
            record_format.restricted_pickle_loads(payload)


def test_restricted_unpickler_refuses_non_class_globals():
    """An allowlisted module still may not hand back a callable that is not a class."""

    payload = _global_pickle("fido2.webauthn", "struct")
    with pytest.raises(pickle.UnpicklingError):
        record_format.restricted_pickle_loads(payload)


def test_restricted_unpickler_still_loads_fido2_value_classes():
    credential_data = _build_attested_credential_data()
    payload = pickle.dumps([{"credential_data": credential_data}])

    restored = record_format.restricted_pickle_loads(payload)

    assert isinstance(restored[0]["credential_data"], AttestedCredentialData)
    assert bytes(restored[0]["credential_data"]) == bytes(credential_data)


def _global_pickle(module: str, name: str) -> bytes:
    """Build a pickle whose only opcode resolves ``module.name``."""

    return (
        b"\x80\x04"
        + b"c"
        + module.encode("ascii")
        + b"\n"
        + name.encode("ascii")
        + b"\n."
    )


class _ReduceTo:
    """Pickles to a call of ``module.name`` so ``find_class`` has to resolve it."""

    def __init__(self, module: str, name: str):
        self._module = module
        self._name = name

    def __reduce__(self):
        return (_resolve_for_pickle(self._module, self._name), ())


def _resolve_for_pickle(module: str, name: str):
    mod = importlib.import_module(module)
    return getattr(mod, name)


# --------------------------------------------------------------------------
# 7. End-to-end: a real registration survives the JSON format
# --------------------------------------------------------------------------


def test_real_registration_round_trips_through_the_json_store(monkeypatch, tmp_path, device_logs_module):
    """A genuinely-signed registration must persist and read back intact.

    The unit tests above pin the codec; this one proves the codec covers what
    the register flow actually stores -- ``AttestedCredentialData``,
    ``AuthenticatorData``, COSE maps keyed by integers and raw attestation
    bytes -- and that ``/api/credentials`` still renders the result.
    """

    pytest.importorskip("server.app.app")
    config_module = pytest.importorskip("server.app.config")
    ceremony = pytest.importorskip("tests.app.security.ceremony_helpers")

    root = tmp_path / "instance" / "session-credentials"
    root.mkdir(parents=True)
    monkeypatch.setattr(credentials, "_LOCAL_CREDENTIAL_BASE", str(root))
    monkeypatch.setattr(credentials, "_LEGACY_LOCAL_CREDENTIAL_BASE", str(tmp_path / "old"))
    monkeypatch.setattr(credentials, "basepath", str(tmp_path / "flat"))
    (tmp_path / "flat").mkdir()
    monkeypatch.setattr(credentials, "_using_gcs", lambda: False)
    monkeypatch.setattr(device_logs_module, "record_registration_event", lambda _event: None)

    # Any value the encoder cannot represent is logged; the flow must not need it.
    warnings: list[str] = []
    monkeypatch.setattr(
        credentials.logger,
        "warning",
        lambda msg, *args, **kwargs: warnings.append(str(msg) % args if args else str(msg)),
    )

    client = config_module.app.test_client()
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

    written = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix != ".lock")
    assert len(written) == 1
    assert written[0].name == "alice@example.com_credential_data.json"
    envelope = json.loads(written[0].read_text(encoding="utf-8"))
    assert envelope["version"] == 1 and envelope["encoding"] == "base64url"

    assert not any("unsupported type" in message for message in warnings), warnings

    # The route reads it back through the same session cookie the client holds.
    listed = client.get("/api/credentials")
    assert listed.status_code == 200
    records = listed.get_json()["credentials"]
    assert len(records) == 1
    rendered = records[0]
    assert rendered["email"] == "alice@example.com"
    assert rendered["publicKeyAlgorithm"] == -7
    assert base64.b64decode(rendered["credentialId"]) == authenticator.credential_id
